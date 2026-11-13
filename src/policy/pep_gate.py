# Autonomous AI SOC Platform — Policy Enforcement Point (PEP) Gateway
# Autonomous SecOps Guardrail Specification v1.0 — Section 5.3 & Section 5.3.5
# src/policy/pep_gate.py
#
# Authoritative gateway executing compiled Open Policy Agent (OPA) Rego policies
# to govern autonomous containment directives.
# Implements fail-closed policy enforcement, untrusted parameter derivation,
# out-of-band attestation state normalization, and differential execution parity.

import json
import math
import os
import shutil
import subprocess
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Union

from src.policy.rsem import OOBStatus, normalize_asset_tier


# Canonical identity containment actions (Specification Section 4.3 Table 21)
IDENTITY_ACTIONS = frozenset({
    "REVOKE_ACTIVE_SESSIONS",
    "ENFORCE_STEP_UP_AUTH",
    "DISABLE_ACCOUNT",
})

# Path references
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_POLICY_FILE = REPO_ROOT / "policies" / "soc_containment.rego"


def find_opa_binary(override_path: Optional[Union[str, Path]] = None) -> Optional[Path]:
    """Resolves the location of the Open Policy Agent (OPA) executable.
    
    Checks in order:
    1. Explicit override path passed by caller (fails closed if path does not exist)
    2. Platform-specific repo-local binary: tools/opa.exe (Windows) or tools/opa (POSIX)
    3. System PATH via shutil.which('opa')
    """
    if override_path is not None:
        p = Path(override_path).resolve()
        if p.exists() and p.is_file():
            return p
        return None

    if os.name == "nt":
        win_path = REPO_ROOT / "tools" / "opa.exe"
        if win_path.exists() and win_path.is_file():
            return win_path
    else:
        posix_path = REPO_ROOT / "tools" / "opa"
        if posix_path.exists() and posix_path.is_file():
            return posix_path

    which_opa = shutil.which("opa")
    if which_opa:
        return Path(which_opa).resolve()

    return None


def evaluate(
    action_type: str,
    asset_tier: Union[str, int],
    rsem: float,
    oob_status: Union[OOBStatus, str] = OOBStatus.PENDING,
    oob_denied: Optional[bool] = None,
    opa_path: Optional[Union[str, Path]] = None,
    policy_path: Optional[Union[str, Path]] = None,
    timeout_seconds: float = 5.0,
) -> Dict[str, Any]:
    """Evaluates an automated containment directive against compiled OPA Rego policy.
    
    Implements a strict fail-closed control plane:
    - If OPA is missing, crashes, times out, or returns invalid JSON, unconditionally
      escalates to human Expert with GATEWAY_FAIL_CLOSED_ERROR.
    - Resolves identity classification and disruption cost internally; callers
      cannot pass or override cost_of_action or is_identity_action.
    - Normalizes legacy oob_denied into 3-state OOBStatus, raising ValueError
      on conflicting inputs.
    - Rejects raw bool oob_status inputs (TypeError) and out-of-range RSEM (ValueError).
    - Targets only the production policy file (soc_containment.rego) to avoid test overhead.
    
    Parameters
    ----------
    action_type : str
        Containment action name (e.g. 'ISOLATE_HOST', 'REVOKE_ACTIVE_SESSIONS').
    asset_tier : Union[str, int]
        Criticality tier of target asset (0, 1, 2, 3 or 'Tier 0'..'Tier 3').
    rsem : float
        Risk-Sensitive Execution Metric score in range [0.0, 100.0].
    oob_status : Union[OOBStatus, str], default=OOBStatus.PENDING
        3-state out-of-band attestation status: PENDING, DENIED_BY_USER,
        or CONFIRMED_LEGITIMATE.
    oob_denied : Optional[bool], default=None
        Legacy boolean flag for backward compatibility. Normalized to OOBStatus.
        Raises ValueError if conflicting with explicit oob_status.
    opa_path : Optional[Union[str, Path]], default=None
        Optional path to OPA binary.
    policy_path : Optional[Union[str, Path]], default=None
        Optional path to soc_containment.rego. Defaults to policies/soc_containment.rego.
    timeout_seconds : float, default=5.0
        Maximum execution time before failing closed.
        
    Returns
    -------
    Dict[str, Any]
        Dictionary with 'decision' ('ALLOW', 'OOB_REQUIRED', 'ESCALATE', 'STAND_DOWN')
        and 'reason' (e.g. 'HARD_AUTONOMY_CEILING_EXCEEDED', 'ZONE1_AUTONOMOUS_ALLOW').
    """
    # -------------------------------------------------------------------------
    # 1. Defensive Type & Value Validations (Fail Fast before spawning OPA)
    # -------------------------------------------------------------------------
    
    # Action type validation
    if not isinstance(action_type, str) or not action_type.strip():
        raise ValueError("action_type must be a non-empty string")
    clean_action = action_type.strip().upper()

    # RSEM type and bound validation (Refinement 3)
    if isinstance(rsem, bool):
        raise TypeError(f"rsem cannot be a boolean ({rsem})")
    if not isinstance(rsem, (int, float)) or not math.isfinite(rsem):
        raise ValueError(f"rsem must be a finite numeric value, got {rsem!r}")
    if rsem < 0.0 or rsem > 100.0:
        raise ValueError(f"rsem must be in range [0.0, 100.0], got {rsem}")
    clean_rsem = float(rsem)

    # OOB status type validation: Reject raw bool (Refinement 3)
    if isinstance(oob_status, bool):
        raise TypeError(
            f"oob_status cannot be a raw boolean ({oob_status}); use OOBStatus enum"
        )

    # Legacy oob_denied normalization & conflict prevention (Refinement 2)
    resolved_oob: OOBStatus
    if isinstance(oob_status, OOBStatus):
        resolved_oob = oob_status
    elif isinstance(oob_status, str):
        try:
            resolved_oob = OOBStatus(oob_status.strip().upper())
        except ValueError:
            raise ValueError(
                f"Invalid oob_status string: {oob_status!r}. "
                f"Valid values: {[e.value for e in OOBStatus]}"
            )
    else:
        raise TypeError(f"oob_status must be OOBStatus or str, got {type(oob_status).__name__}")

    if oob_denied is not None:
        if not isinstance(oob_denied, bool):
            raise TypeError(f"oob_denied must be a boolean or None, got {type(oob_denied).__name__}")
        if oob_denied is True:
            if resolved_oob not in (OOBStatus.PENDING, OOBStatus.DENIED_BY_USER):
                raise ValueError(
                    f"Conflicting OOB states: oob_status={resolved_oob.value} "
                    f"conflicts with legacy oob_denied=True"
                )
            resolved_oob = OOBStatus.DENIED_BY_USER
        else:  # oob_denied is False
            if resolved_oob == OOBStatus.DENIED_BY_USER:
                raise ValueError(
                    "Conflicting OOB states: oob_status=DENIED_BY_USER "
                    "conflicts with legacy oob_denied=False"
                )

    # Asset tier normalization
    clean_tier: int
    try:
        norm_str = normalize_asset_tier(asset_tier)
        clean_tier = int(norm_str.replace("Tier ", ""))
    except ValueError:
        # If unparseable tier format, map to -1 so OPA defaults cost_of_action to 10
        # and triggers HARD_AUTONOMY_CEILING_EXCEEDED -> ESCALATE (fail closed).
        clean_tier = -1

    # -------------------------------------------------------------------------
    # 2. Locate OPA Binary and Policy File (Refinement 4)
    # -------------------------------------------------------------------------
    resolved_opa = find_opa_binary(opa_path)
    if resolved_opa is None:
        return {
            "decision": "ESCALATE",
            "reason": "GATEWAY_FAIL_CLOSED_ERROR",
            "error": "Open Policy Agent binary (opa.exe) could not be located"
        }

    target_policy = (
        Path(policy_path).resolve()
        if policy_path is not None
        else DEFAULT_POLICY_FILE
    )
    if not target_policy.exists() or not target_policy.is_file():
        return {
            "decision": "ESCALATE",
            "reason": "GATEWAY_FAIL_CLOSED_ERROR",
            "error": f"Policy file not found at {target_policy}"
        }

    # -------------------------------------------------------------------------
    # 3. Construct Input Payload (Untrusted inputs sanitized; no cost_of_action)
    # -------------------------------------------------------------------------
    # Note: OPA's --stdin-input treats the incoming JSON document directly as
    # the 'input' document, so fields are placed at root level.
    input_payload = {
        "action_type": clean_action,
        "asset_tier": clean_tier,
        "rsem": clean_rsem,
        "oob_status": resolved_oob.value,
    }

    # -------------------------------------------------------------------------
    # 4. Invoke OPA Subprocess (Strict Fail-Closed Wrapper)
    # -------------------------------------------------------------------------
    try:
        cmd = [
            str(resolved_opa),
            "eval",
            "--stdin-input",
            "-f",
            "json",
            "-d",
            str(target_policy),
            "data.soc.containment.result",
        ]
        
        proc = subprocess.run(
            cmd,
            input=json.dumps(input_payload),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )

        if proc.returncode != 0:
            return {
                "decision": "ESCALATE",
                "reason": "GATEWAY_FAIL_CLOSED_ERROR",
                "error": f"OPA process exited with code {proc.returncode}: {proc.stderr.strip()}"
            }

        parsed = json.loads(proc.stdout)
        results = parsed.get("result", [])
        if not results:
            return {
                "decision": "ESCALATE",
                "reason": "NO_MATCHING_RULE"
            }

        expressions = results[0].get("expressions", [])
        if not expressions:
            return {
                "decision": "ESCALATE",
                "reason": "NO_MATCHING_RULE"
            }

        decision_obj = expressions[0].get("value")
        if not isinstance(decision_obj, dict):
            return {
                "decision": "ESCALATE",
                "reason": "GATEWAY_FAIL_CLOSED_ERROR",
                "error": f"Malformed OPA expression value: {decision_obj!r}"
            }

        return decision_obj

    except subprocess.TimeoutExpired:
        return {
            "decision": "ESCALATE",
            "reason": "GATEWAY_FAIL_CLOSED_ERROR",
            "error": f"OPA evaluation timed out after {timeout_seconds}s"
        }
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        return {
            "decision": "ESCALATE",
            "reason": "GATEWAY_FAIL_CLOSED_ERROR",
            "error": f"Gateway execution exception: {exc}"
        }
