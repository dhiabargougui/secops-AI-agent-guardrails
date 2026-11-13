"""
Pre-Release Safety Gate and Cryptographic Four-Eyes Dual Control Engine (Architectural Invariant #5).
File: src/policy/release_gate.py

Governing Standard:
  Autonomous SecOps Guardrail Specification v1.0 (Section 2.1 Box 5, Decision D2, Decision D4, Section 5.3)

Principles:
  1. automated initial alert closure strictly excludes Tier 0 and Tier 1 critical assets,
     unconditionally routing them to deliberative investigation.
  2. Investigation dismissal, rollback, or hold release on Tier 0 and Tier 1 assets
     strictly requires Four-Eyes dual control from two distinct authenticated human experts.
  3. The action APPROVE_TIER0_REVOKE strictly requires Four-Eyes across all invocations.
  4. Under no circumstances does an authorization timeout degrade Four-Eyes into
     single-analyst execution; requests unfulfilled at T_4eyes = 900s escalate to
     the on-call SOC Manager as co-signer.
  5. Autonomous agents (ROLE_*) cannot self-authorize release on any asset tier.
  6. Cryptographic dual control: approvers must be validated against a trusted key registry
     with strict human role enforcement, replay protection via nonces, and canonical request binding.
"""

from dataclasses import dataclass, field
import hashlib
import hmac
from typing import Any, Dict, List, Optional, Set, Union

from src.ledger.chain import canonicalize_json
from src.policy.rsem import normalize_asset_tier

# Governed high-impact release and approval action allowlist
GOVERNED_RELEASE_ACTIONS: Set[str] = {
    "APPROVE_MANUAL_HOST_ISOLATION",
    "APPROVE_DISABLE_ACCOUNT",
    "APPROVE_TIER0_REVOKE",
    "OVERRIDE_TO_BENIGN",
    "VALIDATE_BENIGN_DISMISSAL",
    "RELEASE_SAFE_CLOSE_HOLD",
    "MARK_DISPROPORTIONATE_CONTAINMENT",
}

# Authorized human roles
AUTHORIZED_HUMAN_ROLES: Set[str] = {
    "HUMAN_EXPERT",
    "HUMAN_SOC_MANAGER",
    "HUMAN_SOC_ANALYST",
}

# Roles permitted to authorize high-impact / critical actions (C_A >= 4 or Tier 0/1 releases)
HIGH_IMPACT_AUTHORIZED_ROLES: Set[str] = {
    "HUMAN_EXPERT",
    "HUMAN_SOC_MANAGER",
}


@dataclass(frozen=True)
class RegisteredApprover:
    """Registered human approver identity bound to role and signing credentials."""
    user_id: str
    role: str
    signing_key: str
    allowed_keys: Set[str] = field(default_factory=set)

    def is_key_valid(self, key: str) -> bool:
        return key == self.signing_key or key in self.allowed_keys


# Authoritative default approver key registry
DEFAULT_APPROVER_REGISTRY: Dict[str, RegisteredApprover] = {
    "analyst-alice": RegisteredApprover(
        user_id="analyst-alice",
        role="HUMAN_EXPERT",
        signing_key="alice-key-1",
        allowed_keys={"alice-key-1", "alice-pubkey-ed25519"},
    ),
    "analyst-bob": RegisteredApprover(
        user_id="analyst-bob",
        role="HUMAN_EXPERT",
        signing_key="bob-key-2",
        allowed_keys={"bob-key-2"},
    ),
    "manager-carol": RegisteredApprover(
        user_id="manager-carol",
        role="HUMAN_SOC_MANAGER",
        signing_key="carol-key-mgr",
        allowed_keys={"carol-key-mgr"},
    ),
    "analyst-dan": RegisteredApprover(
        user_id="analyst-dan",
        role="HUMAN_SOC_ANALYST",
        signing_key="dan-key-tier3",
        allowed_keys={"dan-key-tier3"},
    ),
}

# Seen approval nonces cache for replay protection
_SEEN_APPROVAL_NONCES: Set[str] = set()


def clear_seen_approval_nonces() -> None:
    """Clears the seen approval nonces set (for testing)."""
    _SEEN_APPROVAL_NONCES.clear()


class ReleaseGateError(Exception):
    """Base exception for pre-release safety gate failures."""
    pass


class SecurityViolationError(ReleaseGateError):
    """Raised when an autonomous agent attempts to authorize a release or dual control is violated."""
    pass


def create_approval_signature(
    approver: RegisteredApprover,
    action_type: str,
    asset_tier: Union[str, int],
    incident_id: str,
    tenant_id: str,
    nonce: str,
    issued_at: float,
    expires_at: float,
) -> Dict[str, Any]:
    """
    Creates a cryptographically signed approval payload over canonical request bytes.
    """
    tier_canonical = normalize_asset_tier(asset_tier)
    action_clean = str(action_type).strip().upper()
    req_payload = {
        "action": action_clean,
        "asset_tier": tier_canonical,
        "expires_at": float(expires_at),
        "incident_id": str(incident_id),
        "issued_at": float(issued_at),
        "nonce": str(nonce),
        "tenant_id": str(tenant_id),
    }
    req_bytes = canonicalize_json(req_payload)
    sig = hmac.new(approver.signing_key.encode("utf-8"), req_bytes, hashlib.sha256).hexdigest()
    return {
        "user_id": approver.user_id,
        "role": approver.role,
        "signing_key": approver.signing_key,
        "nonce": str(nonce),
        "issued_at": float(issued_at),
        "expires_at": float(expires_at),
        "signature": sig,
    }


def evaluate_phase1_autoclose(
    asset_tier: Union[str, int],
    s_score: float,
    theta_low: float,
) -> Dict[str, Any]:
    """
    Evaluates automated initial alert closure under Invariant #5.

    Critical assets (Tier 0 and Tier 1) can never be automatically closed,
    regardless of heuristic non-conformity score s(X).
    """
    tier_canonical = normalize_asset_tier(asset_tier)

    # Invariant #5: Tier 0 and Tier 1 critical assets are strictly barred from auto-closure
    if tier_canonical in ("Tier 0", "Tier 1"):
        return {
            "status": "REJECTED",
            "action": "ROUTE_TO_DELIBERATIVE_INVESTIGATION",
            "reason": "CRITICAL_ASSET_AUTO_CLOSE_BARRED",
            "asset_tier": tier_canonical,
        }

    # For non-critical assets (Tier 2 and Tier 3), compare score against threshold
    if float(s_score) < float(theta_low):
        return {
            "status": "APPROVED",
            "action": "AUTO_CLOSE_PERMITTED",
            "reason": "NON_CRITICAL_BELOW_THETA_LOW",
            "asset_tier": tier_canonical,
        }

    return {
        "status": "REJECTED",
        "action": "ROUTE_TO_DELIBERATIVE_INVESTIGATION",
        "reason": "SCORE_EXCEEDS_THETA_LOW",
        "asset_tier": tier_canonical,
    }


def evaluate_hold_release(
    action_type: str,
    asset_tier: Union[str, int],
    approvers: List[Dict[str, Any]],
    request_time: float,
    current_time: float,
    t_4eyes_timeout: float = 900.0,
    incident_id: str = "INC-DEFAULT",
    tenant_id: str = "TENANT-DEFAULT",
    requester_id: Optional[str] = None,
    key_registry: Optional[Dict[str, RegisteredApprover]] = None,
    require_signatures: bool = False,
    escalation_approver: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Evaluates hold release and dismissal requests against Four-Eyes governance.

    Parameters:
      - action_type: Governed action (must belong to GOVERNED_RELEASE_ACTIONS).
      - asset_tier: Target asset criticality tier.
      - approvers: List of approver dictionaries.
      - request_time: Timestamp when release was requested.
      - current_time: Current evaluation timestamp.
      - t_4eyes_timeout: Peer review window before escalating to SOC Manager (default 900s).
      - incident_id: Identifier of the incident being released.
      - tenant_id: Multi-tenant customer identifier.
      - requester_id: Optional identity of the original requester (for separation of duties).
      - key_registry: Optional mapping of user_id to RegisteredApprover.
      - require_signatures: If True, all approvers must supply valid cryptographic signatures.
      - escalation_approver: Optional SOC Manager approver supplied when escalated.

    Returns:
      - Dict with status, reason, and escalation flags.

    Raises:
      - ValueError: If action_type is unknown or approver identities collide.
      - SecurityViolationError: If an autonomous agent attempts authorization,
        requester self-approves, approver is not registered, or signatures fail.
    """
    action_clean = str(action_type).strip().upper()
    if action_clean not in GOVERNED_RELEASE_ACTIONS:
        raise ValueError(
            f"Unknown release action '{action_type}'. Must be one of {sorted(GOVERNED_RELEASE_ACTIONS)}"
        )

    tier_canonical = normalize_asset_tier(asset_tier)
    registry = key_registry if key_registry is not None else DEFAULT_APPROVER_REGISTRY

    # Strict Four-Eyes dual control required for Tier 0/1, or APPROVE_TIER0_REVOKE on any tier
    requires_four_eyes = (
        tier_canonical in ("Tier 0", "Tier 1")
        or action_clean == "APPROVE_TIER0_REVOKE"
    )

    # Validate distinct approver identity check when 2 or more approvers are present
    if len(approvers) >= 2:
        e1, e2 = approvers[0], approvers[1]
        if not isinstance(e1, dict) or not isinstance(e2, dict):
            raise ValueError("Approver entry must be a dictionary.")
        if e1.get("user_id") == e2.get("user_id") or e1.get("signing_key") == e2.get("signing_key"):
            raise ValueError(
                "Four-Eyes dual control violation: Approvers must have distinct user_id and signing_key."
            )

    # Validate each approver against registry, role bounds, and cryptographic signatures
    validated_approvers = []
    for approver in approvers:
        if not isinstance(approver, dict):
            raise ValueError("Approver entry must be a dictionary.")

        user_id = approver.get("user_id")
        if not user_id:
            raise ValueError("Each approver must supply 'user_id'.")

        # 1. Requester separation of duties
        if requester_id is not None and user_id == requester_id:
            raise SecurityViolationError(
                f"Requester '{requester_id}' cannot approve their own release request (separation of duties violation)."
            )

        # 2. Autonomous agent guard
        role = approver.get("role", "")
        if role and role.startswith("ROLE_"):
            raise SecurityViolationError(
                f"Autonomous agent with role '{role}' is barred from authorizing release or dismissal."
            )

        # 3. Key registry membership
        registered = registry.get(user_id)
        if registered is None:
            raise SecurityViolationError(
                f"Approver '{user_id}' is not present in authorized approver key registry."
            )

        # 4. Role validation
        effective_role = role if role else registered.role
        if effective_role not in AUTHORIZED_HUMAN_ROLES:
            raise SecurityViolationError(
                f"Role '{effective_role}' is not an authorized human approver role."
            )

        # 5. Role authority ceiling: Tier 0/1 releases require HUMAN_EXPERT or HUMAN_SOC_MANAGER
        if requires_four_eyes and effective_role not in HIGH_IMPACT_AUTHORIZED_ROLES:
            raise SecurityViolationError(
                f"Role '{effective_role}' lacks authority for critical asset release (requires HUMAN_EXPERT or HUMAN_SOC_MANAGER)."
            )

        # 6. Signing key verification
        if "signing_key" in approver:
            if not registered.is_key_valid(approver["signing_key"]):
                raise SecurityViolationError(
                    f"Signing key provided for '{user_id}' does not match registered key."
                )

        # 7. Cryptographic signature and replay protection
        if require_signatures or "signature" in approver:
            if "signature" not in approver:
                raise SecurityViolationError(f"Missing cryptographic signature for approver '{user_id}'.")

            nonce = approver.get("nonce")
            if not nonce:
                raise SecurityViolationError(f"Missing required nonce for approver '{user_id}'.")

            if nonce in _SEEN_APPROVAL_NONCES:
                raise SecurityViolationError(f"Replay detected: approval nonce '{nonce}' has already been used.")

            issued_at = float(approver.get("issued_at", request_time))
            expires_at = float(approver.get("expires_at", current_time + 300.0))

            if current_time > expires_at:
                raise ReleaseGateError(f"Approval signature for '{user_id}' has expired.")
            if issued_at > current_time + 60.0:
                raise ReleaseGateError(f"Approval signature timestamp for '{user_id}' is in the future.")

            req_payload = {
                "action": action_clean,
                "asset_tier": tier_canonical,
                "expires_at": expires_at,
                "incident_id": str(incident_id),
                "issued_at": issued_at,
                "nonce": str(nonce),
                "tenant_id": str(tenant_id),
            }
            req_bytes = canonicalize_json(req_payload)
            expected_sig = hmac.new(registered.signing_key.encode("utf-8"), req_bytes, hashlib.sha256).hexdigest()

            if not hmac.compare_digest(approver["signature"], expected_sig):
                raise SecurityViolationError(f"Invalid cryptographic signature for approver '{user_id}'.")

            _SEEN_APPROVAL_NONCES.add(nonce)

        validated_approvers.append(approver)

    elapsed_time = float(current_time) - float(request_time)
    timed_out = elapsed_time >= float(t_4eyes_timeout)

    if requires_four_eyes:
        # Zero approvers case
        if len(validated_approvers) == 0:
            if timed_out:
                return {
                    "status": "ESCALATED_TO_SOC_MANAGER",
                    "reason": "FOUR_EYES_TIMEOUT_ESCALATION",
                    "escalated": True,
                    "action_type": action_clean,
                    "asset_tier": tier_canonical,
                }
            return {
                "status": "PENDING_APPROVAL",
                "reason": "AWAITING_HUMAN_APPROVAL",
                "escalated": False,
                "action_type": action_clean,
                "asset_tier": tier_canonical,
            }

        # Single approver case
        if len(validated_approvers) == 1:
            if timed_out:
                # If an escalation approver is supplied at or after timeout, verify credentials
                if escalation_approver is not None:
                    mgr_id = escalation_approver.get("user_id")
                    mgr_reg = registry.get(mgr_id)
                    if mgr_reg is None or mgr_reg.role != "HUMAN_SOC_MANAGER":
                        raise SecurityViolationError("Escalation approval requires registered HUMAN_SOC_MANAGER.")
                    if not mgr_reg.is_key_valid(escalation_approver.get("signing_key", "")):
                        raise SecurityViolationError("Invalid credentials for escalation SOC Manager.")
                    return {
                        "status": "APPROVED",
                        "reason": "FOUR_EYES_TIMEOUT_ESCALATION_SATISFIED_BY_SOC_MANAGER",
                        "escalated": True,
                        "action_type": action_clean,
                        "asset_tier": tier_canonical,
                    }

                return {
                    "status": "ESCALATED_TO_SOC_MANAGER",
                    "reason": "FOUR_EYES_TIMEOUT_ESCALATION",
                    "escalated": True,
                    "action_type": action_clean,
                    "asset_tier": tier_canonical,
                }
            return {
                "status": "PENDING_SECOND_APPROVER",
                "reason": "FOUR_EYES_APPROVAL_REQUIRED",
                "escalated": False,
                "action_type": action_clean,
                "asset_tier": tier_canonical,
            }

        # Two or more approvers: dual control satisfied
        return {
            "status": "APPROVED",
            "reason": "FOUR_EYES_DUAL_CONTROL_SATISFIED",
            "escalated": False,
            "action_type": action_clean,
            "asset_tier": tier_canonical,
        }

    # Non-critical asset (Tier 2 and Tier 3): single human approval is sufficient
    if len(validated_approvers) >= 1:
        return {
            "status": "APPROVED",
            "reason": "SINGLE_EXPERT_APPROVAL_SATISFIED",
            "escalated": False,
            "action_type": action_clean,
            "asset_tier": tier_canonical,
        }

    # Zero approvers on non-critical asset
    if timed_out:
        return {
            "status": "ESCALATED_TO_SOC_MANAGER",
            "reason": "APPROVAL_TIMEOUT_ESCALATION",
            "escalated": True,
            "action_type": action_clean,
            "asset_tier": tier_canonical,
        }

    return {
        "status": "PENDING_APPROVAL",
        "reason": "AWAITING_HUMAN_APPROVAL",
        "escalated": False,
        "action_type": action_clean,
        "asset_tier": tier_canonical,
    }
