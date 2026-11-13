"""
================================================================================
RISK-SENSITIVE EXECUTION METRIC (RSEM) & SEVERITY GOVERNANCE ENGINE
File: src/policy/rsem.py
================================================================================
Architectural Invariants & Mechanisms:
  - Invariant #4: Hard Autonomy Ceiling (Actions with C_A >= 4 are unconditionally
    barred from autonomous actuation across all RSEM and risk levels).
  - Policy Mechanism: Raise-Only Severity Governance (Incident severity C_I can
    never be silently downgraded by agents, and any raise requires explicit citation
    to a hash-verified forensic finding block).

Governing Specification:
  - Autonomous SecOps Guardrail Specification v1.0, Section 4.3 (Equations 15–21, Tables 12, 13, 21)
  - docs/DESIGN_DECISIONS.md

Purpose:
  In the containment policy layer, containment decisions balance the expected
  damage of an unchecked attack against the operational disruption of isolating
  systems. This module provides the mathematical formulas and lookup tables
  governing containment action thresholds, confidence minimums, and severity.
================================================================================
"""

from enum import Enum
import json
import re
from typing import Any, Dict, List, Optional, Tuple, Union


# ==============================================================================
# ENUMERATIONS & PATTERNS
# ==============================================================================

class OOBStatus(str, Enum):
    """
    Three-state representation of Out-of-Band (OOB) step-up verification.
    Inherits from str and Enum for seamless JSON serialization into OPA policies.
    """
    PENDING = "PENDING"
    DENIED_BY_USER = "DENIED_BY_USER"
    CONFIRMED_LEGITIMATE = "CONFIRMED_LEGITIMATE"


# Grounded citation format: must be 'LEDGER_' followed by 3 or more digits
CITATION_PATTERN: re.Pattern = re.compile(r"^LEDGER_(\d{3,})$")


# ==============================================================================
# CANONICAL REFERENCE TABLES (Autonomous SecOps Guardrail Specification v1.0)
# ==============================================================================

# Table 12: Company-Owned Baseline Incident Severity Table (C_{I,base})
# Mapped across 9 Attack Families and 4 Asset Tiers:
#   - Tier 3: Workstation / Client endpoint
#   - Tier 2: Internal application / Dev server
#   - Tier 1: Production database / Core service
#   - Tier 0: Identity provider / Domain Controller / Crown Jewel
TABLE_12_SEVERITY_BASELINES: Dict[str, Dict[str, int]] = {
    "Phishing & Email Threats": {
        "Tier 3": 5,
        "Tier 2": 7,
        "Tier 1": 9,
        "Tier 0": 10,
    },
    "Lateral Movement": {
        "Tier 3": 6,
        "Tier 2": 7,
        "Tier 1": 9,
        "Tier 0": 10,
    },
    "Compromised Accounts": {
        "Tier 3": 4,
        "Tier 2": 6,
        "Tier 1": 8,
        "Tier 0": 10,
    },
    "Malware & Suspicious Exec": {
        "Tier 3": 5,
        "Tier 2": 7,
        "Tier 1": 9,
        "Tier 0": 10,
    },
    "Command & Control": {
        "Tier 3": 6,
        "Tier 2": 7,
        "Tier 1": 9,
        "Tier 0": 10,
    },
    "Cloud Misuse": {
        "Tier 3": 5,
        "Tier 2": 7,
        "Tier 1": 8,
        "Tier 0": 10,
    },
    "Data Exfiltration": {
        "Tier 3": 6,
        "Tier 2": 8,
        "Tier 1": 9,
        "Tier 0": 10,
    },
    "Ransomware & Destruction": {
        "Tier 3": 8,
        "Tier 2": 9,
        "Tier 1": 10,
        "Tier 0": 10,
    },
    "Insider Threat": {
        "Tier 3": 4,
        "Tier 2": 6,
        "Tier 1": 8,
        "Tier 0": 10,
    },
}

# Table 13: Deterministic Finding-Class Severity Lookup Table (C_I(finding_class))
# Signed strictly by ROLE_INV_EXECUTOR upon confirming forensic criteria.
TABLE_13_FINDING_CLASS_SEVERITY: Dict[str, int] = {
    # LSASS memory handle, NTDS.dit extraction, SAM hive export
    "FND_CRED_DUMP": 9,
    # Post-click OAuth consent, Golden SAML, forged Kerberos ticket
    "FND_TOKEN_MINT": 8,
    # Remote service creation, PsExec invocation, WMI process creation
    "FND_LATERAL_MOVE": 8,
    # Shadow copy deletion (VSS), backup termination, mass rename
    "FND_RANSOM_PREP": 10,
    # Beaconing to confirmed threat infrastructure, Cobalt Strike profile
    "FND_C2_ESTABLISHED": 7,
    # Root CA installation, EDR driver unload, event log clearing
    "FND_DEFENSE_EVASION": 8,
}

# Table 21: Baseline Cost-of-Action Catalog by Asset Tier (C_A)
# Quantifies operational disruption when executing remediation directive d against asset a.
# Directives marked with C_A >= 4 are barred from autonomous actuation by Invariant #4.
TABLE_21_CA_CATALOG: Dict[str, Dict[str, int]] = {
    "ISOLATE_HOST": {
        "Tier 3": 2,
        "Tier 2": 5,   # C_A >= 4: Barred from autonomous actuation
        "Tier 1": 9,   # C_A >= 4: Barred from autonomous actuation
        "Tier 0": 10,  # C_A >= 4: Barred from autonomous actuation
    },
    "REVOKE_ACTIVE_SESSIONS": {
        "Tier 3": 1,
        "Tier 2": 2,
        "Tier 1": 3,
        "Tier 0": 5,   # C_A >= 4: Barred from autonomous actuation
    },
    "ENFORCE_STEP_UP_AUTH": {
        "Tier 3": 1,
        "Tier 2": 1,
        "Tier 1": 2,
        "Tier 0": 2,
    },
    "BLOCK_IOC": {
        "Tier 3": 1,
        "Tier 2": 1,
        "Tier 1": 2,
        "Tier 0": 3,
    },
    "PURGE_MESSAGE": {
        "Tier 3": 1,
        "Tier 2": 1,
        "Tier 1": 1,
        "Tier 0": 2,
    },
    "DISABLE_ACCOUNT": {
        "Tier 3": 3,
        "Tier 2": 4,   # C_A >= 4: Barred from autonomous actuation
        "Tier 1": 6,   # C_A >= 4: Barred from autonomous actuation
        "Tier 0": 9,   # C_A >= 4: Barred from autonomous actuation
    },
}

# Identity-oriented directives subject to Out-of-Band verification in Zone 2
IDENTITY_DIRECTIVES: set[str] = {
    "REVOKE_ACTIVE_SESSIONS",
    "ENFORCE_STEP_UP_AUTH",
    "DISABLE_ACCOUNT",
}

# Hard Autonomy Ceiling threshold (Invariant #4)
AUTONOMY_CEILING_THRESHOLD: int = 4

# Autonomous Actuation RSEM threshold (Autonomous SecOps Guardrail Specification v1.0, Eq. 18 / Table 22)
AUTONOMOUS_ACTUATION_THRESHOLD: float = 75.0

# Precautionary Hold lower bound (Autonomous SecOps Guardrail Specification v1.0, Table 22)
PRECAUTIONARY_HOLD_MIN_THRESHOLD: float = 50.0


# ==============================================================================
# NORMALIZATION HELPERS
# ==============================================================================

def normalize_asset_tier(tier: Union[str, int]) -> str:
    """
    Normalizes asset tier representations to canonical 'Tier X' string format.
    Accepts: 0, 1, 2, 3, '0', '1', '2', '3', 'Tier 0'..'Tier 3', 'Crown Jewel', 'workstation'.
    Rejects: booleans (True/False), floats (1.0), multi-digit strings ('Tier 10', 'host-20').
    """
    if isinstance(tier, bool):
        raise ValueError(f"Invalid boolean asset tier: {tier}. Must be 0, 1, 2, or 3.")

    if isinstance(tier, float):
        raise ValueError(f"Invalid float asset tier: {tier}. Must be 0, 1, 2, or 3.")

    if isinstance(tier, int):
        if tier in (0, 1, 2, 3):
            return f"Tier {tier}"
        raise ValueError(f"Invalid integer asset tier: {tier}. Must be 0, 1, 2, or 3.")

    t_str = str(tier).strip()
    if t_str in ("Tier 0", "Tier 1", "Tier 2", "Tier 3"):
        return t_str
    if t_str in ("0", "1", "2", "3"):
        return f"Tier {t_str}"

    lower_tier = t_str.lower().replace("-", " ").replace("_", " ").strip()
    if lower_tier in ("tier 0", "crown jewel", "tier0"):
        return "Tier 0"
    if lower_tier in ("tier 1", "production", "prod", "tier1"):
        return "Tier 1"
    if lower_tier in ("tier 2", "internal", "dev", "tier2"):
        return "Tier 2"
    if lower_tier in ("tier 3", "workstation", "client", "tier3"):
        return "Tier 3"

    raise ValueError(f"Unrecognized asset tier: '{tier}'. Expected Tier 0, 1, 2, or 3.")


def normalize_attack_family(family: str) -> str:
    """
    Normalizes attack family string to Table 12 exact key.
    """
    family_clean = family.strip()
    if family_clean in TABLE_12_SEVERITY_BASELINES:
        return family_clean

    fam_lower = family_clean.lower()
    for canonical in TABLE_12_SEVERITY_BASELINES:
        if fam_lower == canonical.lower():
            return canonical
        # Partial match fallbacks
        if "phishing" in fam_lower and "phishing" in canonical.lower():
            return canonical
        if "lateral" in fam_lower and "lateral" in canonical.lower():
            return canonical
        if "account" in fam_lower and "compromised" in canonical.lower():
            return canonical
        if "malware" in fam_lower and "malware" in canonical.lower():
            return canonical
        if ("c2" in fam_lower or "command" in fam_lower) and "command" in canonical.lower():
            return canonical
        if "cloud" in fam_lower and "cloud" in canonical.lower():
            return canonical
        if "exfiltration" in fam_lower and "exfiltration" in canonical.lower():
            return canonical
        if ("ransomware" in fam_lower or "ransom" in fam_lower) and "ransomware" in canonical.lower():
            return canonical
        if "insider" in fam_lower and "insider" in canonical.lower():
            return canonical

    raise ValueError(f"Unrecognized attack family: '{family}'. Must be one of {list(TABLE_12_SEVERITY_BASELINES.keys())}.")


def normalize_directive(directive: str) -> str:
    """
    Normalizes remediation directive string to Table 21 exact key.
    """
    dir_clean = directive.strip().upper().replace("-", "_").replace(" ", "_")
    if dir_clean in TABLE_21_CA_CATALOG:
        return dir_clean
    raise ValueError(f"Unrecognized remediation directive: '{directive}'. Must be one of {list(TABLE_21_CA_CATALOG.keys())}.")


# ==============================================================================
# CORE MATHEMATICAL FORMULAS (Autonomous SecOps Guardrail Specification v1.0, Section 4.3)
# ==============================================================================

def rsem(p: float, c_i: Union[int, float], c_a: Union[int, float]) -> float:
    """
    Risk-Sensitive Execution Metric (RSEM) formula (Equation 15).
    
    Mathematical definition:
        RSEM(P, C_I, C_A) = 100 * (P * C_I) / (P * C_I + C_A)
        
    Parameters:
      - p: float in [0.0, 1.0]. Judge confidence that investigated activity is malicious.
      - c_i: int or float in [1, 10]. Cost of Inaction (incident severity).
      - c_a: int or float in [1, 10]. Cost of Action (operational disruption).
      
    Returns:
      - Unrounded float representing RSEM score in [0.0, 100.0].
      
    Validation:
      - Raises ValueError if P is outside [0.0, 1.0].
      - Raises ValueError if C_I or C_A are outside [1, 10].
      - Maintains full floating-point precision for threshold comparisons;
        round to 1 decimal place only when formatting for user display.
    """
    if not (0.0 <= p <= 1.0):
        raise ValueError(f"Probability P must be within [0.0, 1.0], got {p}")
    if not (1 <= c_i <= 10):
        raise ValueError(f"Cost of Inaction C_I must be in range [1, 10], got {c_i}")
    if not (1 <= c_a <= 10):
        raise ValueError(f"Cost of Action C_A must be in range [1, 10], got {c_a}")

    numerator = 100.0 * (p * c_i)
    denominator = (p * c_i) + c_a

    if denominator == 0.0:
        return 0.0

    return numerator / denominator


# Alias for explicit naming
compute_rsem = rsem


def p_min(c_i: Union[int, float], c_a: Union[int, float]) -> float:
    """
    Minimum Required Confidence for Autonomous Actuation (Equation 21).
    
    Mathematical derivation:
        RSEM >= 75
        100 * (P * C_I) / (P * C_I + C_A) >= 75
        P * C_I >= 3 * C_A
        P_min = (3 * C_A) / C_I
        
    Parameters:
      - c_i: int or float in [1, 10]. Cost of Inaction.
      - c_a: int or float in [1, 10]. Cost of Action.
      
    Returns:
      - Unrounded float representing minimum P required.
      - If P_min > 1.0, autonomous actuation is mathematically impossible,
        matching Table 20 in the specification.
    """
    if not (1 <= c_i <= 10):
        raise ValueError(f"Cost of Inaction C_I must be in range [1, 10], got {c_i}")
    if not (1 <= c_a <= 10):
        raise ValueError(f"Cost of Action C_A must be in range [1, 10], got {c_a}")

    return (3.0 * float(c_a)) / float(c_i)


def severity(
    base: int,
    finding_class: Optional[str] = None,
    citation: Optional[str] = None,
    ledger: Optional[List[Dict[str, Any]]] = None
) -> int:
    """
    Raise-Only Severity Evaluation Engine (Equation 16).
    
    Mathematical formulation:
        C_I = max( C_{I,base}, C_I(finding_class) )
        
    Governance Invariant:
      1. Raise-Only Rule: Severity can NEVER decrease below C_{I,base}.
         An autonomous agent or model cannot downgrade severity.
      2. Grounded Citation Mandate: Any raise (C_I > C_{I,base}) strictly
         requires a valid citation pointing to an authentic ledger block
         matching ^LEDGER_\\d{3,}$ (e.g. 'LEDGER_002').
      3. Ledger Cross-Validation: When ledger is provided, verifies that:
         - The cited entry exists in the ledger.
         - The entry was signed by ROLE_INV_EXECUTOR (or adjudicated by ROLE_JUDGE).
         - The entry payload contains the exact matching finding_class.
      4. Free-form text, hallucinations, or unverified claims are rejected.
      
    Parameters:
      - base: int in [1, 10]. Initial baseline severity from Table 12.
      - finding_class: Optional finding class string from Table 13.
      - citation: Optional string reference to a ledger entry (e.g. 'LEDGER_002').
      - ledger: Optional list of verified ledger block dicts.
      
    Returns:
      - int in [1, 10]: The governed incident severity C_I.
      
    Raises:
      - ValueError: If base is outside [1, 10].
      - ValueError: If finding_class is unknown.
      - ValueError: If a severity raise is attempted without a valid citation.
      - ValueError: If citation does not match ^LEDGER_\\d{3,}$.
      - ValueError: If citation is not found in ledger or fails role/finding verification.
    """
    if not (1 <= base <= 10):
        raise ValueError(f"Baseline severity base must be in range [1, 10], got {base}")

    # If no finding class is proposed, severity remains at baseline
    if finding_class is None:
        return base

    fc_clean = finding_class.strip().upper()
    if fc_clean not in TABLE_13_FINDING_CLASS_SEVERITY:
        raise ValueError(
            f"Unknown finding class '{finding_class}'. Must be one of {list(TABLE_13_FINDING_CLASS_SEVERITY.keys())}"
        )

    override_score = TABLE_13_FINDING_CLASS_SEVERITY[fc_clean]

    # Check if this finding class would result in a raise
    if override_score > base:
        # Grounded citation requirement: MUST provide a non-empty ledger citation
        if not citation or not citation.strip():
            raise ValueError(
                f"Severity raise from {base} to {override_score} via '{fc_clean}' "
                "rejected: requires an explicit citation to a verified ledger entry (e.g. 'LEDGER_002')."
            )

        cit_clean = citation.strip()
        if not CITATION_PATTERN.match(cit_clean):
            raise ValueError(
                f"Invalid citation format '{citation}'. Must match '^LEDGER_\\d{{3,}}$' (e.g. 'LEDGER_002')."
            )

        # Cross-validate against verified ledger if provided
        if ledger is not None:
            matching_entries = [e for e in ledger if e.get("entry_id") == cit_clean]
            if not matching_entries:
                raise ValueError(
                    f"Severity raise citation '{cit_clean}' not found in the verified ledger."
                )

            cited_entry = matching_entries[0]

            # Role verification: findings must be signed by ROLE_INV_EXECUTOR or adjudicated by ROLE_JUDGE
            signer_role = (
                cited_entry.get("agent_role")
                or cited_entry.get("signature_metadata", {}).get("signer_identity")
            )
            allowed_roles = {"ROLE_INV_EXECUTOR", "ROLE_JUDGE"}
            if signer_role not in allowed_roles:
                raise ValueError(
                    f"Citation '{cit_clean}' signed by unauthorized role '{signer_role}'. "
                    f"Findings must be signed by ROLE_INV_EXECUTOR or adjudicated by ROLE_JUDGE."
                )

            # Inspect payload structure for finding_class
            payload = cited_entry.get("payload")
            recorded_finding = None
            if isinstance(payload, dict):
                recorded_finding = payload.get("finding_class")
            elif isinstance(payload, str):
                try:
                    payload_dict = json.loads(payload)
                    if isinstance(payload_dict, dict):
                        recorded_finding = payload_dict.get("finding_class")
                except Exception:
                    pass

            if recorded_finding != fc_clean:
                raise ValueError(
                    f"Citation '{cit_clean}' payload records finding_class '{recorded_finding}', "
                    f"which does not match cited finding '{fc_clean}'."
                )

        return override_score

    # If override_score <= base, raise-only governance keeps the higher baseline
    return base


# ==============================================================================
# LOOKUP & GOVERNANCE HELPERS
# ==============================================================================

def get_baseline_severity(attack_family: str, asset_tier: Union[str, int]) -> int:
    """
    Retrieves baseline incident severity C_{I,base} from Table 12.
    """
    fam_canonical = normalize_attack_family(attack_family)
    tier_canonical = normalize_asset_tier(asset_tier)
    return TABLE_12_SEVERITY_BASELINES[fam_canonical][tier_canonical]


def get_action_cost(directive: str, asset_tier: Union[str, int]) -> int:
    """
    Retrieves containment action cost C_A from Table 21.
    """
    dir_canonical = normalize_directive(directive)
    tier_canonical = normalize_asset_tier(asset_tier)
    return TABLE_21_CA_CATALOG[dir_canonical][tier_canonical]


def evaluate_autonomy_ceiling(c_a: Union[int, float]) -> bool:
    """
    Evaluates Invariant #4: Hard Autonomy Ceiling.
    
    Returns:
      - True: If C_A >= 4. Autonomous actuation is unconditionally BARRED.
        Must escalate to human Expert authorization.
      - False: If C_A < 4. Autonomous actuation may be permissible if RSEM >= 75.
    """
    return c_a >= AUTONOMY_CEILING_THRESHOLD


def is_identity_directive(directive: str) -> bool:
    """
    Returns True if directive is an identity-oriented action eligible for
    Out-of-Band (OOB) step-up hold in Zone 2.
    """
    try:
        norm = normalize_directive(directive)
        return norm in IDENTITY_DIRECTIVES
    except ValueError:
        return False


def classify_decision_zone(
    rsem_score: float,
    c_a: Union[int, float],
    is_identity_action: bool = False,
    oob_status: Union[OOBStatus, str] = OOBStatus.PENDING,
    oob_denied: Optional[bool] = None
) -> Tuple[str, str, str]:
    """
    Maps an action into deterministic decision zones (Specification Table 22 & OPA soc_containment.rego).
    
    Evaluation Order (Invariant #4 evaluated FIRST):
      1. Rule 1: Front-line Autonomy Ceiling (C_A >= 4):
         Evaluated FIRST. Even if OOB is CONFIRMED_LEGITIMATE, high-disruption
         actions (C_A >= 4) unconditionally escalate to human Expert.
         -> ('ZONE_CEILING', 'ESCALATE', 'HARD_AUTONOMY_CEILING_EXCEEDED')
      2. Rule 2: Zone 1 Autonomous Execution (C_A <= 3, RSEM >= 75.0):
         -> ('ZONE_1_AUTONOMOUS', 'ALLOW', 'ZONE1_AUTONOMOUS_ALLOW')
      3. Rule 2b: Zone 2 Post-OOB Denial Execution (C_A <= 3, 50 <= RSEM < 75, identity action, user denied activity):
         -> ('ZONE_2_GRAY', 'ALLOW', 'ZONE2_POST_DENIAL_ALLOW')
      4. Zone 2 Confirmed Legitimate (C_A <= 3, 50 <= RSEM < 75, identity action, user approved prompt):
         -> ('ZONE_STAND_DOWN', 'STAND_DOWN', 'OOB_CONFIRMED_LEGITIMATE')
      5. Rule 3: Zone 2 Gray Zone Identity Action (C_A <= 3, 50 <= RSEM < 75, identity action, pending):
         -> ('ZONE_2_GRAY', 'OOB_REQUIRED', 'ZONE2_OOB_STEP_UP')
      6. Rule 4: Zone 2 Gray Zone Non-Identity Action (C_A <= 3, 50 <= RSEM < 75, non-identity action):
         -> ('ZONE_2_GRAY', 'ESCALATE', 'ZONE2_NON_IDENTITY_ESCALATE')
      7. Rule 5: Zone 3 Gatekeeper (C_A <= 3, RSEM < 50.0):
         -> ('ZONE_3_GATEKEEPER', 'ESCALATE', 'ZONE3_GATEKEEPER_ESCALATE')
         
    Returns:
      - (zone_name: str, decision: str, reason_code: str)
    """
    # Rule 1: Front-line Autonomy Ceiling check (Invariant #4) - MUST BE FIRST
    if evaluate_autonomy_ceiling(c_a):
        return (
            "ZONE_CEILING",
            "ESCALATE",
            "HARD_AUTONOMY_CEILING_EXCEEDED"
        )

    # Defensive type check: reject raw bool for oob_status to prevent silent misrouting
    if isinstance(oob_status, bool):
        raise TypeError(
            f"oob_status must be an OOBStatus enum or str, got bool ({oob_status}). "
            "Pass OOBStatus.DENIED_BY_USER, OOBStatus.CONFIRMED_LEGITIMATE, or OOBStatus.PENDING instead."
        )

    # Rule 2: Zone 1 Autonomous Execution
    if rsem_score >= AUTONOMOUS_ACTUATION_THRESHOLD:
        return (
            "ZONE_1_AUTONOMOUS",
            "ALLOW",
            "ZONE1_AUTONOMOUS_ALLOW"
        )

    # Zone 2: Gray Zone (50.0 <= RSEM < 75.0)
    if rsem_score >= PRECAUTIONARY_HOLD_MIN_THRESHOLD:
        if is_identity_action:
            # Resolve OOB status with backward compatibility for boolean oob_denied
            status_val = oob_status
            if oob_denied is not None:
                status_val = OOBStatus.DENIED_BY_USER if oob_denied else OOBStatus.PENDING
            elif isinstance(status_val, str):
                try:
                    status_val = OOBStatus(status_val.upper())
                except ValueError:
                    raise ValueError(
                        f"Invalid OOBStatus '{oob_status}'. Must be one of {[s.value for s in OOBStatus]}"
                    )

            if status_val == OOBStatus.DENIED_BY_USER:
                # Rule 2b: User denied OOB prompt (fraud/malice confirmed); execute containment
                return (
                    "ZONE_2_GRAY",
                    "ALLOW",
                    "ZONE2_POST_DENIAL_ALLOW"
                )
            elif status_val == OOBStatus.CONFIRMED_LEGITIMATE:
                # User confirmed they legitimately performed the action (false positive); abort containment
                return (
                    "ZONE_STAND_DOWN",
                    "STAND_DOWN",
                    "OOB_CONFIRMED_LEGITIMATE"
                )
            else:
                # Rule 3: Requires Out-of-Band verification
                return (
                    "ZONE_2_GRAY",
                    "OOB_REQUIRED",
                    "ZONE2_OOB_STEP_UP"
                )

        # Rule 4: Non-identity action in gray zone escalates to human expert
        return (
            "ZONE_2_GRAY",
            "ESCALATE",
            "ZONE2_NON_IDENTITY_ESCALATE"
        )

    # Rule 5: Zone 3 Gatekeeper (RSEM < 50.0)
    return (
        "ZONE_3_GATEKEEPER",
        "ESCALATE",
        "ZONE3_GATEKEEPER_ESCALATE"
    )

