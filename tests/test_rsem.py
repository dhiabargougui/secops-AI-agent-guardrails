"""
================================================================================
TEST SUITE: Risk-Sensitive Execution Metric (RSEM) & Severity Governance
File: tests/test_rsem.py
================================================================================
Architectural Invariant & Mechanism:
  - Invariant #4: Hard Autonomy Ceiling (C_A >= 4 barred from autonomous execution).
  - Policy Mechanism: Raise-Only Severity Governance (Strictly non-decreasing C_I,
    grounded by authentic ledger citations).

Governing Specification:
  - Autonomous SecOps Guardrail Specification v1.0, Section 4.3 (Equations 15–21, Tables 12, 13, 20, 21, 22)
  - Incident Walkthrough 1 (INC-2026-4401)
  - Incident Walkthrough 2 (INC-2026-8820)

Test Scope:
  1. Golden Walkthrough Mathematical Accuracy (8 published target values).
  2. Baseline Severity Matrix Lookups (Table 12).
  3. Deterministic Finding-Class Severity Lookups (Table 13).
  4. Cost-of-Action Matrix Lookups (Table 21).
  5. Minimum Confidence Threshold Derivations (Equation 21 & Table 20).
  6. Raise-Only Severity Governance & Citation Enforcement (Equation 16).
  7. Decision Zone Mapping & Invariant #4 Front-Line Ceiling (Table 22 & OPA Rego).
  8. Boundary & Negative Input Validation.
================================================================================
"""

import json
import pytest
from src.policy.rsem import (
    TABLE_12_SEVERITY_BASELINES,
    TABLE_13_FINDING_CLASS_SEVERITY,
    TABLE_21_CA_CATALOG,
    IDENTITY_DIRECTIVES,
    AUTONOMY_CEILING_THRESHOLD,
    AUTONOMOUS_ACTUATION_THRESHOLD,
    PRECAUTIONARY_HOLD_MIN_THRESHOLD,
    OOBStatus,
    CITATION_PATTERN,
    rsem,
    p_min,
    severity,
    get_baseline_severity,
    get_action_cost,
    evaluate_autonomy_ceiling,
    classify_decision_zone,
    is_identity_directive,
    normalize_asset_tier,
    normalize_attack_family,
    normalize_directive,
)


# ==============================================================================
# SECTION 1: GOLDEN WALKTHROUGH MATHEMATICAL ACCURACY (EXACT MATCHES)
# ==============================================================================

@pytest.mark.parametrize(
    "case_name, p, c_i, c_a, expected_rsem",
    [
        # Walkthrough 1 (INC-2026-4401):
        # Token purge / revoke on Tier 3: P=0.992, C_I=8 (raised by FND_TOKEN_MINT), C_A=1
        ("WT1 purge / revoke", 0.992, 8, 1, 88.8),
        # Host isolation on Tier 3 workstation: P=0.992, C_I=8, C_A=2
        ("WT1 isolate (Tier 3)", 0.992, 8, 2, 79.9),
        # Counterfactual: Dropping LEDGER_008 evidence reverts C_I to baseline (5), C_A=2
        ("WT1 counterfactual (no FND_TOKEN_MINT)", 0.992, 5, 2, 71.3),

        # Walkthrough 2 (INC-2026-8820):
        # Host isolation on Tier 1 production server: P=0.965, C_I=9 (FND_CRED_DUMP), C_A=9
        ("WT2 isolate (Tier 1)", 0.965, 9, 9, 49.1),
        # Session revoke on Tier 1: P=0.965, C_I=9, C_A=3
        ("WT2 revoke", 0.965, 9, 3, 74.3),
        # Block IOC (perimeter firewall): P=0.965, C_I=9, C_A=2
        ("WT2 block IOC", 0.965, 9, 2, 81.3),
        # Disable account on Tier 1: P=0.965, C_I=9, C_A=6
        ("WT2 disable account", 0.965, 9, 6, 59.1),

        # Specification Section 4.3 synthetic benchmarks:
        # Equation 18: P=1.0, C_I=10, C_A=3 -> 76.92
        ("Eq. 18 benchmark (C_A=3)", 1.000, 10, 3, 76.92),
        # Equation 19: P=1.0, C_I=10, C_A=4 -> 71.43
        ("Eq. 19 benchmark (C_A=4)", 1.000, 10, 4, 71.43),
    ]
)
def test_golden_rsem_values(case_name, p, c_i, c_a, expected_rsem):
    """
    Verifies that the RSEM formula matches the exact published numbers in the
    Autonomous SecOps Guardrail Specification v1.0 across all walkthrough scenarios.
    """
    calculated = rsem(p, c_i, c_a)
    # Target values with 1 decimal place match within abs=0.05
    # Target values with 2 decimal places (Eq 18/19) match within abs=0.01
    tolerance = 0.02 if expected_rsem in (76.92, 71.43) else 0.05
    assert calculated == pytest.approx(expected_rsem, abs=tolerance), (
        f"Case '{case_name}' failed: expected {expected_rsem}, got {calculated:.4f}"
    )


# ==============================================================================
# SECTION 2: REFERENCE TABLES & LOOKUP INTEGRITY
# ==============================================================================

def test_table_12_baselines_integrity():
    """
    Verifies Table 12: 9 Attack Families x 4 Asset Tiers = 36 total cells.
    """
    assert len(TABLE_12_SEVERITY_BASELINES) == 9
    for family, tiers in TABLE_12_SEVERITY_BASELINES.items():
        assert len(tiers) == 4
        for tier_name in ("Tier 0", "Tier 1", "Tier 2", "Tier 3"):
            assert tier_name in tiers
            assert 1 <= tiers[tier_name] <= 10

    # Concrete spot checks
    assert get_baseline_severity("Phishing & Email Threats", "Tier 3") == 5
    assert get_baseline_severity("Phishing & Email Threats", "Tier 0") == 10
    assert get_baseline_severity("Lateral Movement", "Tier 1") == 9
    assert get_baseline_severity("Ransomware & Destruction", "Tier 3") == 8
    assert get_baseline_severity("Compromised Accounts", "Tier 2") == 6


def test_table_13_finding_class_severity():
    """
    Verifies Table 13 deterministic finding-class severity scores.
    """
    expected = {
        "FND_CRED_DUMP": 9,
        "FND_TOKEN_MINT": 8,
        "FND_LATERAL_MOVE": 8,
        "FND_RANSOM_PREP": 10,
        "FND_C2_ESTABLISHED": 7,
        "FND_DEFENSE_EVASION": 8,
    }
    assert TABLE_13_FINDING_CLASS_SEVERITY == expected


def test_table_21_action_costs():
    """
    Verifies Table 21: 6 Remediation Directives x 4 Asset Tiers = 24 total cells.
    """
    assert len(TABLE_21_CA_CATALOG) == 6
    for directive, tiers in TABLE_21_CA_CATALOG.items():
        assert len(tiers) == 4
        for tier_name in ("Tier 0", "Tier 1", "Tier 2", "Tier 3"):
            assert tier_name in tiers
            assert 1 <= tiers[tier_name] <= 10

    # Spot checks
    assert get_action_cost("ISOLATE_HOST", "Tier 3") == 2
    assert get_action_cost("ISOLATE_HOST", "Tier 2") == 5
    assert get_action_cost("ISOLATE_HOST", "Tier 1") == 9
    assert get_action_cost("ISOLATE_HOST", "Tier 0") == 10
    assert get_action_cost("REVOKE_ACTIVE_SESSIONS", "Tier 3") == 1
    assert get_action_cost("REVOKE_ACTIVE_SESSIONS", "Tier 0") == 5
    assert get_action_cost("DISABLE_ACCOUNT", "Tier 1") == 6


def test_tier_and_directive_normalization():
    """
    Verifies robust input normalization for asset tiers, attack families, and directives.
    """
    # Asset tiers
    assert normalize_asset_tier(0) == "Tier 0"
    assert normalize_asset_tier("0") == "Tier 0"
    assert normalize_asset_tier("Tier 0") == "Tier 0"
    assert normalize_asset_tier("Crown Jewel") == "Tier 0"
    assert normalize_asset_tier(1) == "Tier 1"
    assert normalize_asset_tier("1") == "Tier 1"
    assert normalize_asset_tier("production") == "Tier 1"
    assert normalize_asset_tier(2) == "Tier 2"
    assert normalize_asset_tier("2") == "Tier 2"
    assert normalize_asset_tier("internal") == "Tier 2"
    assert normalize_asset_tier(3) == "Tier 3"
    assert normalize_asset_tier("workstation") == "Tier 3"

    # Strict rejection of boolean inputs (FIX-05)
    with pytest.raises(ValueError, match="Invalid boolean asset tier"):
        normalize_asset_tier(True)
    with pytest.raises(ValueError, match="Invalid boolean asset tier"):
        normalize_asset_tier(False)

    # Strict rejection of float inputs
    with pytest.raises(ValueError, match="Invalid float asset tier"):
        normalize_asset_tier(1.0)
    with pytest.raises(ValueError, match="Invalid float asset tier"):
        normalize_asset_tier(0.0)

    # Strict rejection of multi-digit strings and unmapped aliases
    for invalid in ("Tier 10", "host-20", "unknown-30", "unknown-88", "tier", "", "Tier 99"):
        with pytest.raises(ValueError, match="Unrecognized asset tier"):
            normalize_asset_tier(invalid)

    # Directives
    assert normalize_directive("isolate_host") == "ISOLATE_HOST"
    assert normalize_directive("ISOLATE-HOST") == "ISOLATE_HOST"
    assert normalize_directive("revoke active sessions") == "REVOKE_ACTIVE_SESSIONS"

    # Attack families
    assert normalize_attack_family("phishing") == "Phishing & Email Threats"
    assert normalize_attack_family("lateral movement") == "Lateral Movement"
    assert normalize_attack_family("c2") == "Command & Control"


# ==============================================================================
# SECTION 3: MINIMUM CONFIDENCE (P_MIN) & TABLE 20 DERIVATIONS
# ==============================================================================

def test_p_min_derivations_and_table_20():
    """
    Verifies Equation 21 (P_min = 3 * C_A / C_I) against Table 20 in the specification.
    """
    # C_A = 1
    assert p_min(c_i=10, c_a=1) == pytest.approx(0.300, abs=0.001)
    assert p_min(c_i=8, c_a=1) == pytest.approx(0.375, abs=0.001)
    assert p_min(c_i=5, c_a=1) == pytest.approx(0.600, abs=0.001)
    assert p_min(c_i=3, c_a=1) == pytest.approx(1.000, abs=0.001)

    # C_A = 2
    assert p_min(c_i=10, c_a=2) == pytest.approx(0.600, abs=0.001)
    assert p_min(c_i=8, c_a=2) == pytest.approx(0.750, abs=0.001)
    # For C_I=5, P_min = 6/5 = 1.20 (> 1.0, mathematically impossible)
    assert p_min(c_i=5, c_a=2) > 1.0

    # C_A = 3
    assert p_min(c_i=10, c_a=3) == pytest.approx(0.900, abs=0.001)
    assert p_min(c_i=8, c_a=3) > 1.0  # 9/8 = 1.125 > 1.0

    # C_A >= 4 (Impossible for all C_I <= 10)
    for c_i in range(1, 11):
        assert p_min(c_i=c_i, c_a=4) > 1.0


# ==============================================================================
# SECTION 4: RAISE-ONLY SEVERITY GOVERNANCE (EQUATION 16)
# ==============================================================================

def test_severity_raise_with_valid_citation():
    """
    Verifies that severity successfully raises from baseline when supported
    by a valid finding class and a non-empty ledger citation.
    """
    # WT1 scenario: Base Phishing on Tier 3 = 5. FND_TOKEN_MINT = 8.
    result = severity(base=5, finding_class="FND_TOKEN_MINT", citation="LEDGER_002")
    assert result == 8

    # WT2 scenario: Base Compromised Account on Tier 1 = 8. FND_CRED_DUMP = 9.
    result = severity(base=8, finding_class="FND_CRED_DUMP", citation="LEDGER_005")
    assert result == 9


def test_severity_raise_rejected_without_citation():
    """
    Verifies that any attempt to raise severity without an authentic ledger citation
    is strictly rejected with ValueError (anti-hallucination governance).
    """
    # Missing citation
    with pytest.raises(ValueError, match="requires an explicit citation"):
        severity(base=5, finding_class="FND_TOKEN_MINT", citation=None)

    # Empty string citation
    with pytest.raises(ValueError, match="requires an explicit citation"):
        severity(base=5, finding_class="FND_TOKEN_MINT", citation="")

    # Whitespace-only citation
    with pytest.raises(ValueError, match="requires an explicit citation"):
        severity(base=5, finding_class="FND_TOKEN_MINT", citation="   ")


@pytest.mark.parametrize("invalid_citation", ["manual", "LEDGER_99", "LEDGER_XYZ", "INV-2026-4401", "LEDGER_"])
def test_severity_invalid_citation_format_rejected(invalid_citation):
    """
    Verifies that citations not matching ^LEDGER_\\d{3,}$ are rejected.
    """
    with pytest.raises(ValueError, match="Invalid citation format"):
        severity(base=5, finding_class="FND_TOKEN_MINT", citation=invalid_citation)


def test_severity_ledger_cross_validation():
    """
    Verifies full cross-validation of severity raises against a verified ledger:
      1. Legitimate cited entry signed by ROLE_INV_EXECUTOR with matching finding succeeds.
      2. Citation not present in ledger is rejected.
      3. Citation signed by unauthorized role (e.g. ROLE_PLANNER) is rejected.
      4. Citation with mismatched finding class in payload is rejected.
    """
    valid_ledger = [
        {
            "entry_id": "LEDGER_000",
            "agent_role": "ROLE_PLANNER",
            "payload": {"h_malicious": "OAuth abuse"}
        },
        {
            "entry_id": "LEDGER_001",
            "agent_role": "ROLE_INVESTIGATOR",
            "payload": {"objective": "Query Entra ID logs"}
        },
        {
            "entry_id": "LEDGER_002",
            "agent_role": "ROLE_INV_EXECUTOR",
            "payload": {"finding_class": "FND_TOKEN_MINT", "scope": "WS-ALICE-11"}
        },
        {
            "entry_id": "LEDGER_003",
            "agent_role": "ROLE_PLANNER",
            "payload": {"finding_class": "FND_CRED_DUMP", "note": "Unverified planner claim"}
        },
    ]

    # 1. Legitimate raise: LEDGER_002 is signed by ROLE_INV_EXECUTOR with FND_TOKEN_MINT
    result = severity(base=5, finding_class="FND_TOKEN_MINT", citation="LEDGER_002", ledger=valid_ledger)
    assert result == 8

    # 2. Citation not in ledger
    with pytest.raises(ValueError, match="not found in the verified ledger"):
        severity(base=5, finding_class="FND_TOKEN_MINT", citation="LEDGER_999", ledger=valid_ledger)

    # 3. Citation signed by unauthorized role (ROLE_PLANNER)
    with pytest.raises(ValueError, match="signed by unauthorized role"):
        severity(base=5, finding_class="FND_CRED_DUMP", citation="LEDGER_003", ledger=valid_ledger)

    # 4. Citation records FND_TOKEN_MINT, but caller cites FND_CRED_DUMP
    with pytest.raises(ValueError, match="does not match cited finding"):
        severity(base=5, finding_class="FND_CRED_DUMP", citation="LEDGER_002", ledger=valid_ledger)


def test_severity_raise_only_rule_blocks_downgrade():
    """
    Verifies the Raise-Only Invariant: If a finding class has a score lower than
    the baseline severity, severity() preserves the higher baseline.
    """
    # Base is 9 (e.g. Lateral Movement on Tier 1).
    # Proposed finding is FND_C2_ESTABLISHED (score 7).
    # Result must remain 9 (max(base, finding_class)).
    result = severity(base=9, finding_class="FND_C2_ESTABLISHED", citation="LEDGER_003")
    assert result == 9


def test_severity_unknown_finding_class_rejected():
    """
    Verifies that arbitrary, un-enumerated finding classes are rejected.
    """
    with pytest.raises(ValueError, match="Unknown finding class"):
        severity(base=5, finding_class="FND_UNVERIFIED_HUNCH", citation="LEDGER_001")


def test_severity_default_no_finding():
    """
    Verifies that calling severity without a finding class safely returns baseline.
    """
    assert severity(base=7) == 7
    assert severity(base=10) == 10


# ==============================================================================
# SECTION 5: INVARIANT #4 AUTONOMY CEILING & DECISION ZONES
# ==============================================================================

def test_autonomy_ceiling_invariant_4():
    """
    Verifies Invariant #4: Actions with C_A >= 4 are unconditionally barred
    from autonomous actuation.
    """
    assert evaluate_autonomy_ceiling(4) is True
    assert evaluate_autonomy_ceiling(5) is True
    assert evaluate_autonomy_ceiling(9) is True
    assert evaluate_autonomy_ceiling(10) is True

    assert evaluate_autonomy_ceiling(3) is False
    assert evaluate_autonomy_ceiling(2) is False
    assert evaluate_autonomy_ceiling(1) is False


def test_decision_zone_ceiling_rule_1():
    """
    Verifies Rule 1: C_A >= 4 escalates unconditionally to human Expert,
    even when RSEM is 100.0 (maximum risk).
    """
    zone, decision, reason = classify_decision_zone(rsem_score=100.0, c_a=4)
    assert zone == "ZONE_CEILING"
    assert decision == "ESCALATE"
    assert reason == "HARD_AUTONOMY_CEILING_EXCEEDED"

    zone, decision, reason = classify_decision_zone(rsem_score=99.9, c_a=9)
    assert decision == "ESCALATE"
    assert reason == "HARD_AUTONOMY_CEILING_EXCEEDED"


def test_decision_zone_1_autonomous_rule_2():
    """
    Verifies Rule 2: C_A <= 3 and RSEM >= 75.0 permits autonomous execution.
    """
    zone, decision, reason = classify_decision_zone(rsem_score=88.8, c_a=1)
    assert zone == "ZONE_1_AUTONOMOUS"
    assert decision == "ALLOW"
    assert reason == "ZONE1_AUTONOMOUS_ALLOW"

    zone, decision, reason = classify_decision_zone(rsem_score=75.0, c_a=3)
    assert decision == "ALLOW"
    assert reason == "ZONE1_AUTONOMOUS_ALLOW"


def test_decision_zone_2_gray_zone_identity_action_rule_3():
    """
    Verifies Rule 3: C_A <= 3 and 50 <= RSEM < 75 for identity actions
    requires Out-of-Band (OOB) step-up verification.
    """
    zone, decision, reason = classify_decision_zone(
        rsem_score=65.0,
        c_a=2,
        is_identity_action=True,
        oob_denied=False
    )
    assert zone == "ZONE_2_GRAY"
    assert decision == "OOB_REQUIRED"
    assert reason == "ZONE2_OOB_STEP_UP"


def test_decision_zone_2_post_oob_denial_rule_2b():
    """
    Verifies Rule 2b: If user denies OOB challenge (confirming attack or malice),
    the containment action is approved for execution.
    """
    # Test via Enum
    zone, decision, reason = classify_decision_zone(
        rsem_score=65.0,
        c_a=2,
        is_identity_action=True,
        oob_status=OOBStatus.DENIED_BY_USER
    )
    assert zone == "ZONE_2_GRAY"
    assert decision == "ALLOW"
    assert reason == "ZONE2_POST_DENIAL_ALLOW"

    # Test backward compatibility via boolean
    zone, decision, reason = classify_decision_zone(
        rsem_score=65.0,
        c_a=2,
        is_identity_action=True,
        oob_denied=True
    )
    assert zone == "ZONE_2_GRAY"
    assert decision == "ALLOW"
    assert reason == "ZONE2_POST_DENIAL_ALLOW"


def test_decision_zone_2_confirmed_legitimate_stands_down():
    """
    Verifies that when user confirms legitimate activity (false positive),
    the system aborts containment and stands down.
    """
    zone, decision, reason = classify_decision_zone(
        rsem_score=65.0,
        c_a=2,
        is_identity_action=True,
        oob_status=OOBStatus.CONFIRMED_LEGITIMATE
    )
    assert zone == "ZONE_STAND_DOWN"
    assert decision == "STAND_DOWN"
    assert reason == "OOB_CONFIRMED_LEGITIMATE"


def test_autonomy_ceiling_overrides_confirmed_legitimate():
    """
    CRITICAL INVARIANT TEST:
    Verifies that Rule 1 (C_A >= 4) is evaluated BEFORE any OOB logic.
    Even if OOB status is CONFIRMED_LEGITIMATE, a high-blast action (C_A >= 4)
    can NEVER bypass the ceiling and must still escalate to human Expert.
    """
    zone, decision, reason = classify_decision_zone(
        rsem_score=65.0,
        c_a=4,  # Autonomy ceiling threshold
        is_identity_action=True,
        oob_status=OOBStatus.CONFIRMED_LEGITIMATE
    )
    assert zone == "ZONE_CEILING"
    assert decision == "ESCALATE"
    assert reason == "HARD_AUTONOMY_CEILING_EXCEEDED"


def test_oob_status_bool_rejected():
    """
    Verifies defensive type checking: passing a raw bool to oob_status raises TypeError.
    """
    with pytest.raises(TypeError, match="oob_status must be an OOBStatus enum or str"):
        classify_decision_zone(rsem_score=65.0, c_a=2, is_identity_action=True, oob_status=True)

    with pytest.raises(TypeError, match="oob_status must be an OOBStatus enum or str"):
        classify_decision_zone(rsem_score=65.0, c_a=2, is_identity_action=True, oob_status=False)


def test_oob_status_strenum_json_serializability():
    """
    Verifies that OOBStatus is a StrEnum that serializes cleanly to JSON without
    requiring custom encoders (for Day 4 OPA evaluation).
    """
    assert isinstance(OOBStatus.PENDING, str)
    assert isinstance(OOBStatus.DENIED_BY_USER, str)
    assert isinstance(OOBStatus.CONFIRMED_LEGITIMATE, str)

    payload = {"status": OOBStatus.CONFIRMED_LEGITIMATE}
    serialized = json.dumps(payload)
    assert serialized == '{"status": "CONFIRMED_LEGITIMATE"}'


def test_decision_zone_2_gray_zone_non_identity_rule_4():
    """
    Verifies Rule 4: C_A <= 3 and 50 <= RSEM < 75 for non-identity actions
    cannot step up via OOB, so it escalates to human Experts.
    """
    zone, decision, reason = classify_decision_zone(
        rsem_score=65.0,
        c_a=2,
        is_identity_action=False
    )
    assert zone == "ZONE_2_GRAY"
    assert decision == "ESCALATE"
    assert reason == "ZONE2_NON_IDENTITY_ESCALATE"


def test_decision_zone_3_gatekeeper_rule_5():
    """
    Verifies Rule 5: C_A <= 3 and RSEM < 50.0 is below containment threshold,
    escalating to human review.
    """
    zone, decision, reason = classify_decision_zone(rsem_score=49.1, c_a=2)
    assert zone == "ZONE_3_GATEKEEPER"
    assert decision == "ESCALATE"
    assert reason == "ZONE3_GATEKEEPER_ESCALATE"


def test_identity_directive_classification():
    """
    Verifies that identity directives are correctly distinguished.
    """
    assert is_identity_directive("REVOKE_ACTIVE_SESSIONS") is True
    assert is_identity_directive("ENFORCE_STEP_UP_AUTH") is True
    assert is_identity_directive("DISABLE_ACCOUNT") is True

    assert is_identity_directive("ISOLATE_HOST") is False
    assert is_identity_directive("BLOCK_IOC") is False
    assert is_identity_directive("PURGE_MESSAGE") is False


# ==============================================================================
# SECTION 6: BOUNDARY & NEGATIVE INPUT VALIDATION
# ==============================================================================

@pytest.mark.parametrize("invalid_p", [-0.01, -1.0, 1.01, 2.5])
def test_rsem_invalid_probability(invalid_p):
    """
    Verifies that probabilities outside [0.0, 1.0] raise ValueError.
    """
    with pytest.raises(ValueError, match="Probability P must be within"):
        rsem(p=invalid_p, c_i=8, c_a=1)


@pytest.mark.parametrize("invalid_ci", [0, -1, 11, 20])
def test_rsem_invalid_ci(invalid_ci):
    """
    Verifies that Cost of Inaction outside [1, 10] raises ValueError.
    """
    with pytest.raises(ValueError, match="Cost of Inaction C_I must be in range"):
        rsem(p=0.9, c_i=invalid_ci, c_a=1)


@pytest.mark.parametrize("invalid_ca", [0, -1, 11, 20])
def test_rsem_invalid_ca(invalid_ca):
    """
    Verifies that Cost of Action outside [1, 10] raises ValueError.
    """
    with pytest.raises(ValueError, match="Cost of Action C_A must be in range"):
        rsem(p=0.9, c_i=8, c_a=invalid_ca)


def test_severity_invalid_base():
    """
    Verifies that baseline severity outside [1, 10] raises ValueError.
    """
    with pytest.raises(ValueError, match="Baseline severity base must be in range"):
        severity(base=0)
    with pytest.raises(ValueError, match="Baseline severity base must be in range"):
        severity(base=11)


def test_normalize_invalid_inputs():
    """
    Verifies that unknown tiers, families, and directives raise ValueError.
    """
    with pytest.raises(ValueError, match="Unrecognized asset tier"):
        normalize_asset_tier("Tier 99")
    with pytest.raises(ValueError, match="Unrecognized attack family"):
        normalize_attack_family("Space Alien Attack")
    with pytest.raises(ValueError, match="Unrecognized remediation directive"):
        normalize_directive("FORMAT_C_DRIVE")


# ==============================================================================
# SECTION: FAIL-CLOSED BRANCH COVERAGE (FIX-09)
# ==============================================================================

def test_severity_raise_payload_as_json_string():
    """
    Verifies that severity() correctly parses JSON-string serialized payloads
    when cross-validating finding_class in a ledger citation.
    """
    import json
    chain = [
        {"entry_id": "LEDGER_000", "payload": {}},
        {
            "entry_id": "LEDGER_001",
            "agent_role": "ROLE_INV_EXECUTOR",
            "payload": json.dumps({"finding_class": "FND_TOKEN_MINT"}),
        },
    ]
    res = severity(
        base=5,
        finding_class="FND_TOKEN_MINT",
        citation="LEDGER_001",
        ledger=chain,
    )
    assert res == 8


def test_is_identity_directive_unknown_directive_returns_false():
    """Unknown directives safely return False instead of raising unhandled exceptions."""
    assert is_identity_directive("NON_EXISTENT_DIRECTIVE_123") is False


def test_classify_decision_zone_invalid_oob_status_string():
    """Invalid oob_status string in Zone 2 raises ValueError."""
    with pytest.raises(ValueError, match="Invalid OOBStatus"):
        classify_decision_zone(
            rsem_score=60.0,
            c_a=2,
            is_identity_action=True,
            oob_status="INVALID_STATUS_STRING",
        )

