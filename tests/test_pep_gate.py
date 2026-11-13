# Autonomous AI SOC Platform — PEP Gateway Test Suite
# Autonomous SecOps Guardrail Specification v1.0 — Section 5.3 & Section 5.3.5
# tests/test_pep_gate.py
#
# Comprehensive test suite verifying the PEP gateway:
# 1. Normal evaluation across all 6 decision outcomes
# 2. Defensive input validation and error rejection (Refinements 2 & 3)
# 3. Fail-closed posture on OPA missing, timeout, or failure
# 4. Differential parity grid between Python reference (rsem.py) and OPA (soc_containment.rego)

import pytest
from src.policy.pep_gate import evaluate, find_opa_binary, IDENTITY_ACTIONS
from src.policy.rsem import (
    OOBStatus,
    TABLE_21_CA_CATALOG,
    classify_decision_zone,
)


@pytest.fixture(scope="module")
def opa_available():
    binary = find_opa_binary()
    if binary is None:
        pytest.skip("tools/opa.exe binary not available in environment")
    return binary


# =============================================================================
# 1. Unit Tests Across All Decision Zones & Outcomes
# =============================================================================

def test_zone1_autonomous_allow(opa_available):
    """Zone 1 Green: Low disruption (C_A=2) + high RSEM (79.9) -> ALLOW."""
    res = evaluate("ISOLATE_HOST", "Tier 3", 79.9, oob_status=OOBStatus.PENDING)
    assert res["decision"] == "ALLOW"
    assert res["reason"] == "ZONE1_AUTONOMOUS_ALLOW"


def test_zone1_exact_75_boundary(opa_available):
    """Zone 1 boundary: Exact RSEM 75.0 evaluates to ALLOW."""
    res = evaluate("BLOCK_IOC", "Tier 2", 75.0)
    assert res["decision"] == "ALLOW"
    assert res["reason"] == "ZONE1_AUTONOMOUS_ALLOW"


def test_zone2_gray_zone_identity_step_up(opa_available):
    """Zone 2 Gray: Identity action (C_A=3) + gray RSEM (74.3) + PENDING -> OOB_REQUIRED."""
    res = evaluate("REVOKE_ACTIVE_SESSIONS", "Tier 1", 74.3, oob_status=OOBStatus.PENDING)
    assert res["decision"] == "OOB_REQUIRED"
    assert res["reason"] == "ZONE2_OOB_STEP_UP"


def test_zone2_gray_zone_post_denial_allow(opa_available):
    """Zone 2 Post-Denial: User denied activity -> credential theft confirmed -> ALLOW."""
    res = evaluate("REVOKE_ACTIVE_SESSIONS", "Tier 1", 74.3, oob_status=OOBStatus.DENIED_BY_USER)
    assert res["decision"] == "ALLOW"
    assert res["reason"] == "ZONE2_POST_DENIAL_ALLOW"


def test_zone2_gray_zone_confirmed_legitimate_stand_down(opa_available):
    """Zone 2 Stand-Down: User confirmed legitimate activity -> abort containment -> STAND_DOWN."""
    res = evaluate("REVOKE_ACTIVE_SESSIONS", "Tier 1", 74.3, oob_status=OOBStatus.CONFIRMED_LEGITIMATE)
    assert res["decision"] == "STAND_DOWN"
    assert res["reason"] == "OOB_CONFIRMED_LEGITIMATE"


def test_zone2_gray_zone_non_identity_escalate(opa_available):
    """Zone 2 Non-Identity: ISOLATE_HOST has no OOB channel -> ESCALATE."""
    res = evaluate("ISOLATE_HOST", "Tier 3", 71.3, oob_status=OOBStatus.PENDING)
    assert res["decision"] == "ESCALATE"
    assert res["reason"] == "ZONE2_NON_IDENTITY_ESCALATE"


def test_zone3_gatekeeper_escalate(opa_available):
    """Zone 3 Red: Low conviction (RSEM 49.1 < 50.0) -> ESCALATE."""
    res = evaluate("ISOLATE_HOST", "Tier 3", 49.1, oob_status=OOBStatus.PENDING)
    assert res["decision"] == "ESCALATE"
    assert res["reason"] == "ZONE3_GATEKEEPER_ESCALATE"


def test_rule1_hard_autonomy_ceiling_tier0_isolate(opa_available):
    """Invariant #4: C_A >= 4 (Tier 0 ISOLATE_HOST = 10) unconditionally escalates."""
    res = evaluate("ISOLATE_HOST", "Tier 0", 99.5, oob_status=OOBStatus.DENIED_BY_USER)
    assert res["decision"] == "ESCALATE"
    assert res["reason"] == "HARD_AUTONOMY_CEILING_EXCEEDED"


def test_rule1_hard_autonomy_ceiling_tier1_isolate(opa_available):
    """Invariant #4: Tier 1 ISOLATE_HOST (C_A = 9) unconditionally escalates."""
    res = evaluate("ISOLATE_HOST", "Tier 1", 85.0)
    assert res["decision"] == "ESCALATE"
    assert res["reason"] == "HARD_AUTONOMY_CEILING_EXCEEDED"


def test_rule1_ceiling_overrides_confirmed_legitimate(opa_available):
    """Invariant #4 Precedence: C_A >= 4 cannot be overridden by user confirmation."""
    res = evaluate("REVOKE_ACTIVE_SESSIONS", "Tier 0", 65.0, oob_status=OOBStatus.CONFIRMED_LEGITIMATE)
    assert res["decision"] == "ESCALATE"
    assert res["reason"] == "HARD_AUTONOMY_CEILING_EXCEEDED"


def test_unmapped_action_fails_closed_to_ceiling(opa_available):
    """Unmapped actions fail closed to C_A = 10 -> HARD_AUTONOMY_CEILING_EXCEEDED."""
    res = evaluate("UNKNOWN_CONTAINMENT_DIRECTIVE", "Tier 3", 95.0)
    assert res["decision"] == "ESCALATE"
    assert res["reason"] == "HARD_AUTONOMY_CEILING_EXCEEDED"


def test_unmapped_tier_fails_closed_to_ceiling(opa_available):
    """Unmapped asset tiers fail closed to C_A = 10 -> HARD_AUTONOMY_CEILING_EXCEEDED."""
    res = evaluate("ISOLATE_HOST", "Tier 99", 95.0)
    assert res["decision"] == "ESCALATE"
    assert res["reason"] == "HARD_AUTONOMY_CEILING_EXCEEDED"


# =============================================================================
# 2. Defensive Validations & Error Handling (Refinements 2 & 3)
# =============================================================================

def test_raw_bool_rsem_rejected():
    """rsem cannot be a raw boolean."""
    with pytest.raises(TypeError, match="rsem cannot be a boolean"):
        evaluate("ISOLATE_HOST", 3, True)


def test_non_numeric_rsem_rejected():
    """rsem must be a finite numeric value."""
    with pytest.raises(ValueError, match="rsem must be a finite numeric value"):
        evaluate("ISOLATE_HOST", 3, float("nan"))


def test_out_of_range_rsem_high_rejected():
    """rsem > 100.0 rejected before spawning OPA."""
    with pytest.raises(ValueError, match=r"rsem must be in range \[0.0, 100.0\]"):
        evaluate("ISOLATE_HOST", 3, 105.0)


def test_out_of_range_rsem_negative_rejected():
    """rsem < 0.0 rejected before spawning OPA."""
    with pytest.raises(ValueError, match=r"rsem must be in range \[0.0, 100.0\]"):
        evaluate("ISOLATE_HOST", 3, -1.0)


def test_raw_bool_oob_status_rejected():
    """oob_status cannot be a raw boolean."""
    with pytest.raises(TypeError, match="oob_status cannot be a raw boolean"):
        evaluate("ISOLATE_HOST", 3, 75.0, oob_status=True)


def test_invalid_oob_status_string_rejected():
    """Unknown oob_status string rejected."""
    with pytest.raises(ValueError, match="Invalid oob_status string"):
        evaluate("ISOLATE_HOST", 3, 75.0, oob_status="MAYBE_LEGITIMATE")


def test_conflicting_oob_parameters_rejected():
    """Conflicting oob_status and legacy oob_denied raises ValueError."""
    with pytest.raises(ValueError, match="Conflicting OOB states"):
        evaluate(
            "REVOKE_ACTIVE_SESSIONS",
            1,
            65.0,
            oob_status=OOBStatus.CONFIRMED_LEGITIMATE,
            oob_denied=True,
        )


def test_legacy_oob_denied_true_normalized(opa_available):
    """Legacy oob_denied=True correctly normalizes to DENIED_BY_USER."""
    res = evaluate("REVOKE_ACTIVE_SESSIONS", 1, 74.3, oob_denied=True)
    assert res["decision"] == "ALLOW"
    assert res["reason"] == "ZONE2_POST_DENIAL_ALLOW"


def test_legacy_oob_denied_false_normalized(opa_available):
    """Legacy oob_denied=False correctly normalizes to PENDING."""
    res = evaluate("REVOKE_ACTIVE_SESSIONS", 1, 74.3, oob_denied=False)
    assert res["decision"] == "OOB_REQUIRED"
    assert res["reason"] == "ZONE2_OOB_STEP_UP"


def test_empty_action_type_rejected():
    """Empty action_type raises ValueError."""
    with pytest.raises(ValueError, match="action_type must be a non-empty string"):
        evaluate("", 3, 75.0)


# =============================================================================
# 3. Fail-Closed Posture on Gateway & Subprocess Failures
# =============================================================================

def test_missing_opa_binary_fails_closed():
    """If OPA binary is missing, gateway fails closed to ESCALATE."""
    res = evaluate("ISOLATE_HOST", 3, 80.0, opa_path="nonexistent_opa_binary.exe")
    assert res["decision"] == "ESCALATE"
    assert res["reason"] == "GATEWAY_FAIL_CLOSED_ERROR"
    assert "could not be located" in res["error"]


def test_missing_policy_file_fails_closed(opa_available):
    """If policy file is missing, gateway fails closed to ESCALATE."""
    res = evaluate("ISOLATE_HOST", 3, 80.0, policy_path="nonexistent_policy.rego")
    assert res["decision"] == "ESCALATE"
    assert res["reason"] == "GATEWAY_FAIL_CLOSED_ERROR"
    assert "not found" in res["error"]


def test_opa_timeout_fails_closed(opa_available):
    """If OPA evaluation times out, gateway fails closed to ESCALATE."""
    # A timeout of 0.000001s triggers TimeoutExpired
    res = evaluate("ISOLATE_HOST", 3, 80.0, timeout_seconds=0.000001)
    assert res["decision"] == "ESCALATE"
    assert res["reason"] == "GATEWAY_FAIL_CLOSED_ERROR"
    assert "timed out" in res["error"]


# =============================================================================
# 4. Differential Parity Matrix: Python reference (rsem.py) vs OPA Rego (pep_gate.py)
# =============================================================================

@pytest.mark.parametrize("action_type", list(TABLE_21_CA_CATALOG.keys()))
@pytest.mark.parametrize("tier_idx", [0, 1, 2, 3])
@pytest.mark.parametrize("rsem_val", [25.0, 49.9, 50.0, 60.0, 74.9, 75.0, 85.0])
@pytest.mark.parametrize(
    "oob_st",
    [OOBStatus.PENDING, OOBStatus.DENIED_BY_USER, OOBStatus.CONFIRMED_LEGITIMATE],
)
def test_differential_parity_cross_product(
    opa_available, action_type, tier_idx, rsem_val, oob_st
):
    """Differential testing proving 100% agreement across all 504 test combinations."""
    tier_str = f"Tier {tier_idx}"
    c_a = TABLE_21_CA_CATALOG[action_type][tier_str]
    is_identity = action_type in IDENTITY_ACTIONS

    _, expected_decision, expected_reason = classify_decision_zone(
        rsem_score=rsem_val,
        c_a=c_a,
        is_identity_action=is_identity,
        oob_status=oob_st,
    )

    opa_result = evaluate(
        action_type=action_type,
        asset_tier=tier_idx,
        rsem=rsem_val,
        oob_status=oob_st,
    )

    assert opa_result["decision"] == expected_decision, (
        f"Decision mismatch for {action_type} on {tier_str} (CA={c_a}) with "
        f"RSEM={rsem_val}, OOB={oob_st.value}: expected {expected_decision}, got {opa_result['decision']}"
    )
    assert opa_result["reason"] == expected_reason, (
        f"Reason mismatch for {action_type} on {tier_str} (CA={c_a}) with "
        f"RSEM={rsem_val}, OOB={oob_st.value}: expected {expected_reason}, got {opa_result['reason']}"
    )


# ==============================================================================
# SECTION: FAIL-CLOSED BRANCH COVERAGE (FIX-09)
# ==============================================================================

def test_pep_evaluate_invalid_oob_status_type():
    """oob_status of invalid type raises TypeError."""
    with pytest.raises(TypeError, match="oob_status must be OOBStatus or str"):
        evaluate("ISOLATE_HOST", 3, 75.0, oob_status=12345)


def test_pep_evaluate_invalid_oob_denied_type():
    """oob_denied of non-bool/non-None type raises TypeError."""
    with pytest.raises(TypeError, match="oob_denied must be a boolean or None"):
        evaluate("ISOLATE_HOST", 3, 75.0, oob_denied="true_string")


def test_pep_evaluate_conflicting_denied_by_user_with_oob_denied_false():
    """oob_status=DENIED_BY_USER conflicting with oob_denied=False raises ValueError."""
    with pytest.raises(ValueError, match="conflicts with legacy oob_denied=False"):
        evaluate(
            "REVOKE_ACTIVE_SESSIONS",
            1,
            65.0,
            oob_status=OOBStatus.DENIED_BY_USER,
            oob_denied=False,
        )


def test_pep_evaluate_opa_failure_and_malformed_outputs(monkeypatch):
    """Verifies fail-closed ESCALATE outcomes on subprocess errors and malformed output."""
    import subprocess
    from pathlib import Path
    existing_file = str(Path(__file__).resolve())

    class DummyProc:
        def __init__(self, returncode=0, stdout="{}", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    # 1. Non-zero exit code
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: DummyProc(returncode=1, stderr="syntax error"))
    res1 = evaluate("ISOLATE_HOST", 3, 75.0, opa_path=existing_file)
    assert res1["decision"] == "ESCALATE"
    assert res1["reason"] == "GATEWAY_FAIL_CLOSED_ERROR"

    # 2. Empty result list
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: DummyProc(returncode=0, stdout='{"result": []}'))
    res2 = evaluate("ISOLATE_HOST", 3, 75.0, opa_path=existing_file)
    assert res2["decision"] == "ESCALATE"
    assert res2["reason"] == "NO_MATCHING_RULE"

    # 3. Empty expressions list
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: DummyProc(returncode=0, stdout='{"result": [{"expressions": []}]}'))
    res3 = evaluate("ISOLATE_HOST", 3, 75.0, opa_path=existing_file)
    assert res3["decision"] == "ESCALATE"
    assert res3["reason"] == "NO_MATCHING_RULE"

    # 4. Malformed expression value (non-dict)
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: DummyProc(returncode=0, stdout='{"result": [{"expressions": [{"value": "not-a-dict"}]}]}'))
    res4 = evaluate("ISOLATE_HOST", 3, 75.0, opa_path=existing_file)
    assert res4["decision"] == "ESCALATE"
    assert res4["reason"] == "GATEWAY_FAIL_CLOSED_ERROR"

    # 5. Subprocess raises OSError
    def raise_oserror(*args, **kwargs):
        raise OSError("Permission denied to executable")
    monkeypatch.setattr(subprocess, "run", raise_oserror)
    res5 = evaluate("ISOLATE_HOST", 3, 75.0, opa_path=existing_file)
    assert res5["decision"] == "ESCALATE"
    assert res5["reason"] == "GATEWAY_FAIL_CLOSED_ERROR"

