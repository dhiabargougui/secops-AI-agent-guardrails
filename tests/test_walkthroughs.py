# Autonomous AI SOC Platform — Walkthrough Replay & Counterfactual Suite
# Autonomous SecOps Guardrail Specification v1.0 — Section 4.5 & Section 5.6
# tests/test_walkthroughs.py
#
# Deterministic replays of:
#   - Walkthrough 1 (INC-2026-4401): 14-block phishing investigation, dynamic severity raise,
#     Phishing Scenario counterfactual sensitivity analysis, and pinned golden head hash.
#   - Walkthrough 2 (INC-2026-8820): 15-block lateral movement attack, OOB attestation,
#     multi-directive gating, Hard Autonomy Ceiling enforcement, and pinned golden head hash.

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from src.ledger.chain import verify_chain
from src.policy.anti_anchoring import agent_view
from src.policy.pep_gate import evaluate, find_opa_binary
from src.policy.rsem import (
    OOBStatus,
    TABLE_12_SEVERITY_BASELINES,
    compute_rsem,
    severity,
)


# Pinned golden cryptographic head hashes
GOLDEN_HEAD_INC_2026_4401 = "f1ee3e47957b57aeb428908d41cc7d60b704da7694e550f26adb4ec9c090c3ac"
GOLDEN_HEAD_INC_2026_8820 = "5a22007d561c17a5249d5e43a3f95c853d382fbd442d65b01a1560f4ef7ddad8"

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "incident_handoff_v1_2_0.json"


@pytest.fixture(scope="module")
def schema_validator():
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema = json.load(f)
    return Draft202012Validator(schema, format_checker=FormatChecker())


@pytest.fixture(scope="module")
def fixture_4401():
    with open(FIXTURES_DIR / "inc_2026_4401.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def fixture_8820():
    with open(FIXTURES_DIR / "inc_2026_8820.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def opa_available():
    binary = find_opa_binary()
    if binary is None:
        pytest.skip("tools/opa.exe binary not available in environment")
    return binary


# =============================================================================
# Refinement 1: Validate LEDGER_000 Schema and Runtime Anti-Anchoring Projection
# =============================================================================

def test_ledger_000_schema_and_anti_anchoring_wt1(fixture_4401, schema_validator):
    """Verifies WT1 genesis payload satisfies schema and anti-anchoring projection."""
    genesis_entry = fixture_4401[0]
    payload = genesis_entry["payload"]

    # 1. Validates against canonical JSON schema
    schema_validator.validate(payload)
    assert payload["evaluation_metadata"]["non_evidentiary_for_agents"] is True

    # 2. Validates runtime projection layer
    projected = agent_view(payload)
    assert "evaluation_metadata" not in projected
    assert "initial_triage" not in projected
    assert projected["incident_cluster_id"] == "b0000000-0000-0000-0000-000000004401"
    assert "WS-ALICE-11" in projected["query_perimeter"]["target_hosts"]


def test_ledger_000_schema_and_anti_anchoring_wt2(fixture_8820, schema_validator):
    """Verifies WT2 genesis payload satisfies schema and anti-anchoring projection."""
    genesis_entry = fixture_8820[0]
    payload = genesis_entry["payload"]

    schema_validator.validate(payload)
    assert payload["evaluation_metadata"]["non_evidentiary_for_agents"] is True

    projected = agent_view(payload)
    assert "evaluation_metadata" not in projected
    assert "initial_triage" not in projected
    assert projected["incident_cluster_id"] == "b0000000-0000-0000-0000-000000008820"
    assert "SRV-PROD-DB01" in projected["query_perimeter"]["target_hosts"]


# =============================================================================
# Refinement 2: Explicit finding_class Key in WT1 LEDGER_008 Payload
# =============================================================================

def test_wt1_ledger_008_finding_class_contract(fixture_4401):
    """Verifies LEDGER_008 has required finding_class and valid role for severity raising."""
    entry_008 = fixture_4401[8]
    assert entry_008["entry_id"] == "LEDGER_008"
    assert entry_008["agent_role"] == "ROLE_INV_EXECUTOR"
    assert entry_008["payload"]["finding_class"] == "FND_TOKEN_MINT"
    assert entry_008["payload"]["finding_id"] == "FND_4401_05"


# =============================================================================
# Refinement 3: Verify Both Ledger Salt Modes Against Pinned Golden Head Hashes
# =============================================================================

def test_wt1_ledger_verification_in_block_and_external_salt(fixture_4401):
    """Verifies WT1 14-block chain in both in-block and external key_store salt modes."""
    # Mode A: Standard in-block verification against pinned golden head
    valid_a, err_a = verify_chain(fixture_4401, expected_head=GOLDEN_HEAD_INC_2026_4401)
    assert valid_a is True, f"WT1 in-block verification failed: {err_a}"
    assert fixture_4401[-1]["entry_hash"] == GOLDEN_HEAD_INC_2026_4401

    # Mode B: External key_store isolation verification against same head
    key_store = {entry["entry_id"]: entry["per_entry_salt"] for entry in fixture_4401}
    scrubbed_chain = copy.deepcopy(fixture_4401)
    for entry in scrubbed_chain:
        del entry["per_entry_salt"]

    valid_b, err_b = verify_chain(
        scrubbed_chain,
        expected_head=GOLDEN_HEAD_INC_2026_4401,
        key_store=key_store,
    )
    assert valid_b is True, f"WT1 external key_store verification failed: {err_b}"


def test_wt2_ledger_verification_in_block_and_external_salt(fixture_8820):
    """Verifies WT2 15-block chain in both in-block and external key_store salt modes."""
    valid_a, err_a = verify_chain(fixture_8820, expected_head=GOLDEN_HEAD_INC_2026_8820)
    assert valid_a is True, f"WT2 in-block verification failed: {err_a}"
    assert fixture_8820[-1]["entry_hash"] == GOLDEN_HEAD_INC_2026_8820

    key_store = {entry["entry_id"]: entry["per_entry_salt"] for entry in fixture_8820}
    scrubbed_chain = copy.deepcopy(fixture_8820)
    for entry in scrubbed_chain:
        del entry["per_entry_salt"]

    valid_b, err_b = verify_chain(
        scrubbed_chain,
        expected_head=GOLDEN_HEAD_INC_2026_8820,
        key_store=key_store,
    )
    assert valid_b is True, f"WT2 external key_store verification failed: {err_b}"


# =============================================================================
# Walkthrough 1 Replay: Phishing Credential Harvest (INC-2026-4401)
# =============================================================================

def test_walkthrough_1_phishing_investigation_replay(fixture_4401, opa_available):
    """Replays Walkthrough 1 end-to-end through ledger, severity, and OPA gateway."""
    # 1. Baseline Severity Lookup (Table 12: Phishing on Tier 3 = 5)
    ci_base = TABLE_12_SEVERITY_BASELINES["Phishing & Email Threats"]["Tier 3"]
    assert ci_base == 5

    # 2. Dynamic Severity Raise with Grounded Ledger Citation
    ci_final = severity(
        base=ci_base,
        finding_class="FND_TOKEN_MINT",
        citation="LEDGER_008",
        ledger=fixture_4401,
    )
    assert ci_final == 8  # max(5, 8) = 8

    # 3. Judge Confidence: P = 0.992
    p = 0.992

    # 4. Directive 1: PURGE_MESSAGE (Tier 3, C_A = 1)
    # Refinement 4: Pass unrounded compute_rsem directly to evaluate()
    rsem_purge = compute_rsem(p=p, c_i=ci_final, c_a=1)
    assert pytest.approx(rsem_purge, abs=0.01) == 88.81
    assert round(rsem_purge, 1) == 88.8
    res_purge = evaluate("PURGE_MESSAGE", "Tier 3", rsem_purge)
    assert res_purge["decision"] == "ALLOW"
    assert res_purge["reason"] == "ZONE1_AUTONOMOUS_ALLOW"

    # 5. Directive 2: REVOKE_ACTIVE_SESSIONS (Tier 3, C_A = 1)
    rsem_revoke = compute_rsem(p=p, c_i=ci_final, c_a=1)
    assert round(rsem_revoke, 1) == 88.8
    res_revoke = evaluate("REVOKE_ACTIVE_SESSIONS", "Tier 3", rsem_revoke)
    assert res_revoke["decision"] == "ALLOW"
    assert res_revoke["reason"] == "ZONE1_AUTONOMOUS_ALLOW"

    # 6. Directive 3: ISOLATE_HOST (Tier 3, C_A = 2)
    rsem_isolate = compute_rsem(p=p, c_i=ci_final, c_a=2)
    assert pytest.approx(rsem_isolate, abs=0.01) == 79.87
    assert round(rsem_isolate, 1) == 79.9
    res_isolate = evaluate("ISOLATE_HOST", "Tier 3", rsem_isolate)
    assert res_isolate["decision"] == "ALLOW"
    assert res_isolate["reason"] == "ZONE1_AUTONOMOUS_ALLOW"

    # 7. Receipts committed to ledger match gateway decisions
    assert fixture_4401[11]["payload"]["receipt_id"] == "REC_4401_01"
    assert fixture_4401[11]["payload"]["action_type"] == "PURGE_MESSAGE"
    assert fixture_4401[11]["payload"]["status"] == "CONFIRMED"

    assert fixture_4401[12]["payload"]["receipt_id"] == "REC_4401_02"
    assert fixture_4401[12]["payload"]["action_type"] == "REVOKE_ACTIVE_SESSIONS"
    assert fixture_4401[12]["payload"]["status"] == "CONFIRMED"

    assert fixture_4401[13]["payload"]["receipt_id"] == "REC_4401_03"
    assert fixture_4401[13]["payload"]["action_type"] == "ISOLATE_HOST"
    assert fixture_4401[13]["payload"]["status"] == "CONFIRMED"


# =============================================================================
# Refinement 4: Walkthrough 1 Phishing Scenario Counterfactual Sensitivity Analysis
# =============================================================================

def test_walkthrough_1_counterfactual_sensitivity_analysis(fixture_4401, opa_available):
    """Phishing Scenario Replay: Dropping LEDGER_008 flips host isolation to ESCALATE (decision robust)."""
    # 1. Construct counterfactual chain omitting LEDGER_008
    cf_chain = [entry for entry in fixture_4401 if entry["entry_id"] != "LEDGER_008"]
    assert len(cf_chain) == 13

    # Refinement 4: Assert severity raises ValueError if citation LEDGER_008 is cited
    # when that block is missing from the ledger
    with pytest.raises(ValueError, match="Severity raise citation 'LEDGER_008' not found in the verified ledger"):
        severity(5, "FND_TOKEN_MINT", citation="LEDGER_008", ledger=cf_chain)

    # 2. Severity falls back to baseline C_I = 5
    cf_ci = 5
    p = 0.992

    # 3. Message purge remains ALLOW (83.2 >= 75)
    rsem_purge = compute_rsem(p=p, c_i=cf_ci, c_a=1)
    assert pytest.approx(rsem_purge, abs=0.01) == 83.22
    assert evaluate("PURGE_MESSAGE", "Tier 3", rsem_purge)["decision"] == "ALLOW"

    # 4. Session revoke remains ALLOW (83.2 >= 75)
    rsem_revoke = compute_rsem(p=p, c_i=cf_ci, c_a=1)
    assert evaluate("REVOKE_ACTIVE_SESSIONS", "Tier 3", rsem_revoke)["decision"] == "ALLOW"

    # 5. Host isolation RSEM drops to 71.3 (< 75.0)
    rsem_isolate = compute_rsem(p=p, c_i=cf_ci, c_a=2)
    assert pytest.approx(rsem_isolate, abs=0.01) == 71.26
    assert round(rsem_isolate, 1) == 71.3

    # 6. Gateway evaluation flips from ALLOW to ESCALATE
    res_isolate = evaluate("ISOLATE_HOST", "Tier 3", rsem_isolate)
    assert res_isolate["decision"] == "ESCALATE"
    assert res_isolate["reason"] == "ZONE2_NON_IDENTITY_ESCALATE"


# =============================================================================
# Walkthrough 2 Replay: Governed Lateral Movement (INC-2026-8820)
# =============================================================================

def test_walkthrough_2_lateral_movement_replay(fixture_8820, opa_available):
    """Replays Walkthrough 2: Ceiling barring Tier 1 isolation and account disable."""
    # 1. Baseline Severity (Table 12: Lateral Movement on Tier 1 = 9)
    ci = TABLE_12_SEVERITY_BASELINES["Lateral Movement"]["Tier 1"]
    assert ci == 9
    p = 0.965

    # 2. Directive 1: ISOLATE_HOST on Tier 1 (C_A = 9) -> Ceiling ESCALATE
    rsem_isolate = compute_rsem(p=p, c_i=ci, c_a=9)
    assert pytest.approx(rsem_isolate, abs=0.01) == 49.11
    assert round(rsem_isolate, 1) == 49.1
    res_isolate = evaluate("ISOLATE_HOST", "Tier 1", rsem_isolate)
    assert res_isolate["decision"] == "ESCALATE"
    assert res_isolate["reason"] == "HARD_AUTONOMY_CEILING_EXCEEDED"
    assert fixture_8820[11]["payload"]["receipt_id"] == "REC_8820_01"
    assert fixture_8820[11]["payload"]["receipt_type"] == "ESCALATION_RECEIPT"

    # 3. Directive 2: REVOKE_ACTIVE_SESSIONS on Tier 1 (C_A = 3) -> OOB Step-Up & Allow
    rsem_revoke = compute_rsem(p=p, c_i=ci, c_a=3)
    assert pytest.approx(rsem_revoke, abs=0.01) == 74.33
    assert round(rsem_revoke, 1) == 74.3

    # Initial pending state -> OOB_REQUIRED
    res_pending = evaluate(
        "REVOKE_ACTIVE_SESSIONS", "Tier 1", rsem_revoke, oob_status=OOBStatus.PENDING
    )
    assert res_pending["decision"] == "OOB_REQUIRED"
    assert res_pending["reason"] == "ZONE2_OOB_STEP_UP"

    # User fraud denial -> ALLOW under post-denial threshold 50
    res_denied = evaluate(
        "REVOKE_ACTIVE_SESSIONS",
        "Tier 1",
        rsem_revoke,
        oob_status=OOBStatus.DENIED_BY_USER,
    )
    assert res_denied["decision"] == "ALLOW"
    assert res_denied["reason"] == "ZONE2_POST_DENIAL_ALLOW"
    assert fixture_8820[12]["payload"]["receipt_id"] == "REC_8820_02"
    assert fixture_8820[12]["payload"]["receipt_type"] == "EXECUTION_RECEIPT"

    # 4. Directive 3: BLOCK_IOC on External IP (Tier 1 Perimeter, C_A = 2) -> Zone 1 ALLOW
    rsem_block = compute_rsem(p=p, c_i=ci, c_a=2)
    assert pytest.approx(rsem_block, abs=0.01) == 81.28
    assert round(rsem_block, 1) == 81.3
    res_block = evaluate("BLOCK_IOC", "Tier 1", rsem_block)
    assert res_block["decision"] == "ALLOW"
    assert res_block["reason"] == "ZONE1_AUTONOMOUS_ALLOW"
    assert fixture_8820[13]["payload"]["receipt_id"] == "REC_8820_03"
    assert fixture_8820[13]["payload"]["receipt_type"] == "EXECUTION_RECEIPT"

    # 5. Directive 4: DISABLE_ACCOUNT on svc_dbadmin (Tier 1, C_A = 6) -> Ceiling ESCALATE
    rsem_disable = compute_rsem(p=p, c_i=ci, c_a=6)
    assert pytest.approx(rsem_disable, abs=0.01) == 59.14
    assert round(rsem_disable, 1) == 59.1

    # Invariant #4: Hard Autonomy Ceiling overrides user fraud denial
    res_disable = evaluate(
        "DISABLE_ACCOUNT", "Tier 1", rsem_disable, oob_status=OOBStatus.DENIED_BY_USER
    )
    assert res_disable["decision"] == "ESCALATE"
    assert res_disable["reason"] == "HARD_AUTONOMY_CEILING_EXCEEDED"
    assert fixture_8820[14]["payload"]["receipt_id"] == "REC_8820_04"
    assert fixture_8820[14]["payload"]["receipt_type"] == "ESCALATION_RECEIPT"


# =============================================================================
# Adversarial Tamper Detection Against Pinned Golden Head Hashes
# =============================================================================

def test_tamper_detection_against_pinned_head_wt1(fixture_4401):
    """Tampering with historical entries breaks verification against golden head hash."""
    tampered_chain = copy.deepcopy(fixture_4401)
    tampered_chain[4]["payload"]["clicked_at_utc"] = "2026-10-24T20:11:59Z"

    valid, err = verify_chain(tampered_chain, expected_head=GOLDEN_HEAD_INC_2026_4401)
    assert valid is False
    assert "Tampered payload detected at LEDGER_004" in err


def test_tip_truncation_detection_against_pinned_head_wt1(fixture_4401):
    """Truncating tip entries is immediately caught by anchored golden head hash."""
    truncated_chain = copy.deepcopy(fixture_4401[:-1])

    valid, err = verify_chain(truncated_chain, expected_head=GOLDEN_HEAD_INC_2026_4401)
    assert valid is False
    assert "Tip truncation or head mismatch" in err


def test_tamper_detection_against_pinned_head_wt2(fixture_8820):
    """Tampering with WT2 telemetry breaks verification against golden head hash."""
    tampered_chain = copy.deepcopy(fixture_8820)
    tampered_chain[8]["payload"]["ticket_id"] = "CHG-99999"

    valid, err = verify_chain(tampered_chain, expected_head=GOLDEN_HEAD_INC_2026_8820)
    assert valid is False
    assert "Tampered payload detected at LEDGER_008" in err


def test_tip_truncation_detection_against_pinned_head_wt2(fixture_8820):
    """Truncating tip entries in WT2 is caught by anchored golden head hash."""
    truncated_chain = copy.deepcopy(fixture_8820[:-1])

    valid, err = verify_chain(truncated_chain, expected_head=GOLDEN_HEAD_INC_2026_8820)
    assert valid is False
    assert "Tip truncation or head mismatch" in err
