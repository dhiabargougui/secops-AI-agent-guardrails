"""
test_characterization.py - Characterization tests and baseline invariant assertions.

Pins baseline behavior across the five core architectural invariants and explicitly
asserts Invariant #4 (Hard Autonomy Ceiling) across all 24 cells of Table 21.
"""

import copy
import pytest
from src.policy.rsem import (
    TABLE_21_CA_CATALOG,
    TABLE_12_SEVERITY_BASELINES,
    TABLE_13_FINDING_CLASS_SEVERITY,
    OOBStatus,
    classify_decision_zone,
    rsem,
    severity,
)
from src.policy.pep_gate import evaluate as pep_evaluate, find_opa_binary
from src.ledger.chain import append, verify_chain, GENESIS_PREV_HASH
from src.policy.anti_anchoring import agent_view
from src.execution.actuator import create_containment_order, OrderExecutor


class TestBaselineInvariantAssertions:
    """Explicit assertions proving the architectural invariants across continuous ranges."""

    # --------------------------------------------------------------------------
    # FIX-07: Explicit Autonomy Ceiling Invariant Assertion Test (All 24 Cells)
    # --------------------------------------------------------------------------
    @pytest.mark.parametrize("rsem_val", [0.0, 25.0, 49.9, 50.0, 74.9, 75.0, 85.0, 100.0])
    @pytest.mark.parametrize("oob_st", [OOBStatus.PENDING, OOBStatus.DENIED_BY_USER, OOBStatus.CONFIRMED_LEGITIMATE])
    def test_explicit_catalog_autonomy_ceiling_all_cells(self, rsem_val: float, oob_st: OOBStatus):
        """
        Directly asserts that for every cell in Table 21 where C_A >= 4,
        actuation is unconditionally barred and strictly escalates,
        regardless of RSEM score (0.0 to 100.0) or OOB status.
        """
        identity_actions = {"REVOKE_ACTIVE_SESSIONS", "ENFORCE_STEP_UP_AUTH", "DISABLE_ACCOUNT"}

        ceiling_tested = 0
        for action_type, tiers in TABLE_21_CA_CATALOG.items():
            is_identity = action_type in identity_actions
            for tier_name, c_a in tiers.items():
                if c_a >= 4:
                    zone, decision, reason = classify_decision_zone(
                        rsem_score=rsem_val,
                        c_a=c_a,
                        is_identity_action=is_identity,
                        oob_status=oob_st,
                    )
                    assert zone == "ZONE_CEILING", (
                        f"Expected ZONE_CEILING for {action_type} on {tier_name} (CA={c_a})"
                    )
                    assert decision == "ESCALATE", (
                        f"Expected ESCALATE for {action_type} on {tier_name} (CA={c_a})"
                    )
                    assert reason == "HARD_AUTONOMY_CEILING_EXCEEDED", (
                        f"Expected HARD_AUTONOMY_CEILING_EXCEEDED for {action_type} on {tier_name}"
                    )
                    ceiling_tested += 1

        # Exactly 7 cells in Table 21 have C_A >= 4:
        # ISOLATE_HOST (Tier 0=10, Tier 1=9, Tier 2=5) -> 3
        # REVOKE_ACTIVE_SESSIONS (Tier 0=5) -> 1
        # DISABLE_ACCOUNT (Tier 0=9, Tier 1=6, Tier 2=4) -> 3
        # Total = 7 cells
        assert ceiling_tested == 7

    def test_opa_autonomy_ceiling_boundary_extremities(self):
        """OPA PEP gate also strictly escalates at RSEM = 0.0 and RSEM = 100.0 for C_A >= 4."""
        opa_bin = find_opa_binary()
        if not opa_bin:
            pytest.skip("OPA binary not found on path")

        # Test ISOLATE_HOST on Tier 1 (C_A = 9) at RSEM 0.0 and 100.0
        res_0 = pep_evaluate("ISOLATE_HOST", 1, 0.0, oob_status=OOBStatus.CONFIRMED_LEGITIMATE)
        assert res_0["decision"] == "ESCALATE"
        assert res_0["reason"] == "HARD_AUTONOMY_CEILING_EXCEEDED"

        res_100 = pep_evaluate("ISOLATE_HOST", 1, 100.0, oob_status=OOBStatus.CONFIRMED_LEGITIMATE)
        assert res_100["decision"] == "ESCALATE"
        assert res_100["reason"] == "HARD_AUTONOMY_CEILING_EXCEEDED"

        # Test DISABLE_ACCOUNT on Tier 2 (C_A = 4) at RSEM 100.0
        res_da = pep_evaluate("DISABLE_ACCOUNT", 2, 100.0, oob_status=OOBStatus.DENIED_BY_USER)
        assert res_da["decision"] == "ESCALATE"
        assert res_da["reason"] == "HARD_AUTONOMY_CEILING_EXCEEDED"

    # --------------------------------------------------------------------------
    # FIX-00: Characterization Baselines
    # --------------------------------------------------------------------------
    def test_characterize_genesis_anchor_prev_hash(self):
        """Characterizes the Genesis block previous hash anchor (64 zeros)."""
        chain = []
        append(chain, {"incident_id": "INC-TEST", "payload": {"data": "test"}}, salt="aa" * 32)
        assert chain[0]["entry_id"] == "LEDGER_000"
        assert chain[0]["prev_entry_hash"] == GENESIS_PREV_HASH
        assert chain[0]["prev_entry_hash"] == "0" * 64

    def test_characterize_raise_only_severity_contract(self):
        """Characterizes that severity can never be reduced below baseline."""
        # Baseline severity 9 (e.g. Lateral Movement on Tier 1)
        base = 9
        # Proposed finding is FND_C2_ESTABLISHED with score 7
        lower_class = "FND_C2_ESTABLISHED"
        assert TABLE_13_FINDING_CLASS_SEVERITY[lower_class] == 7
        # Calling severity with lower finding class must preserve base 9
        res = severity(base=base, finding_class=lower_class)
        assert res == base

    def test_characterize_actuator_valid_execution(self):
        """Characterizes valid actuator execution flow."""
        secret_key = "test-secret-key-char-32bytes!!"
        pep_eval = {"decision": "ALLOW", "reason": "ZONE1_HIGH_RSEM_ALLOW"}
        order = create_containment_order(
            pep_evaluation=pep_eval,
            action_type="BLOCK_IOC",
            target_entity="203.0.113.5",
            tenant_id="tenant-ch",
            incident_id="INC-CH-01",
            decision_citation="LEDGER_005",
            secret_key=secret_key,
            current_time=1700000000.0,
        )
        executor = OrderExecutor(secret_key=secret_key)
        receipt = executor.execute_order(order, current_time=1700000010.0)
        assert receipt["status"] == "EXECUTED"
        assert receipt["order_id"] == order["order_id"]
        assert receipt["executor_role"] == "ROLE_ORDER_EXECUTOR"
