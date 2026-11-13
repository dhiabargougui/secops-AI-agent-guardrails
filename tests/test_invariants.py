"""
Autonomous AI SOC Platform — Comprehensive Adversarial & Invariant Test Suite
Autonomous SecOps Guardrail Specification v1.0 — Section 2.1 (Architectural Invariants #1 through #5)
tests/test_invariants.py

Test Organization:
  1. TestInvariant1ActuationIntegrity: PEP authorization binding, HMAC signing,
     replay prevention, clock skew bounds, and cache poisoning protection.
  2. TestInvariant2AntiAnchoring: Deeply nested triage smuggling, mutation isolation,
     and Hypothesis property-based fuzzing.
  3. TestInvariant3LedgerTamperResistance: Retroactive insertion, sequence gaps,
     cross-tenant splicing, KMS key store desync, genesis tampering, and tip truncation.
  4. TestInvariant4AutonomyCeilingAndSeverity: Hypothesis property tests across continuous
     RSEM domain, OPA parameter injection resistance, and deterministic raise-only severity.
  5. TestInvariant5PreReleaseSafety: Tier 0/1 auto-close ban, Four-Eyes dual control
     enforcement, timeout escalation to SOC Manager, and autonomous agent rejection.
"""

import copy
import json
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.execution.actuator import (
    ActuationAuthorizationError,
    OrderExecutor,
    OrderValidationError,
    create_containment_order,
)
from src.ledger.chain import append, canonicalize_json, verify_chain
from src.policy.anti_anchoring import (
    CognitiveAnchoringLeakError,
    agent_view,
)
from src.policy.pep_gate import evaluate as pep_evaluate
from src.policy.pep_gate import find_opa_binary
from src.policy.release_gate import (
    GOVERNED_RELEASE_ACTIONS,
    RegisteredApprover,
    ReleaseGateError,
    SecurityViolationError,
    clear_seen_approval_nonces,
    create_approval_signature,
    evaluate_hold_release,
    evaluate_phase1_autoclose,
)
from src.policy.rsem import (
    TABLE_12_SEVERITY_BASELINES,
    TABLE_13_FINDING_CLASS_SEVERITY,
    TABLE_21_CA_CATALOG,
    OOBStatus,
    classify_decision_zone,
    rsem,
    severity,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
GOLDEN_HEAD_INC_2026_4401 = "f1ee3e47957b57aeb428908d41cc7d60b704da7694e550f26adb4ec9c090c3ac"
GOLDEN_HEAD_INC_2026_8820 = "5a22007d561c17a5249d5e43a3f95c853d382fbd442d65b01a1560f4ef7ddad8"


@pytest.fixture(scope="module")
def fixture_4401() -> List[Dict[str, Any]]:
    with open(FIXTURES_DIR / "inc_2026_4401.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def fixture_8820() -> List[Dict[str, Any]]:
    with open(FIXTURES_DIR / "inc_2026_8820.json", "r", encoding="utf-8") as f:
        return json.load(f)


# ==============================================================================
# INVARIANT #1: THE ACTUATION INVARIANT (src/execution/actuator.py)
# ==============================================================================

class TestInvariant1ActuationIntegrity:
    """Verifies that containment actuation occurs only via verified PEP authorization."""

    SECRET_KEY = "test-order-executor-secret-key-32b"

    def test_actuation_without_pep_allow_rejected(self):
        """Orders built without a PEP ALLOW decision are rejected immediately."""
        escalate_eval = {"decision": "ESCALATE", "reason": "HARD_AUTONOMY_CEILING_EXCEEDED"}
        with pytest.raises(ActuationAuthorizationError, match="required 'ALLOW'"):
            create_containment_order(
                pep_evaluation=escalate_eval,
                action_type="ISOLATE_HOST",
                target_entity="srv-prod-01",
                tenant_id="tenant-alpha",
                incident_id="INC-2026-1001",
                decision_citation="LEDGER_010",
                secret_key=self.SECRET_KEY,
            )

        oob_eval = {"decision": "OOB_REQUIRED", "reason": "IDENTITY_CONFIRMATION_PENDING"}
        with pytest.raises(ActuationAuthorizationError, match="required 'ALLOW'"):
            create_containment_order(
                pep_evaluation=oob_eval,
                action_type="REVOKE_ACTIVE_SESSIONS",
                target_entity="user@example.com",
                tenant_id="tenant-alpha",
                incident_id="INC-2026-1001",
                decision_citation="LEDGER_010",
                secret_key=self.SECRET_KEY,
            )

    def test_actuation_unauthorized_issuer_role_rejected(self):
        """Only ROLE_REM_EXECUTOR can issue signed containment orders."""
        allow_eval = {"decision": "ALLOW", "reason": "ZONE1_HIGH_RSEM_ALLOW"}
        for forbidden_role in ("ROLE_PLANNER", "ROLE_INVESTIGATOR", "ROLE_ADVERSARY", "ROLE_JUDGE"):
            with pytest.raises(ActuationAuthorizationError, match="Only 'ROLE_REM_EXECUTOR'"):
                create_containment_order(
                    pep_evaluation=allow_eval,
                    action_type="BLOCK_IOC",
                    target_entity="198.51.100.42",
                    tenant_id="tenant-alpha",
                    incident_id="INC-2026-1001",
                    decision_citation="LEDGER_010",
                    secret_key=self.SECRET_KEY,
                    issuer_role=forbidden_role,
                )

    def test_actuation_invalid_citation_format_rejected(self):
        """Decision citation must match ^LEDGER_\\d{3,}$."""
        allow_eval = {"decision": "ALLOW", "reason": "ZONE1_HIGH_RSEM_ALLOW"}
        for bad_citation in ("LEDGER_01", "LEDGER_001_OBJ", "FREE_TEXT_CLAIM", ""):
            with pytest.raises(ActuationAuthorizationError, match="Invalid decision citation"):
                create_containment_order(
                    pep_evaluation=allow_eval,
                    action_type="BLOCK_IOC",
                    target_entity="198.51.100.42",
                    tenant_id="tenant-alpha",
                    incident_id="INC-2026-1001",
                    decision_citation=bad_citation,
                    secret_key=self.SECRET_KEY,
                )

    def test_actuation_hmac_signature_tamper_rejected(self):
        """Modifying any signed parameter invalidates the HMAC signature."""
        allow_eval = {"decision": "ALLOW", "reason": "ZONE1_HIGH_RSEM_ALLOW"}
        order = create_containment_order(
            pep_evaluation=allow_eval,
            action_type="BLOCK_IOC",
            target_entity="198.51.100.42",
            tenant_id="tenant-alpha",
            incident_id="INC-2026-1001",
            decision_citation="LEDGER_010",
            secret_key=self.SECRET_KEY,
            current_time=1700000000.0,
        )

        executor = OrderExecutor(secret_key=self.SECRET_KEY)

        # Tampering target entity
        tampered_target = dict(order)
        tampered_target["target_entity"] = "198.51.100.99"
        with pytest.raises(OrderValidationError, match="Cryptographic signature verification failed"):
            executor.execute_order(tampered_target, current_time=1700000010.0)

        # Tampering action type
        tampered_action = dict(order)
        tampered_action["action_type"] = "DISABLE_ACCOUNT"
        with pytest.raises(OrderValidationError, match="Cryptographic signature verification failed"):
            executor.execute_order(tampered_action, current_time=1700000010.0)

    def test_actuation_replay_attack_rejected(self):
        """Submitting the same order nonce twice triggers replay detection."""
        allow_eval = {"decision": "ALLOW", "reason": "ZONE1_HIGH_RSEM_ALLOW"}
        order = create_containment_order(
            pep_evaluation=allow_eval,
            action_type="BLOCK_IOC",
            target_entity="198.51.100.42",
            tenant_id="tenant-alpha",
            incident_id="INC-2026-1001",
            decision_citation="LEDGER_010",
            secret_key=self.SECRET_KEY,
            current_time=1700000000.0,
        )

        executor = OrderExecutor(secret_key=self.SECRET_KEY)
        receipt = executor.execute_order(order, current_time=1700000010.0)
        assert receipt["status"] == "EXECUTED"

        # Replay attempt
        with pytest.raises(OrderValidationError, match="Replay attack detected"):
            executor.execute_order(order, current_time=1700000015.0)

    def test_actuation_expired_order_rejected(self):
        """Orders past their TTL expires_at timestamp are rejected."""
        allow_eval = {"decision": "ALLOW", "reason": "ZONE1_HIGH_RSEM_ALLOW"}
        order = create_containment_order(
            pep_evaluation=allow_eval,
            action_type="BLOCK_IOC",
            target_entity="198.51.100.42",
            tenant_id="tenant-alpha",
            incident_id="INC-2026-1001",
            decision_citation="LEDGER_010",
            secret_key=self.SECRET_KEY,
            ttl_seconds=60,
            current_time=1700000000.0,
        )

        executor = OrderExecutor(secret_key=self.SECRET_KEY)
        with pytest.raises(OrderValidationError, match="Order has expired"):
            executor.execute_order(order, current_time=1700000065.0)

    def test_actuation_future_timestamp_skew_rejected(self):
        """Orders timestamped beyond the clock skew allowance are rejected."""
        allow_eval = {"decision": "ALLOW", "reason": "ZONE1_HIGH_RSEM_ALLOW"}
        order = create_containment_order(
            pep_evaluation=allow_eval,
            action_type="BLOCK_IOC",
            target_entity="198.51.100.42",
            tenant_id="tenant-alpha",
            incident_id="INC-2026-1001",
            decision_citation="LEDGER_010",
            secret_key=self.SECRET_KEY,
            current_time=1700000100.0,
        )

        executor = OrderExecutor(secret_key=self.SECRET_KEY, clock_skew_seconds=30.0)
        # Current time is 1700000000.0, order issued_at is 1700000100.0 (skew = 100s > 30s)
        with pytest.raises(OrderValidationError, match="future beyond allowed clock skew"):
            executor.execute_order(order, current_time=1700000000.0)

    def test_actuation_nonce_cache_poisoning_prevented(self):
        """
        Unauthenticated orders with invalid HMAC must NOT consume nonces in the cache.
        A subsequent authentic order with that nonce must succeed.
        """
        allow_eval = {"decision": "ALLOW", "reason": "ZONE1_HIGH_RSEM_ALLOW"}
        order = create_containment_order(
            pep_evaluation=allow_eval,
            action_type="BLOCK_IOC",
            target_entity="198.51.100.42",
            tenant_id="tenant-alpha",
            incident_id="INC-2026-1001",
            decision_citation="LEDGER_010",
            secret_key=self.SECRET_KEY,
            current_time=1700000000.0,
        )

        executor = OrderExecutor(secret_key=self.SECRET_KEY)

        # Adversary attempts nonce pre-poisoning with forged signature
        spoofed_order = dict(order)
        spoofed_order["signature"] = "0000000000000000000000000000000000000000000000000000000000000000"

        with pytest.raises(OrderValidationError, match="Cryptographic signature verification failed"):
            executor.execute_order(spoofed_order, current_time=1700000010.0)

        # The nonce must not be in seen_nonces
        assert order["nonce"] not in executor.seen_nonces

        # Legitimate order with the authentic signature arrives and executes
        receipt = executor.execute_order(order, current_time=1700000012.0)
        assert receipt["status"] == "EXECUTED"
        assert order["nonce"] in executor.seen_nonces

    def test_actuation_valid_order_execution_receipt(self):
        """A valid containment order generates a deterministic execution receipt."""
        allow_eval = {"decision": "ALLOW", "reason": "ZONE1_HIGH_RSEM_ALLOW"}
        order = create_containment_order(
            pep_evaluation=allow_eval,
            action_type="REVOKE_ACTIVE_SESSIONS",
            target_entity="compromised.user@enterprise.com",
            tenant_id="tenant-acme",
            incident_id="INC-2026-4401",
            decision_citation="LEDGER_010",
            secret_key=self.SECRET_KEY,
            current_time=1700000000.0,
        )

        executor = OrderExecutor(secret_key=self.SECRET_KEY)
        receipt = executor.execute_order(order, current_time=1700000005.0)

        assert receipt["status"] == "EXECUTED"
        assert receipt["order_id"] == order["order_id"]
        assert receipt["action_type"] == "REVOKE_ACTIVE_SESSIONS"
        assert receipt["target_entity"] == "compromised.user@enterprise.com"
        assert receipt["tenant_id"] == "tenant-acme"
        assert receipt["incident_id"] == "INC-2026-4401"
        assert receipt["decision_citation"] == "LEDGER_010"
        assert receipt["executed_at"] == 1700000005.0
        assert receipt["executor_role"] == "ROLE_ORDER_EXECUTOR"

    def test_actuation_cross_tenant_tamper_rejected(self):
        """Cross-tenant tampering (modifying tenant_id) invalidates HMAC signature."""
        allow_eval = {"decision": "ALLOW", "reason": "ZONE1_HIGH_RSEM_ALLOW"}
        order = create_containment_order(
            pep_evaluation=allow_eval,
            action_type="BLOCK_IOC",
            target_entity="198.51.100.42",
            tenant_id="tenant-alpha",
            incident_id="INC-2026-1001",
            decision_citation="LEDGER_010",
            secret_key=self.SECRET_KEY,
            current_time=1700000000.0,
        )
        # Adversary attempts to redirect containment order to tenant-victim
        tampered_order = dict(order)
        tampered_order["tenant_id"] = "tenant-victim"
        executor = OrderExecutor(secret_key=self.SECRET_KEY)
        with pytest.raises(OrderValidationError, match="Cryptographic signature verification failed"):
            executor.execute_order(tampered_order, current_time=1700000005.0)

    def test_actuation_cross_incident_tamper_rejected(self):
        """Cross-incident tampering (modifying incident_id) invalidates HMAC signature."""
        allow_eval = {"decision": "ALLOW", "reason": "ZONE1_HIGH_RSEM_ALLOW"}
        order = create_containment_order(
            pep_evaluation=allow_eval,
            action_type="BLOCK_IOC",
            target_entity="198.51.100.42",
            tenant_id="tenant-alpha",
            incident_id="INC-2026-1001",
            decision_citation="LEDGER_010",
            secret_key=self.SECRET_KEY,
            current_time=1700000000.0,
        )
        tampered_order = dict(order)
        tampered_order["incident_id"] = "INC-2026-9999"
        executor = OrderExecutor(secret_key=self.SECRET_KEY)
        with pytest.raises(OrderValidationError, match="Cryptographic signature verification failed"):
            executor.execute_order(tampered_order, current_time=1700000005.0)

    def test_actuation_max_lifetime_exceeded_rejected(self):
        """Orders specifying a TTL beyond MAX_ORDER_TTL (3600s) are rejected."""
        allow_eval = {"decision": "ALLOW", "reason": "ZONE1_HIGH_RSEM_ALLOW"}
        order = create_containment_order(
            pep_evaluation=allow_eval,
            action_type="BLOCK_IOC",
            target_entity="198.51.100.42",
            tenant_id="tenant-alpha",
            incident_id="INC-2026-1001",
            decision_citation="LEDGER_010",
            secret_key=self.SECRET_KEY,
            ttl_seconds=7200,  # 2 hours > 1 hour ceiling
            current_time=1700000000.0,
        )
        executor = OrderExecutor(secret_key=self.SECRET_KEY, max_order_ttl=3600.0)
        with pytest.raises(OrderValidationError, match="exceeds maximum allowed ceiling of 3600"):
            executor.execute_order(order, current_time=1700000005.0)

    def test_actuation_negative_lifetime_rejected(self):
        """Orders where expires_at < issued_at are rejected as malformed."""
        allow_eval = {"decision": "ALLOW", "reason": "ZONE1_HIGH_RSEM_ALLOW"}
        order = create_containment_order(
            pep_evaluation=allow_eval,
            action_type="BLOCK_IOC",
            target_entity="198.51.100.42",
            tenant_id="tenant-alpha",
            incident_id="INC-2026-1001",
            decision_citation="LEDGER_010",
            secret_key=self.SECRET_KEY,
            current_time=1700000000.0,
        )
        malformed_order = dict(order)
        malformed_order["expires_at"] = 1699999990.0  # Before issued_at
        # Re-sign to isolate the lifetime check
        from src.ledger.chain import canonicalize_json
        import hmac, hashlib
        req_fields = ("order_id", "nonce", "tenant_id", "incident_id", "action_type",
                      "target_entity", "decision_citation", "pep_decision", "pep_reason",
                      "issued_at", "expires_at", "issuer_role")
        payload = {k: malformed_order[k] for k in req_fields}
        malformed_order["signature"] = hmac.new(
            self.SECRET_KEY.encode("utf-8"), canonicalize_json(payload), hashlib.sha256
        ).hexdigest()

        executor = OrderExecutor(secret_key=self.SECRET_KEY)
        with pytest.raises(OrderValidationError, match="expires_at .* is earlier than issued_at"):
            executor.execute_order(malformed_order, current_time=1700000000.0)

    def test_actuation_non_allow_decision_rejected(self):
        """OrderExecutor strictly rejects orders if pep_decision is not ALLOW (kills R3-OE-1)."""
        eval_escalate = {"decision": "ESCALATE", "reason": "HARD_AUTONOMY_CEILING_EXCEEDED"}
        with pytest.raises(ActuationAuthorizationError, match="required 'ALLOW'"):
            create_containment_order(
                pep_evaluation=eval_escalate,
                action_type="BLOCK_IOC",
                target_entity="198.51.100.42",
                tenant_id="tenant-alpha",
                incident_id="INC-2026-1001",
                decision_citation="LEDGER_010",
                secret_key=self.SECRET_KEY,
            )

        # Directly test OrderExecutor validation if an adversary crafts a signed payload with decision != ALLOW
        allow_eval = {"decision": "ALLOW", "reason": "ZONE1_HIGH_RSEM_ALLOW"}
        order = create_containment_order(
            pep_evaluation=allow_eval,
            action_type="BLOCK_IOC",
            target_entity="198.51.100.42",
            tenant_id="tenant-alpha",
            incident_id="INC-2026-1001",
            decision_citation="LEDGER_010",
            secret_key=self.SECRET_KEY,
            current_time=1700000000.0,
        )
        tampered_order = dict(order)
        tampered_order["pep_decision"] = "DENY"
        from src.ledger.chain import canonicalize_json
        import hmac, hashlib
        req_fields = ("order_id", "nonce", "tenant_id", "incident_id", "action_type",
                      "target_entity", "decision_citation", "pep_decision", "pep_reason",
                      "issued_at", "expires_at", "issuer_role")
        payload = {k: tampered_order[k] for k in req_fields}
        tampered_order["signature"] = hmac.new(
            self.SECRET_KEY.encode("utf-8"), canonicalize_json(payload), hashlib.sha256
        ).hexdigest()

        executor = OrderExecutor(secret_key=self.SECRET_KEY)
        with pytest.raises(OrderValidationError, match="PEP decision is 'DENY', expected 'ALLOW'"):
            executor.execute_order(tampered_order, current_time=1700000005.0)

    def test_actuation_executor_non_rem_role_rejected(self):
        """OrderExecutor rejects orders if issuer_role is not ROLE_REM_EXECUTOR (kills R3-OE-2)."""
        allow_eval = {"decision": "ALLOW", "reason": "ZONE1_HIGH_RSEM_ALLOW"}
        order = create_containment_order(
            pep_evaluation=allow_eval,
            action_type="BLOCK_IOC",
            target_entity="198.51.100.42",
            tenant_id="tenant-alpha",
            incident_id="INC-2026-1001",
            decision_citation="LEDGER_010",
            secret_key=self.SECRET_KEY,
            current_time=1700000000.0,
        )
        tampered_order = dict(order)
        tampered_order["issuer_role"] = "ROLE_PLANNER"
        from src.ledger.chain import canonicalize_json
        import hmac, hashlib
        req_fields = ("order_id", "nonce", "tenant_id", "incident_id", "action_type",
                      "target_entity", "decision_citation", "pep_decision", "pep_reason",
                      "issued_at", "expires_at", "issuer_role")
        payload = {k: tampered_order[k] for k in req_fields}
        tampered_order["signature"] = hmac.new(
            self.SECRET_KEY.encode("utf-8"), canonicalize_json(payload), hashlib.sha256
        ).hexdigest()

        executor = OrderExecutor(secret_key=self.SECRET_KEY)
        with pytest.raises(OrderValidationError, match="Unauthorized issuer role: 'ROLE_PLANNER'"):
            executor.execute_order(tampered_order, current_time=1700000005.0)

    def test_actuation_malformed_decision_citation_rejected(self):
        """OrderExecutor rejects orders with invalid decision citation pattern (kills R3-OE-3)."""
        allow_eval = {"decision": "ALLOW", "reason": "ZONE1_HIGH_RSEM_ALLOW"}
        order = create_containment_order(
            pep_evaluation=allow_eval,
            action_type="BLOCK_IOC",
            target_entity="198.51.100.42",
            tenant_id="tenant-alpha",
            incident_id="INC-2026-1001",
            decision_citation="LEDGER_010",
            secret_key=self.SECRET_KEY,
            current_time=1700000000.0,
        )
        tampered_order = dict(order)
        tampered_order["decision_citation"] = "INVALID_CITATION"
        from src.ledger.chain import canonicalize_json
        import hmac, hashlib
        req_fields = ("order_id", "nonce", "tenant_id", "incident_id", "action_type",
                      "target_entity", "decision_citation", "pep_decision", "pep_reason",
                      "issued_at", "expires_at", "issuer_role")
        payload = {k: tampered_order[k] for k in req_fields}
        tampered_order["signature"] = hmac.new(
            self.SECRET_KEY.encode("utf-8"), canonicalize_json(payload), hashlib.sha256
        ).hexdigest()

        executor = OrderExecutor(secret_key=self.SECRET_KEY)
        with pytest.raises(OrderValidationError, match="Invalid decision citation"):
            executor.execute_order(tampered_order, current_time=1700000005.0)

    def test_actuation_concurrent_barrier_race_prevented(self):
        """Proves that threading.Lock prevents concurrent double execution of the same order nonce."""
        allow_eval = {"decision": "ALLOW", "reason": "ZONE1_HIGH_RSEM_ALLOW"}
        order = create_containment_order(
            pep_evaluation=allow_eval,
            action_type="BLOCK_IOC",
            target_entity="198.51.100.42",
            tenant_id="tenant-alpha",
            incident_id="INC-2026-1001",
            decision_citation="LEDGER_010",
            secret_key=self.SECRET_KEY,
            current_time=1700000000.0,
        )

        executor = OrderExecutor(secret_key=self.SECRET_KEY)
        results = []
        barrier = threading.Barrier(5)

        def worker():
            barrier.wait()
            try:
                receipt = executor.execute_order(order, current_time=1700000005.0)
                results.append(("SUCCESS", receipt))
            except OrderValidationError as e:
                results.append(("REPLAY", str(e)))

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        successes = [r for r in results if r[0] == "SUCCESS"]
        replays = [r for r in results if r[0] == "REPLAY"]
        assert len(successes) == 1, f"Expected exactly 1 success, got {len(successes)}"
        assert len(replays) == 4, f"Expected 4 replay rejections, got {len(replays)}"

    def test_actuation_ttl_eviction_sweeps_expired_nonces(self):
        """Proves that OrderExecutor automatically evicts expired nonces, preventing memory leaks."""
        executor = OrderExecutor(secret_key=self.SECRET_KEY, clock_skew_seconds=10.0)
        # Populate nonces expiring at t=1000 and t=2000
        executor.seen_nonces["nonce-1"] = 1000.0
        executor.seen_nonces["nonce-2"] = 2000.0

        # At t=1050, nonce-1 expiry (1000) is < 1050 - 10 = 1040, so it must be evicted
        executor._evict_expired_nonces(now=1050.0)
        assert "nonce-1" not in executor.seen_nonces
        assert "nonce-2" in executor.seen_nonces

    def test_actuation_non_dict_pep_evaluation_rejected(self):
        """PEP evaluation of non-dict type raises ActuationAuthorizationError."""
        with pytest.raises(ActuationAuthorizationError, match="PEP evaluation must be a dictionary"):
            create_containment_order(
                pep_evaluation="not-a-dict",
                action_type="BLOCK_IOC",
                target_entity="198.51.100.1",
                tenant_id="tenant-alpha",
                incident_id="INC-1001",
                decision_citation="LEDGER_010",
                secret_key=self.SECRET_KEY,
            )

    def test_actuation_missing_required_field_rejected(self):
        """Order missing required field raises OrderValidationError."""
        order = create_containment_order(
            pep_evaluation={"decision": "ALLOW", "reason": "TEST_REASON"},
            action_type="ISOLATE_HOST",
            target_entity="198.51.100.42",
            tenant_id="tenant-alpha",
            incident_id="INC-2026-1001",
            decision_citation="LEDGER_010",
            secret_key=self.SECRET_KEY,
            current_time=1700000000.0,
        )
        del order["signature"]
        executor = OrderExecutor(secret_key=self.SECRET_KEY)
        with pytest.raises(OrderValidationError, match="Missing required order field: 'signature'"):
            executor.execute_order(order)


# ==============================================================================
# INVARIANT #2: THE COGNITIVE ANTI-ANCHORING INVARIANT (src/policy/anti_anchoring.py)
# ==============================================================================

class TestInvariant2AntiAnchoring:
    """Verifies complete eradication of prior statistical scores and non-evidentiary heuristics."""

    def _make_base_handoff(self) -> Dict[str, Any]:
        return {
            "incident_id": "INC-2026-9901",
            "tenant_id": "tenant-corp",
            "ingress_vector": "VECTOR_EXTERNAL_EMAIL",
            "query_perimeter": "enterprise-boundary",
            "observables": [
                {"type": "ip", "value": "198.51.100.7"},
                {"type": "domain", "value": "suspicious-phish.net"},
            ],
            "initial_triage": {
                "non_evidentiary_for_agents": True,
                "s_score": 0.88,
                "theta_high": 0.85,
                "theta_low": 0.35,
                "aip_score": 0.92,
            },
        }

    def test_anti_anchoring_deep_nested_smuggling_rejected(self):
        """Smuggling forbidden triage keys at arbitrary nesting depths raises CognitiveAnchoringLeakError."""
        for forbidden_key in ("s_score", "theta_high", "theta_low", "aip_score"):
            # Depth 2: observables -> extra dict
            handoff = self._make_base_handoff()
            handoff["observables"][0]["metadata"] = {forbidden_key: 0.95}
            with pytest.raises(CognitiveAnchoringLeakError, match=f"Forbidden triage metric '{forbidden_key}'"):
                agent_view(handoff)

            # Depth 4: observables -> metadata -> sublist -> dict
            handoff_deep = self._make_base_handoff()
            handoff_deep["observables"][1]["meta"] = {"nested": [{"hidden": {forbidden_key: 0.77}}]}
            with pytest.raises(CognitiveAnchoringLeakError, match=f"Forbidden triage metric '{forbidden_key}'"):
                agent_view(handoff_deep)

    def test_anti_anchoring_mutation_isolation(self):
        """Mutating the dictionary returned by agent_view does not mutate the source handoff."""
        handoff = self._make_base_handoff()
        view = agent_view(handoff)

        # Mutate the projected view
        view["observables"].append({"type": "hash", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"})
        view["observables"][0]["value"] = "MUTATED_VALUE"

        # Assert original handoff is completely unchanged
        assert len(handoff["observables"]) == 2
        assert handoff["observables"][0]["value"] == "198.51.100.7"

    def test_anti_anchoring_missing_non_evidentiary_precondition_fails_closed(self):
        """Handoff missing non_evidentiary_for_agents: true fails closed immediately."""
        handoff_missing = self._make_base_handoff()
        del handoff_missing["initial_triage"]["non_evidentiary_for_agents"]
        with pytest.raises(ValueError, match="non_evidentiary_for_agents.*True"):
            agent_view(handoff_missing)

        handoff_false = self._make_base_handoff()
        handoff_false["initial_triage"]["non_evidentiary_for_agents"] = False
        with pytest.raises(ValueError, match="non_evidentiary_for_agents.*True"):
            agent_view(handoff_false)

    @given(
        forbidden_key=st.sampled_from(["s_score", "theta_high", "theta_low", "aip_score"]),
        leak_value=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
        noise_key=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=2, max_size=8),
    )
    @settings(max_examples=40, deadline=None)
    def test_anti_anchoring_hypothesis_property_nested_leak_detection(
        self, forbidden_key: str, leak_value: float, noise_key: str
    ):
        """Hypothesis property test: 100% detection rate when forbidden keys are smuggled into payload."""
        handoff = self._make_base_handoff()
        # Smuggle into an arbitrary nested structure
        handoff["observables"].append({
            noise_key: {"container": [{forbidden_key: leak_value}]}
        })
        with pytest.raises(CognitiveAnchoringLeakError, match=f"Forbidden triage metric '{forbidden_key}'"):
            agent_view(handoff)


# ==============================================================================
# INVARIANT #3: SINGLE SOURCE OF TRUTH / CRYPTOGRAPHIC LEDGER (src/ledger/chain.py)
# ==============================================================================

class TestInvariant3LedgerTamperResistance:
    """Verifies append-only hash linking, HMAC commitments, and fail-closed ledger integrity."""

    def test_ledger_retroactive_insertion_rejected(self, fixture_4401):
        """Inserting an unauthorized block in the middle of a verified chain breaks linkage."""
        chain = copy.deepcopy(fixture_4401)
        valid, _ = verify_chain(chain, expected_head=GOLDEN_HEAD_INC_2026_4401)
        assert valid is True

        # Construct a rogue block inserted between LEDGER_004 and LEDGER_005
        rogue_block = copy.deepcopy(chain[4])
        rogue_block["entry_id"] = "LEDGER_004_ROGUE"
        rogue_block["payload"]["finding_title"] = "Fabricated finding"

        tampered_chain = chain[:5] + [rogue_block] + chain[5:]
        valid_tampered, msg = verify_chain(tampered_chain)
        assert valid_tampered is False
        assert "invalid ID format" in msg or "Monotonic sequence violation" in msg or "Broken hash link" in msg

    def test_ledger_sequence_id_gap_or_swap_rejected(self, fixture_8820):
        """Sequence ID gaps or swapped entries break cryptographic validation."""
        chain = copy.deepcopy(fixture_8820)
        valid, _ = verify_chain(chain, expected_head=GOLDEN_HEAD_INC_2026_8820)
        assert valid is True

        # Sequence gap: drop block 5 (LEDGER_005)
        chain_gap = chain[:5] + chain[6:]
        valid_gap, msg_gap = verify_chain(chain_gap)
        assert valid_gap is False
        assert "Monotonic sequence violation" in msg_gap or "Broken hash link" in msg_gap

        # Monotonic swap: swap block 5 and 6
        chain_swapped = copy.deepcopy(chain)
        chain_swapped[5], chain_swapped[6] = chain_swapped[6], chain_swapped[5]
        valid_swapped, msg_swapped = verify_chain(chain_swapped)
        assert valid_swapped is False
        assert "Monotonic sequence violation" in msg_swapped or "Broken hash link" in msg_swapped

    def test_ledger_cross_tenant_block_splicing_rejected(self, fixture_4401, fixture_8820):
        """Splicing a block from one tenant's chain into another breaks cryptographic verification."""
        chain_4401 = copy.deepcopy(fixture_4401)
        block_8820 = copy.deepcopy(fixture_8820[4])

        # Replace block 4 in 4401 with block 4 from 8820
        chain_4401[4] = block_8820
        valid, msg = verify_chain(chain_4401)
        assert valid is False
        assert "Broken hash link" in msg or "Tampered payload" in msg or "Tampered entry" in msg

    def test_ledger_missing_external_salt_fails_closed(self, fixture_4401):
        """When in external key_store mode, missing salts fail closed."""
        chain = copy.deepcopy(fixture_4401)
        key_store: Dict[str, str] = {}

        # Strip salts into external key_store
        stripped_chain = []
        for entry in chain:
            e_copy = copy.deepcopy(entry)
            key_store[e_copy["entry_id"]] = e_copy.pop("per_entry_salt")
            stripped_chain.append(e_copy)

        # Baseline external verification passes
        valid, _ = verify_chain(stripped_chain, key_store=key_store, expected_head=GOLDEN_HEAD_INC_2026_4401)
        assert valid is True

        # Delete salt for LEDGER_006
        del key_store["LEDGER_006"]
        valid_missing, msg = verify_chain(stripped_chain, key_store=key_store)
        assert valid_missing is False
        assert "missing from external key_store" in msg

    def test_ledger_genesis_block_tampering_rejected(self, fixture_4401):
        """Modifying the genesis block invalidates the entire downstream chain."""
        chain = copy.deepcopy(fixture_4401)
        chain[0]["payload"]["investigation_id"] = "inv-malicious-override"
        valid, msg = verify_chain(chain)
        assert valid is False
        assert "Tampered payload detected at LEDGER_000" in msg

    def test_ledger_tip_truncation_detection_against_pinned_head(self, fixture_8820):
        """Tip truncation is caught when verifying against the WORM pinned head."""
        chain = copy.deepcopy(fixture_8820)
        truncated_chain = chain[:-2]

        valid, msg = verify_chain(truncated_chain, expected_head=GOLDEN_HEAD_INC_2026_8820)
        assert valid is False
        assert "Tip truncation or head mismatch" in msg


# ==============================================================================
# INVARIANT #4: HARD AUTONOMY CEILING & DETERMINISTIC SEVERITY
# ==============================================================================

class TestInvariant4AutonomyCeilingAndSeverity:
    """Verifies unconditional enforcement of CA >= 4 ceiling and raise-only severity."""

    @given(
        rsem_score=st.floats(min_value=0.0, max_value=100.0, allow_nan=False, allow_infinity=False),
        oob_status=st.sampled_from(list(OOBStatus)),
        action_type=st.sampled_from(["ISOLATE_HOST", "DISABLE_ACCOUNT", "REVOKE_ACTIVE_SESSIONS"]),
    )
    @settings(max_examples=50, deadline=None)
    def test_autonomy_ceiling_hypothesis_property(
        self, rsem_score: float, oob_status: OOBStatus, action_type: str
    ):
        """
        Property test across continuous RSEM: actions with CA >= 4 strictly escalate.
        Decorated with deadline=None to prevent subprocess timeout flakes.
        """
        # Select an asset tier where CA >= 4
        # ISOLATE_HOST on Tier 1 (CA=9)
        # DISABLE_ACCOUNT on Tier 2 (CA=6)
        # REVOKE_ACTIVE_SESSIONS on Tier 0 (CA=4)
        tier_map = {
            "ISOLATE_HOST": "Tier 1",
            "DISABLE_ACCOUNT": "Tier 2",
            "REVOKE_ACTIVE_SESSIONS": "Tier 0",
        }
        asset_tier = tier_map[action_type]
        c_a = TABLE_21_CA_CATALOG[action_type][asset_tier]
        assert c_a >= 4

        # 1. Python RSEM gate verification
        zone, decision, reason = classify_decision_zone(
            rsem_score=rsem_score,
            c_a=c_a,
            is_identity_action=(action_type in {"REVOKE_ACTIVE_SESSIONS", "DISABLE_ACCOUNT"}),
            oob_status=oob_status,
        )
        assert zone == "ZONE_CEILING"
        assert decision == "ESCALATE"
        assert reason == "HARD_AUTONOMY_CEILING_EXCEEDED"

        # 2. OPA Policy Gatekeeper verification
        pep_result = pep_evaluate(action_type, asset_tier, rsem_score, oob_status=oob_status)
        assert pep_result["decision"] == "ESCALATE"
        assert pep_result["reason"] == "HARD_AUTONOMY_CEILING_EXCEEDED"

    def test_autonomy_ceiling_parameter_injection_disregarded(self):
        """
        Adversary supplies cost_of_action: 1 and override_ceiling: true directly to OPA.
        The Rego policy must ignore client parameters and evaluate strictly against internal catalog.
        Tests both integer and string tier representations for actions with catalog C_A >= 4.
        """
        opa_bin = find_opa_binary()
        if not opa_bin:
            pytest.skip("OPA binary not found on local path.")

        rego_path = Path(__file__).resolve().parent.parent / "policies" / "soc_containment.rego"

        # Test cases where catalog C_A >= 4:
        # 1. DISABLE_ACCOUNT on Tier 2 (Table 21 has C_A = 4)
        # 2. ISOLATE_HOST on Tier 1 (Table 21 has C_A = 9)
        test_payloads = [
            {"action_type": "DISABLE_ACCOUNT", "asset_tier": 2, "rsem": 88.5, "cost_of_action": 1},
            {"action_type": "DISABLE_ACCOUNT", "asset_tier": "Tier 2", "rsem": 88.5, "cost_of_action": 1},
            {"action_type": "ISOLATE_HOST", "asset_tier": 1, "rsem": 95.0, "cost_of_action": 1},
            {"action_type": "ISOLATE_HOST", "asset_tier": "Tier 1", "rsem": 95.0, "cost_of_action": 1},
        ]

        for payload in test_payloads:
            full_input = dict(payload)
            full_input.update({
                "is_identity_action": False,
                "override_ceiling": True,
                "oob_status": "CONFIRMED_LEGITIMATE",
            })

            cmd = [
                opa_bin,
                "eval",
                "-d",
                str(rego_path),
                "--stdin-input",
                "data.soc.containment.result",
            ]

            proc = subprocess.run(
                cmd,
                input=json.dumps(full_input),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )

            res_json = json.loads(proc.stdout)
            result = res_json["result"][0]["expressions"][0]["value"]

            # Must ignore cost_of_action: 1 and strictly escalate via catalog C_A >= 4
            assert result["decision"] == "ESCALATE", (
                f"Failed for {payload['action_type']} on {payload['asset_tier']}: got {result}"
            )
            assert result["reason"] == "HARD_AUTONOMY_CEILING_EXCEEDED"

    def test_severity_downgrade_rejected(self):
        """
        Severity can never be lowered below baseline (Equation 16: CI = max(CI_base, CI(finding_class))).
        Preserves Day 3 raise-only signature and contract.
        """
        # Baseline 9 (e.g. Lateral movement Tier 1). Propose finding class with score 7.
        base_ci = 9
        proposed_class = "FND_C2_ESTABLISHED"  # Table 13 score: 7
        assert TABLE_13_FINDING_CLASS_SEVERITY[proposed_class] == 7

        result = severity(base=base_ci, finding_class=proposed_class)
        # Severity remains max(9, 7) = 9
        assert result == 9

        # Propose baseline out of bounds
        with pytest.raises(ValueError, match="Baseline severity base must be in range"):
            severity(base=0)

        with pytest.raises(ValueError, match="Baseline severity base must be in range"):
            severity(base=11)

    def test_severity_raise_without_citation_rejected(self):
        """Raising severity without an explicit ledger citation raises ValueError."""
        # Baseline 5 (Phishing Tier 3). Propose FND_TOKEN_MINT (score 8).
        with pytest.raises(ValueError, match="requires an explicit citation"):
            severity(base=5, finding_class="FND_TOKEN_MINT", citation=None)

        with pytest.raises(ValueError, match="requires an explicit citation"):
            severity(base=5, finding_class="FND_TOKEN_MINT", citation="")

    def test_severity_raise_non_fnd_citation_rejected(self, fixture_4401):
        """Raising severity with a citation pointing to a non-finding block raises ValueError."""
        # Citation LEDGER_001 is a checklist entry (CHK_001) signed by ROLE_PLANNER
        with pytest.raises(ValueError, match="signed by unauthorized role 'ROLE_PLANNER'"):
            severity(base=5, finding_class="FND_TOKEN_MINT", citation="LEDGER_001", ledger=fixture_4401)

        # Citation LEDGER_002 has finding_class 'FND_ACCOUNT_COMPROMISE', mismatching requested 'FND_TOKEN_MINT'
        with pytest.raises(ValueError, match="does not match cited finding 'FND_TOKEN_MINT'"):
            severity(base=5, finding_class="FND_TOKEN_MINT", citation="LEDGER_002", ledger=fixture_4401)

    def test_severity_raise_wrong_role_rejected(self, fixture_4401):
        """Raising severity with an FND block created by an unauthorized role raises ValueError."""
        chain = copy.deepcopy(fixture_4401)
        # Block 8 (LEDGER_008) is FND_TOKEN_MINT created by ROLE_INV_EXECUTOR.
        # Alter its agent_role to ROLE_PLANNER.
        chain[8]["agent_role"] = "ROLE_PLANNER"
        with pytest.raises(ValueError, match="signed by unauthorized role 'ROLE_PLANNER'"):
            severity(base=5, finding_class="FND_TOKEN_MINT", citation="LEDGER_008", ledger=chain)

    def test_severity_raise_unknown_finding_class_rejected(self):
        """Proposing an unknown finding class raises ValueError."""
        with pytest.raises(ValueError, match="Unknown finding class 'HALLUCINATED_THREAT'"):
            severity(base=5, finding_class="HALLUCINATED_THREAT", citation="LEDGER_002")


# ==============================================================================
# INVARIANT #5: PRE-RELEASE SAFETY GATE & FOUR-EYES DUAL CONTROL
# ==============================================================================

class TestInvariant5PreReleaseSafety:
    """Verifies that Tier 0/1 critical assets require dual human approval and cannot auto-close."""

    def test_phase1_autoclose_barred_on_tier0_and_tier1(self):
        """Tier 0 and Tier 1 critical assets can never auto-close during initial triage."""
        for tier in ("Tier 0", "Tier 1", 0, 1, "Crown Jewel", "Prod"):
            res = evaluate_phase1_autoclose(asset_tier=tier, s_score=0.01, theta_low=0.35)
            assert res["status"] == "REJECTED"
            assert res["action"] == "ROUTE_TO_DELIBERATIVE_INVESTIGATION"
            assert res["reason"] == "CRITICAL_ASSET_AUTO_CLOSE_BARRED"

    def test_phase1_autoclose_permitted_on_tier2_and_tier3(self):
        """Tier 2 and Tier 3 non-critical assets can auto-close when s(X) < theta_low."""
        for tier in ("Tier 2", "Tier 3", 2, 3):
            # Below threshold -> auto-close permitted
            res_below = evaluate_phase1_autoclose(asset_tier=tier, s_score=0.20, theta_low=0.35)
            assert res_below["status"] == "APPROVED"
            assert res_below["action"] == "AUTO_CLOSE_PERMITTED"

            # Above threshold -> route to investigation
            res_above = evaluate_phase1_autoclose(asset_tier=tier, s_score=0.55, theta_low=0.35)
            assert res_above["status"] == "REJECTED"
            assert res_above["action"] == "ROUTE_TO_DELIBERATIVE_INVESTIGATION"
            assert res_above["reason"] == "SCORE_EXCEEDS_THETA_LOW"

    def test_hold_release_unknown_action_rejected(self):
        """Unrecognized release actions raise ValueError."""
        with pytest.raises(ValueError, match="Unknown release action"):
            evaluate_hold_release(
                action_type="UNAUTHORIZED_DISMISSAL",
                asset_tier="Tier 1",
                approvers=[],
                request_time=1000.0,
                current_time=1050.0,
            )

    def test_hold_release_autonomous_agent_rejected(self):
        """Autonomous reasoning agents (ROLE_*) cannot authorize hold releases."""
        agent_approver = {"user_id": "agent-planner", "signing_key": "k1", "role": "ROLE_PLANNER"}
        with pytest.raises(SecurityViolationError, match="Autonomous agent with role 'ROLE_PLANNER'"):
            evaluate_hold_release(
                action_type="RELEASE_SAFE_CLOSE_HOLD",
                asset_tier="Tier 1",
                approvers=[agent_approver],
                request_time=1000.0,
                current_time=1050.0,
            )

    def test_hold_release_zero_approvers_before_and_after_timeout(self):
        """Zero approvers returns pending before T_4eyes and escalates to SOC Manager after T_4eyes."""
        # 1. Before timeout (elapsed = 300s < 900s)
        res_pending = evaluate_hold_release(
            action_type="RELEASE_SAFE_CLOSE_HOLD",
            asset_tier="Tier 1",
            approvers=[],
            request_time=1000.0,
            current_time=1300.0,
            t_4eyes_timeout=900.0,
        )
        assert res_pending["status"] == "PENDING_APPROVAL"
        assert res_pending["escalated"] is False

        # 2. At or after timeout (elapsed = 950s >= 900s)
        res_timeout = evaluate_hold_release(
            action_type="RELEASE_SAFE_CLOSE_HOLD",
            asset_tier="Tier 1",
            approvers=[],
            request_time=1000.0,
            current_time=1950.0,
            t_4eyes_timeout=900.0,
        )
        assert res_timeout["status"] == "ESCALATED_TO_SOC_MANAGER"
        assert res_timeout["escalated"] is True

    def test_hold_release_tier0_tier1_requires_four_eyes(self):
        """Tier 0/1 release with one approver waits for second approver before timeout."""
        approver1 = {"user_id": "analyst-alice", "signing_key": "alice-pubkey-ed25519"}
        res = evaluate_hold_release(
            action_type="APPROVE_MANUAL_HOST_ISOLATION",
            asset_tier="Tier 0",
            approvers=[approver1],
            request_time=1000.0,
            current_time=1400.0,
            t_4eyes_timeout=900.0,
        )
        assert res["status"] == "PENDING_SECOND_APPROVER"
        assert res["escalated"] is False

    def test_hold_release_tier0_tier1_duplicate_approver_rejected(self):
        """Using the same human analyst identity or signing key twice raises ValueError."""
        approver1 = {"user_id": "analyst-alice", "signing_key": "alice-key-1"}
        approver2_same_id = {"user_id": "analyst-alice", "signing_key": "alice-key-2"}

        with pytest.raises(ValueError, match="distinct user_id and signing_key"):
            evaluate_hold_release(
                action_type="OVERRIDE_TO_BENIGN",
                asset_tier="Tier 1",
                approvers=[approver1, approver2_same_id],
                request_time=1000.0,
                current_time=1200.0,
            )

        approver3_same_key = {"user_id": "analyst-charlie", "signing_key": "alice-key-1"}
        with pytest.raises(ValueError, match="distinct user_id and signing_key"):
            evaluate_hold_release(
                action_type="OVERRIDE_TO_BENIGN",
                asset_tier="Tier 1",
                approvers=[approver1, approver3_same_key],
                request_time=1000.0,
                current_time=1200.0,
            )

    def test_hold_release_tier0_tier1_timeout_escalates_to_soc_manager(self):
        """
        When T_4eyes expires with only one approver, it escalates to the SOC Manager.
        It never degrades to single-analyst approval.
        """
        approver1 = {"user_id": "analyst-alice", "signing_key": "alice-key-1"}
        res = evaluate_hold_release(
            action_type="APPROVE_DISABLE_ACCOUNT",
            asset_tier="Tier 1",
            approvers=[approver1],
            request_time=1000.0,
            current_time=2000.0,  # 1000s elapsed > 900s
            t_4eyes_timeout=900.0,
        )
        assert res["status"] == "ESCALATED_TO_SOC_MANAGER"
        assert res["reason"] == "FOUR_EYES_TIMEOUT_ESCALATION"
        assert res["escalated"] is True

    def test_hold_release_approve_tier0_revoke_unconditionally_requires_four_eyes(self):
        """APPROVE_TIER0_REVOKE strictly requires Four-Eyes across all asset tiers."""
        approver1 = {"user_id": "analyst-alice", "signing_key": "alice-key-1"}
        approver2 = {"user_id": "analyst-bob", "signing_key": "bob-key-2"}

        # Even on Tier 3, APPROVE_TIER0_REVOKE requires two approvers
        res_single = evaluate_hold_release(
            action_type="APPROVE_TIER0_REVOKE",
            asset_tier="Tier 3",
            approvers=[approver1],
            request_time=1000.0,
            current_time=1200.0,
        )
        assert res_single["status"] == "PENDING_SECOND_APPROVER"

        res_dual = evaluate_hold_release(
            action_type="APPROVE_TIER0_REVOKE",
            asset_tier="Tier 3",
            approvers=[approver1, approver2],
            request_time=1000.0,
            current_time=1200.0,
        )
        assert res_dual["status"] == "APPROVED"
        assert res_dual["reason"] == "FOUR_EYES_DUAL_CONTROL_SATISFIED"

    def test_hold_release_tier2_tier3_single_approver_satisfied(self):
        """Tier 2 and Tier 3 non-revoke actions require only a single human expert approval."""
        approver1 = {"user_id": "analyst-alice", "signing_key": "alice-key-1"}
        res = evaluate_hold_release(
            action_type="RELEASE_SAFE_CLOSE_HOLD",
            asset_tier="Tier 2",
            approvers=[approver1],
            request_time=1000.0,
            current_time=1100.0,
        )
        assert res["status"] == "APPROVED"
        assert res["reason"] == "SINGLE_EXPERT_APPROVAL_SATISFIED"

    def test_hold_release_non_critical_zero_approvers_timeout_escalation(self):
        """
        Kills mutant R3-RG-11:
        On Tier 2 or Tier 3, when len(approvers) == 0 and timeout has elapsed,
        the request must escalate to SOC Manager (status: ESCALATED_TO_SOC_MANAGER).
        """
        res = evaluate_hold_release(
            action_type="RELEASE_SAFE_CLOSE_HOLD",
            asset_tier="Tier 2",
            approvers=[],
            request_time=1000.0,
            current_time=1950.0,  # 950s elapsed >= 900s
            t_4eyes_timeout=900.0,
        )
        assert res["status"] == "ESCALATED_TO_SOC_MANAGER"
        assert res["reason"] == "APPROVAL_TIMEOUT_ESCALATION"
        assert res["escalated"] is True

        res_tier3 = evaluate_hold_release(
            action_type="RELEASE_SAFE_CLOSE_HOLD",
            asset_tier="Tier 3",
            approvers=[],
            request_time=1000.0,
            current_time=2000.0,
            t_4eyes_timeout=900.0,
        )
        assert res_tier3["status"] == "ESCALATED_TO_SOC_MANAGER"
        assert res_tier3["reason"] == "APPROVAL_TIMEOUT_ESCALATION"

    def test_hold_release_cryptographic_signature_verification_success(self):
        """
        Verifies that approvers with valid HMAC signatures over canonical request bytes
        are accepted under require_signatures=True.
        """
        clear_seen_approval_nonces()
        from src.policy.release_gate import DEFAULT_APPROVER_REGISTRY

        alice = DEFAULT_APPROVER_REGISTRY["analyst-alice"]
        bob = DEFAULT_APPROVER_REGISTRY["analyst-bob"]

        token_alice = create_approval_signature(
            approver=alice,
            action_type="APPROVE_MANUAL_HOST_ISOLATION",
            asset_tier="Tier 0",
            incident_id="INC-2026-4401",
            tenant_id="tenant-acme",
            nonce="nonce-alice-001",
            issued_at=1000.0,
            expires_at=1300.0,
        )
        token_bob = create_approval_signature(
            approver=bob,
            action_type="APPROVE_MANUAL_HOST_ISOLATION",
            asset_tier="Tier 0",
            incident_id="INC-2026-4401",
            tenant_id="tenant-acme",
            nonce="nonce-bob-002",
            issued_at=1000.0,
            expires_at=1300.0,
        )

        res = evaluate_hold_release(
            action_type="APPROVE_MANUAL_HOST_ISOLATION",
            asset_tier="Tier 0",
            approvers=[token_alice, token_bob],
            request_time=1000.0,
            current_time=1050.0,
            incident_id="INC-2026-4401",
            tenant_id="tenant-acme",
            require_signatures=True,
        )
        assert res["status"] == "APPROVED"
        assert res["reason"] == "FOUR_EYES_DUAL_CONTROL_SATISFIED"

    def test_hold_release_cryptographic_signature_tamper_rejected(self):
        """Tampering with signature payload or action bytes causes signature rejection."""
        clear_seen_approval_nonces()
        from src.policy.release_gate import DEFAULT_APPROVER_REGISTRY

        alice = DEFAULT_APPROVER_REGISTRY["analyst-alice"]
        bob = DEFAULT_APPROVER_REGISTRY["analyst-bob"]

        token_alice = create_approval_signature(
            approver=alice,
            action_type="APPROVE_MANUAL_HOST_ISOLATION",
            asset_tier="Tier 0",
            incident_id="INC-2026-4401",
            tenant_id="tenant-acme",
            nonce="nonce-alice-tamper",
            issued_at=1000.0,
            expires_at=1300.0,
        )
        token_bob = create_approval_signature(
            approver=bob,
            action_type="APPROVE_MANUAL_HOST_ISOLATION",
            asset_tier="Tier 0",
            incident_id="INC-2026-4401",
            tenant_id="tenant-acme",
            nonce="nonce-bob-tamper",
            issued_at=1000.0,
            expires_at=1300.0,
        )

        # Corrupt Alice's signature
        token_alice["signature"] = "deadbeef" * 8

        with pytest.raises(SecurityViolationError, match="Invalid cryptographic signature"):
            evaluate_hold_release(
                action_type="APPROVE_MANUAL_HOST_ISOLATION",
                asset_tier="Tier 0",
                approvers=[token_alice, token_bob],
                request_time=1000.0,
                current_time=1050.0,
                incident_id="INC-2026-4401",
                tenant_id="tenant-acme",
                require_signatures=True,
            )

    def test_hold_release_replay_nonce_rejected(self):
        """Reusing an approval nonce raises SecurityViolationError."""
        clear_seen_approval_nonces()
        from src.policy.release_gate import DEFAULT_APPROVER_REGISTRY

        alice = DEFAULT_APPROVER_REGISTRY["analyst-alice"]
        bob = DEFAULT_APPROVER_REGISTRY["analyst-bob"]

        token_alice = create_approval_signature(
            approver=alice,
            action_type="RELEASE_SAFE_CLOSE_HOLD",
            asset_tier="Tier 2",
            incident_id="INC-2026-4401",
            tenant_id="tenant-acme",
            nonce="nonce-replay-target",
            issued_at=1000.0,
            expires_at=1300.0,
        )

        # First presentation succeeds
        res = evaluate_hold_release(
            action_type="RELEASE_SAFE_CLOSE_HOLD",
            asset_tier="Tier 2",
            approvers=[token_alice],
            request_time=1000.0,
            current_time=1050.0,
            incident_id="INC-2026-4401",
            tenant_id="tenant-acme",
            require_signatures=True,
        )
        assert res["status"] == "APPROVED"

        # Second presentation with same nonce fails replay guard
        with pytest.raises(SecurityViolationError, match="Replay detected: approval nonce 'nonce-replay-target'"):
            evaluate_hold_release(
                action_type="RELEASE_SAFE_CLOSE_HOLD",
                asset_tier="Tier 2",
                approvers=[token_alice],
                request_time=1000.0,
                current_time=1060.0,
                incident_id="INC-2026-4401",
                tenant_id="tenant-acme",
                require_signatures=True,
            )

    def test_hold_release_unauthorized_role_on_critical_tier_rejected(self):
        """
        HUMAN_SOC_ANALYST cannot authorize release on Tier 0 or Tier 1 assets
        (strictly requires HUMAN_EXPERT or HUMAN_SOC_MANAGER).
        """
        from src.policy.release_gate import DEFAULT_APPROVER_REGISTRY
        dan = DEFAULT_APPROVER_REGISTRY["analyst-dan"]  # HUMAN_SOC_ANALYST
        bob = DEFAULT_APPROVER_REGISTRY["analyst-bob"]  # HUMAN_EXPERT

        approver_dan = {"user_id": dan.user_id, "signing_key": dan.signing_key, "role": dan.role}
        approver_bob = {"user_id": bob.user_id, "signing_key": bob.signing_key, "role": bob.role}

        with pytest.raises(SecurityViolationError, match="lacks authority for critical asset release"):
            evaluate_hold_release(
                action_type="APPROVE_MANUAL_HOST_ISOLATION",
                asset_tier="Tier 0",
                approvers=[approver_dan, approver_bob],
                request_time=1000.0,
                current_time=1050.0,
            )

    def test_hold_release_self_approval_rejected(self):
        """Original requester cannot approve their own release request."""
        approver1 = {"user_id": "analyst-alice", "signing_key": "alice-key-1"}
        approver2 = {"user_id": "analyst-bob", "signing_key": "bob-key-2"}

        with pytest.raises(SecurityViolationError, match="Requester 'analyst-alice' cannot approve their own release"):
            evaluate_hold_release(
                action_type="APPROVE_MANUAL_HOST_ISOLATION",
                asset_tier="Tier 0",
                approvers=[approver1, approver2],
                request_time=1000.0,
                current_time=1050.0,
                requester_id="analyst-alice",
            )

    def test_hold_release_unregistered_approver_rejected(self):
        """Unregistered user identity is rejected."""
        unregistered = {"user_id": "attacker-eve", "signing_key": "eve-secret-key"}
        with pytest.raises(SecurityViolationError, match="not present in authorized approver key registry"):
            evaluate_hold_release(
                action_type="RELEASE_SAFE_CLOSE_HOLD",
                asset_tier="Tier 2",
                approvers=[unregistered],
                request_time=1000.0,
                current_time=1050.0,
            )

    def test_hold_release_soc_manager_escalation_authorization(self):
        """
        When timed out with a single approver, providing a valid SOC Manager
        escalation approver satisfies authorization.
        """
        from src.policy.release_gate import DEFAULT_APPROVER_REGISTRY
        approver1 = {"user_id": "analyst-alice", "signing_key": "alice-key-1"}
        mgr = DEFAULT_APPROVER_REGISTRY["manager-carol"]
        mgr_approver = {"user_id": mgr.user_id, "signing_key": mgr.signing_key}

        res = evaluate_hold_release(
            action_type="APPROVE_DISABLE_ACCOUNT",
            asset_tier="Tier 1",
            approvers=[approver1],
            request_time=1000.0,
            current_time=2000.0,  # 1000s > 900s
            t_4eyes_timeout=900.0,
            escalation_approver=mgr_approver,
        )
        assert res["status"] == "APPROVED"
        assert res["reason"] == "FOUR_EYES_TIMEOUT_ESCALATION_SATISFIED_BY_SOC_MANAGER"

    def test_hold_release_non_dict_approver_rejected(self):
        """Non-dict approver entries raise ValueError."""
        with pytest.raises(ValueError, match="Approver entry must be a dictionary"):
            evaluate_hold_release(
                action_type="RELEASE_SAFE_CLOSE_HOLD",
                asset_tier="Tier 2",
                approvers=["not-a-dict"],
                request_time=1000.0,
                current_time=1050.0,
            )

        with pytest.raises(ValueError, match="Approver entry must be a dictionary"):
            evaluate_hold_release(
                action_type="RELEASE_SAFE_CLOSE_HOLD",
                asset_tier="Tier 2",
                approvers=[{"user_id": "analyst-alice", "signing_key": "alice-key-1"}, "not-a-dict"],
                request_time=1000.0,
                current_time=1050.0,
            )

    def test_hold_release_empty_user_id_rejected(self):
        """Approver missing user_id raises ValueError."""
        with pytest.raises(ValueError, match="Each approver must supply 'user_id'"):
            evaluate_hold_release(
                action_type="RELEASE_SAFE_CLOSE_HOLD",
                asset_tier="Tier 2",
                approvers=[{"user_id": "", "signing_key": "k1"}],
                request_time=1000.0,
                current_time=1050.0,
            )

    def test_hold_release_unauthorized_role_rejected(self):
        """Approver with unauthorized human role raises SecurityViolationError."""
        with pytest.raises(SecurityViolationError, match="not an authorized human approver role"):
            evaluate_hold_release(
                action_type="RELEASE_SAFE_CLOSE_HOLD",
                asset_tier="Tier 2",
                approvers=[{"user_id": "analyst-alice", "role": "intern", "signing_key": "alice-key-1"}],
                request_time=1000.0,
                current_time=1050.0,
            )

    def test_hold_release_signature_missing_when_required(self):
        """When require_signatures=True, missing signature raises SecurityViolationError."""
        with pytest.raises(SecurityViolationError, match="Missing cryptographic signature"):
            evaluate_hold_release(
                action_type="RELEASE_SAFE_CLOSE_HOLD",
                asset_tier="Tier 2",
                approvers=[{"user_id": "analyst-alice", "signing_key": "alice-key-1"}],
                request_time=1000.0,
                current_time=1050.0,
                require_signatures=True,
            )

    def test_hold_release_signature_missing_nonce(self):
        """Signed approver missing nonce raises SecurityViolationError."""
        with pytest.raises(SecurityViolationError, match="Missing required nonce"):
            evaluate_hold_release(
                action_type="RELEASE_SAFE_CLOSE_HOLD",
                asset_tier="Tier 2",
                approvers=[{"user_id": "analyst-alice", "signing_key": "alice-key-1", "signature": "sig"}],
                request_time=1000.0,
                current_time=1050.0,
            )

    def test_hold_release_signature_expired(self):
        """Signature presented after expiration raises ReleaseGateError."""
        from src.policy.release_gate import DEFAULT_APPROVER_REGISTRY
        alice = DEFAULT_APPROVER_REGISTRY["analyst-alice"]
        token = create_approval_signature(
            approver=alice,
            action_type="RELEASE_SAFE_CLOSE_HOLD",
            asset_tier="Tier 2",
            incident_id="INC-1",
            tenant_id="T-1",
            nonce="nonce-exp-test",
            issued_at=1000.0,
            expires_at=1100.0,
        )
        with pytest.raises(ReleaseGateError, match="has expired"):
            evaluate_hold_release(
                action_type="RELEASE_SAFE_CLOSE_HOLD",
                asset_tier="Tier 2",
                approvers=[token],
                request_time=1000.0,
                current_time=1200.0,  # 1200 > 1100 expires_at
                incident_id="INC-1",
                tenant_id="T-1",
            )

    def test_hold_release_signature_future_skew(self):
        """Signature with issued_at in the far future raises ReleaseGateError."""
        from src.policy.release_gate import DEFAULT_APPROVER_REGISTRY
        alice = DEFAULT_APPROVER_REGISTRY["analyst-alice"]
        token = create_approval_signature(
            approver=alice,
            action_type="RELEASE_SAFE_CLOSE_HOLD",
            asset_tier="Tier 2",
            incident_id="INC-1",
            tenant_id="T-1",
            nonce="nonce-skew-test",
            issued_at=1500.0,
            expires_at=2000.0,
        )
        with pytest.raises(ReleaseGateError, match="timestamp for 'analyst-alice' is in the future"):
            evaluate_hold_release(
                action_type="RELEASE_SAFE_CLOSE_HOLD",
                asset_tier="Tier 2",
                approvers=[token],
                request_time=1000.0,
                current_time=1050.0,  # 1500 > 1050 + 60
                incident_id="INC-1",
                tenant_id="T-1",
            )

    def test_hold_release_soc_manager_invalid_escalation_role_and_key(self):
        """Escalation approver with non-manager role or wrong key is rejected."""
        approver1 = {"user_id": "analyst-alice", "signing_key": "alice-key-1"}

        # Non-manager role (analyst-dan)
        with pytest.raises(SecurityViolationError, match="requires registered HUMAN_SOC_MANAGER"):
            evaluate_hold_release(
                action_type="APPROVE_DISABLE_ACCOUNT",
                asset_tier="Tier 1",
                approvers=[approver1],
                request_time=1000.0,
                current_time=2000.0,
                t_4eyes_timeout=900.0,
                escalation_approver={"user_id": "analyst-dan", "signing_key": "dan-key-tier3"},
            )

        # Manager user with invalid key
        with pytest.raises(SecurityViolationError, match="Invalid credentials for escalation SOC Manager"):
            evaluate_hold_release(
                action_type="APPROVE_DISABLE_ACCOUNT",
                asset_tier="Tier 1",
                approvers=[approver1],
                request_time=1000.0,
                current_time=2000.0,
                t_4eyes_timeout=900.0,
                escalation_approver={"user_id": "manager-carol", "signing_key": "wrong-key"},
            )

    def test_hold_release_tier2_zero_approvers_before_timeout_pending(self):
        """Tier 2 release with 0 approvers before timeout returns PENDING_APPROVAL."""
        res = evaluate_hold_release(
            action_type="RELEASE_SAFE_CLOSE_HOLD",
            asset_tier="Tier 2",
            approvers=[],
            request_time=1000.0,
            current_time=1200.0,  # 200s < 900s
            t_4eyes_timeout=900.0,
        )
        assert res["status"] == "PENDING_APPROVAL"
        assert res["escalated"] is False
