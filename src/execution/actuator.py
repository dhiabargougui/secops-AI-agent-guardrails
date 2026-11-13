"""
Actuation Integrity Engine (Architectural Invariant #1).
File: src/execution/actuator.py

Governing Standard:
  Autonomous SecOps Guardrail Specification v1.0 (Section 2.1 Box 1, Section 3.2, Section 5.3)

Principles:
  1. Reasoning agents have zero direct actuation credentials.
  2. Containment actuation requires an explicit PEP ALLOW decision.
  3. Remediation Executor generates cryptographically signed containment orders.
  4. In-network Order Executor verifies HMAC signatures, binds PEP outcomes,
     validates citations against ^LEDGER_\\d{3,}$, and enforces anti-replay
     and clock skew constraints without cache-poisoning vulnerabilities.
"""

import hashlib
import hmac
import re
import threading
import time
import uuid
from typing import Any, Dict, Optional, Set

from src.ledger.chain import canonicalize_json

# Strict ledger block citation pattern matching ^LEDGER_\d{3,}$
CITATION_PATTERN: re.Pattern = re.compile(r"^LEDGER_(\d{3,})$")

# Maximum permitted containment order lifetime (1 hour ceiling to bound nonce storage)
MAX_ORDER_TTL: float = 3600.0


class ActuationError(Exception):
    """Base exception for actuation failures."""
    pass


class ActuationAuthorizationError(ActuationError):
    """Raised when an order lacks valid PEP authorization."""
    pass


class OrderValidationError(ActuationError):
    """Raised when order signature, replay, or time constraints fail."""
    pass


def create_containment_order(
    pep_evaluation: Dict[str, Any],
    action_type: str,
    target_entity: str,
    tenant_id: str,
    incident_id: str,
    decision_citation: str,
    secret_key: str,
    ttl_seconds: int = 300,
    issuer_role: str = "ROLE_REM_EXECUTOR",
    current_time: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Creates an HMAC-SHA256 signed containment order from an authorized PEP evaluation.

    Parameters:
      - pep_evaluation: PEP result dict containing at least 'decision' and 'reason'.
      - action_type: Containment directive (e.g., 'ISOLATE_HOST', 'REVOKE_ACTIVE_SESSIONS').
      - target_entity: Affected hostname, user principal, or IP observable.
      - tenant_id: Customer tenant identifier.
      - incident_id: Active incident identifier.
      - decision_citation: Grounded ledger citation for the PEP receipt (e.g., 'LEDGER_010').
      - secret_key: Shared symmetric secret between platform and Order Executor.
      - ttl_seconds: Validity lifetime in seconds (default 300s).
      - issuer_role: Role of creating agent; must be 'ROLE_REM_EXECUTOR'.
      - current_time: Optional deterministic timestamp override for testing.

    Returns:
      - Dict containing the complete signed order.

    Raises:
      - ActuationAuthorizationError: If PEP decision is not ALLOW, issuer role is
        unauthorized, or citation format is invalid.
    """
    if not isinstance(pep_evaluation, dict):
        raise ActuationAuthorizationError("PEP evaluation must be a dictionary.")

    decision = pep_evaluation.get("decision")
    if decision != "ALLOW":
        raise ActuationAuthorizationError(
            f"Cannot issue containment order: PEP decision is '{decision}', required 'ALLOW'."
        )

    if issuer_role != "ROLE_REM_EXECUTOR":
        raise ActuationAuthorizationError(
            f"Unauthorized issuer role '{issuer_role}'. Only 'ROLE_REM_EXECUTOR' can issue containment orders."
        )

    if not decision_citation or not CITATION_PATTERN.match(decision_citation.strip()):
        raise ActuationAuthorizationError(
            f"Invalid decision citation '{decision_citation}'. Must match '^LEDGER_\\d{{3,}}$'."
        )

    now = float(current_time) if current_time is not None else time.time()
    order_id = f"ORD-{uuid.uuid4()}"
    nonce = str(uuid.uuid4())
    expires_at = now + float(ttl_seconds)

    payload_to_sign = {
        "order_id": order_id,
        "nonce": nonce,
        "tenant_id": tenant_id,
        "incident_id": incident_id,
        "action_type": action_type,
        "target_entity": target_entity,
        "decision_citation": decision_citation.strip(),
        "pep_decision": decision,
        "pep_reason": pep_evaluation.get("reason", ""),
        "issued_at": now,
        "expires_at": expires_at,
        "issuer_role": issuer_role,
    }

    canonical_bytes = canonicalize_json(payload_to_sign)
    key_bytes = secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
    signature = hmac.new(key_bytes, canonical_bytes, hashlib.sha256).hexdigest()

    order = dict(payload_to_sign)
    order["signature"] = signature
    return order


class OrderExecutor:
    """
    In-network Order Executor holding execution credentials.

    Validates incoming signed orders, checks clock bounds and replay caches,
    and returns deterministic execution receipts.
    """

    def __init__(
        self,
        secret_key: str,
        clock_skew_seconds: float = 30.0,
        max_order_ttl: float = MAX_ORDER_TTL,
    ):
        self.secret_key = secret_key
        self.clock_skew_seconds = float(clock_skew_seconds)
        self.max_order_ttl = float(max_order_ttl)
        self._lock = threading.Lock()
        self.seen_nonces: Dict[str, float] = {}

    def _evict_expired_nonces(self, now: float) -> None:
        """Purges nonces whose order expiry is older than now - clock_skew."""
        cutoff = now - self.clock_skew_seconds
        expired = [n for n, exp in self.seen_nonces.items() if exp < cutoff]
        for n in expired:
            del self.seen_nonces[n]

    def execute_order(
        self,
        order: Dict[str, Any],
        current_time: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Validates and executes a containment order.

        Parameters:
          - order: Dict representing the signed order.
          - current_time: Optional deterministic timestamp override for testing.

        Returns:
          - Dict containing the execution receipt.

        Raises:
          - OrderValidationError: If signature verification fails, timestamps exceed
            bounds, role is unauthorized, or a replay attack is detected.
        """
        required_fields = (
            "order_id",
            "nonce",
            "tenant_id",
            "incident_id",
            "action_type",
            "target_entity",
            "decision_citation",
            "pep_decision",
            "pep_reason",
            "issued_at",
            "expires_at",
            "issuer_role",
            "signature",
        )

        for field in required_fields:
            if field not in order:
                raise OrderValidationError(f"Missing required order field: '{field}'")

        # 1. Validate issuer role
        if order["issuer_role"] != "ROLE_REM_EXECUTOR":
            raise OrderValidationError(
                f"Unauthorized issuer role: '{order['issuer_role']}'. Expected 'ROLE_REM_EXECUTOR'."
            )

        # 2. Validate PEP outcome binding
        if order["pep_decision"] != "ALLOW":
            raise OrderValidationError(
                f"Order rejected: PEP decision is '{order['pep_decision']}', expected 'ALLOW'."
            )

        if not CITATION_PATTERN.match(str(order["decision_citation"]).strip()):
            raise OrderValidationError(
                f"Invalid decision citation: '{order['decision_citation']}'"
            )

        # 3. Verify HMAC signature before inspecting replay cache
        payload_to_verify = {k: order[k] for k in required_fields if k != "signature"}
        canonical_bytes = canonicalize_json(payload_to_verify)
        key_bytes = self.secret_key.encode("utf-8") if isinstance(self.secret_key, str) else self.secret_key
        expected_sig = hmac.new(key_bytes, canonical_bytes, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(order["signature"], expected_sig):
            raise OrderValidationError("Cryptographic signature verification failed.")

        # 4. Check clock bounds and order lifetime
        now = float(current_time) if current_time is not None else time.time()
        issued_at = float(order["issued_at"])
        expires_at = float(order["expires_at"])

        # Check order lifetime bounds (FIX-02 cap)
        if expires_at - issued_at > self.max_order_ttl:
            raise OrderValidationError(
                f"Order lifetime {expires_at - issued_at}s exceeds maximum allowed ceiling of {self.max_order_ttl}s."
            )
        if expires_at < issued_at:
            raise OrderValidationError(
                f"Malformed order: expires_at ({expires_at}) is earlier than issued_at ({issued_at})."
            )

        # Check future timestamp skew
        if issued_at > now + self.clock_skew_seconds:
            raise OrderValidationError(
                f"Order timestamp {issued_at} is in the future beyond allowed clock skew "
                f"({self.clock_skew_seconds}s). Current time is {now}."
            )

        # Check order expiry
        if now > expires_at:
            raise OrderValidationError(
                f"Order has expired. Current time {now} > expires_at {expires_at}."
            )

        # 5. Check anti-replay cache under lock after cryptographic authenticity is confirmed
        nonce = str(order["nonce"])
        with self._lock:
            self._evict_expired_nonces(now)
            if nonce in self.seen_nonces:
                raise OrderValidationError(
                    f"Replay attack detected: nonce '{nonce}' has already been processed."
                )

            # Record nonce and its expiry timestamp only after all checks pass
            self.seen_nonces[nonce] = expires_at

        # 6. Emit execution receipt
        return {
            "status": "EXECUTED",
            "order_id": order["order_id"],
            "nonce": nonce,
            "action_type": order["action_type"],
            "target_entity": order["target_entity"],
            "tenant_id": order["tenant_id"],
            "incident_id": order["incident_id"],
            "decision_citation": order["decision_citation"],
            "executed_at": now,
            "executor_role": "ROLE_ORDER_EXECUTOR",
        }

