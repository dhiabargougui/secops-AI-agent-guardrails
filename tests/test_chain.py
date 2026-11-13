"""
================================================================================
TEST SUITE: Cryptographic Evidence Ledger Verification
File: tests/test_chain.py
================================================================================
Architectural Invariant:
  Invariant #3 (Single Source of Truth / Cryptographic Audit Ledger)

Governing Standard:
  docs/DESIGN_DECISIONS.md & Autonomous SecOps Guardrail Specification v1.0 (Section 4.2)

Purpose:
  Verifies that the ledger engine (src/ledger/chain.py):
    1. Correctly verifies a valid multi-agent investigation chain.
    2. Detects and rejects 7 distinct adversarial tamper attacks.
    3. Detects tail-truncation when anchored against an expected head hash.

Test Scenarios:
  - Test 1: Happy Path (Valid 5-step investigation chain passes cleanly)
  - Test 2: Tamper Attack - Payload modified (HMAC commitment mismatch)
  - Test 3: Tamper Attack - Metadata modified (SHA-256 entry hash mismatch)
  - Test 4: Tamper Attack - Middle entry deleted (sequence gap & link mismatch)
  - Test 5: Tamper Attack - Two entries swapped (sequence & linkage failure)
  - Test 6: Tamper Attack - ID sequence gap (LEDGER_000 -> LEDGER_002)
  - Test 7: Tamper Attack - Sub-indexed ID rejected (e.g., LEDGER_003_OBJ)
  - Test 8: Tamper Attack - Duplicate ID injected (repeated LEDGER_001)
  - Test 9: Tail-Truncation & External WORM Anchoring Defense
================================================================================
"""

import copy
import pytest
from src.ledger.chain import (
    GENESIS_PREV_HASH,
    VerificationResult,
    WORMAnchorInterface,
    append,
    entry_hash,
    payload_commitment,
    verify_chain,
    verify_chain_anchored,
)


# ==============================================================================
# FIXTURE: Authentic 5-Entry Multi-Agent Investigation
# ==============================================================================
@pytest.fixture
def sample_5_entry_chain():
    """
    Constructs an authentic 5-block investigation chain modeling the Investigation
    dialectical deliberation protocol from the specification:
    
      - LEDGER_000: Planner proposes bifurcated hypotheses (malicious vs benign).
      - LEDGER_001: Investigator posts checklist item CHK_001.
      - LEDGER_002: Investigative Executor reports forensic evidence (FND_TOKEN_MINT).
      - LEDGER_003: Adversary audits evidence and enters a material objection.
      - LEDGER_004: Judge issues a judicial remand for further telemetry before action.
    """
    chain = []
    
    # --------------------------------------------------------------------------
    # Block 0: Genesis - Planner Hypotheses
    # --------------------------------------------------------------------------
    append(chain, {
        "investigation_id": "inv-2026-4401-001",
        "tenant_id": "tenant-enterprise-alpha",
        "timestamp_utc": "2026-10-24T20:12:05Z",
        "agent_role": "ROLE_PLANNER",
        "skill_invoked": "PROPOSE_HYPOTHESIS",
        "target_checklist_item": None,
        "payload": {
            "h_malicious": "OAuth application abuse via spear-phishing token mint",
            "h_benign": "Legitimate Microsoft security notification click-through"
        }
    }, salt="a" * 64)  # Inject deterministic salt for test reproducibility

    # --------------------------------------------------------------------------
    # Block 1: Investigator Checklist Item
    # --------------------------------------------------------------------------
    append(chain, {
        "investigation_id": "inv-2026-4401-001",
        "tenant_id": "tenant-enterprise-alpha",
        "timestamp_utc": "2026-10-24T20:12:15Z",
        "agent_role": "ROLE_INVESTIGATOR",
        "skill_invoked": "CREATE_CHECKLIST",
        "target_checklist_item": "CHK_001",
        "payload": {
            "objective": "Verify Entra ID OAuth grant logs for Alice within 72h window"
        }
    }, salt="b" * 64)

    # --------------------------------------------------------------------------
    # Block 2: Investigative Executor Forensic Finding
    # --------------------------------------------------------------------------
    append(chain, {
        "investigation_id": "inv-2026-4401-001",
        "tenant_id": "tenant-enterprise-alpha",
        "timestamp_utc": "2026-10-24T20:12:40Z",
        "agent_role": "ROLE_INV_EXECUTOR",
        "skill_invoked": "QUERY_TELEMETRY",
        "target_checklist_item": "CHK_001",
        "payload": {
            "finding_class": "FND_TOKEN_MINT",
            "evidence": "OAuth consent granted to untrusted AppID e84f91d2",
            "scope_verified": "WS-ALICE-11"
        }
    }, salt="c" * 64)

    # --------------------------------------------------------------------------
    # Block 3: Adversary Evidence Audit & Objection
    # --------------------------------------------------------------------------
    append(chain, {
        "investigation_id": "inv-2026-4401-001",
        "tenant_id": "tenant-enterprise-alpha",
        "timestamp_utc": "2026-10-24T20:13:00Z",
        "agent_role": "ROLE_ADVERSARY",
        "skill_invoked": "ENTER_OBJECTION",
        "target_checklist_item": "CHK_001",
        "payload": {
            "objection_type": "INSUFFICIENT_CORROBORATION",
            "reason": "Token mint confirmed, but no active C2 outbound session logged"
        }
    }, salt="d" * 64)

    # --------------------------------------------------------------------------
    # Block 4: Judge Decision & Remand
    # --------------------------------------------------------------------------
    append(chain, {
        "investigation_id": "inv-2026-4401-001",
        "tenant_id": "tenant-enterprise-alpha",
        "timestamp_utc": "2026-10-24T20:13:20Z",
        "agent_role": "ROLE_JUDGE",
        "skill_invoked": "ISSUE_REMAND",
        "target_checklist_item": "CHK_001",
        "payload": {
            "verdict": "PARTIAL_CONCURRENCE",
            "directive": "Query network egress proxy for AppID e84f91d2 before isolation"
        }
    }, salt="e" * 64)

    return chain


# ==============================================================================
# TEST 1: Happy Path - Authentic 5-Entry Chain Verifies Cleanly
# ==============================================================================
def test_valid_5_entry_chain_verifies(sample_5_entry_chain):
    """
    WHAT THIS TESTS:
      Verifies that an authentic, untampered 5-entry chain satisfies all
      cryptographic checks:
        - 5 entries present (LEDGER_000 to LEDGER_004).
        - Genesis block points to 64 zeros.
        - Every Equation 14 HMAC commitment matches.
        - Every entry hash matches.
    WHY IT MATTERS:
      Proves the normal, legitimate multi-agent deliberation flow succeeds.
    """
    assert len(sample_5_entry_chain) == 5
    is_valid, reason = verify_chain(sample_5_entry_chain)
    assert is_valid is True, f"Legitimate chain failed verification: {reason}"
    assert "verified successfully" in reason


# ==============================================================================
# TEST 2: Tamper Attack - Payload Modified
# ==============================================================================
def test_tamper_payload_fails(sample_5_entry_chain):
    """
    WHAT THIS TESTS:
      Simulates an attacker or rogue script modifying forensic evidence
      (e.g., rewriting 'FND_TOKEN_MINT' to a benign application in Block 2).
    WHY IT MATTERS:
      Equation 14 requires that payload modification invalidates the HMAC
      commitment. The validator must catch this immediately.
    """
    tampered_chain = copy.deepcopy(sample_5_entry_chain)
    # Tamper with the evidence in Block 2
    tampered_chain[2]["payload"]["finding_class"] = "FND_BENIGN_APPLICATION"

    is_valid, reason = verify_chain(tampered_chain)
    assert is_valid is False
    assert "Tampered payload detected at LEDGER_002" in reason


# ==============================================================================
# TEST 3: Tamper Attack - Metadata Modified
# ==============================================================================
def test_tamper_metadata_fails(sample_5_entry_chain):
    """
    WHAT THIS TESTS:
      Simulates modifying a block's metadata (e.g. forging the agent's role
      from ROLE_ADVERSARY to ROLE_JUDGE to forge a ruling).
    WHY IT MATTERS:
      Because metadata is included in the SHA-256 entry hash calculation,
      any change to metadata breaks the entry hash check.
    """
    tampered_chain = copy.deepcopy(sample_5_entry_chain)
    # Impersonate the Judge in Block 3
    tampered_chain[3]["agent_role"] = "ROLE_JUDGE"

    is_valid, reason = verify_chain(tampered_chain)
    assert is_valid is False
    assert "Tampered entry or metadata detected at LEDGER_003" in reason


# ==============================================================================
# TEST 4: Tamper Attack - Middle Entry Deleted
# ==============================================================================
def test_tamper_delete_middle_entry_fails(sample_5_entry_chain):
    """
    WHAT THIS TESTS:
      Simulates an attacker deleting Block 2 (the forensic evidence block)
      to hide the token mint finding from human auditors.
    WHY IT MATTERS:
      Deletion breaks the chain in two ways:
        1. Monotonic sequence gap: LEDGER_003 now appears at index 2.
        2. Broken hash link: Block 3 points to Block 2's hash, which is now missing.
    """
    tampered_chain = copy.deepcopy(sample_5_entry_chain)
    del tampered_chain[2]

    is_valid, reason = verify_chain(tampered_chain)
    assert is_valid is False
    assert "Monotonic sequence violation" in reason or "Broken hash link" in reason


# ==============================================================================
# TEST 5: Tamper Attack - Two Entries Swapped
# ==============================================================================
def test_tamper_swap_entries_fails(sample_5_entry_chain):
    """
    WHAT THIS TESTS:
      Simulates reordering the timeline (swapping Block 1 and Block 2).
    WHY IT MATTERS:
      Attackers often try to rearrange forensic timelines to create false alibis.
      Reordering causes immediate sequence and hash linkage failure.
    """
    tampered_chain = copy.deepcopy(sample_5_entry_chain)
    tampered_chain[1], tampered_chain[2] = tampered_chain[2], tampered_chain[1]

    is_valid, reason = verify_chain(tampered_chain)
    assert is_valid is False
    assert "Monotonic sequence violation" in reason or "Broken hash link" in reason


# ==============================================================================
# TEST 6: Tamper Attack - Monotonic ID Gap
# ==============================================================================
def test_tamper_id_gap_fails(sample_5_entry_chain):
    """
    WHAT THIS TESTS:
      Simulates an ID numbering gap (LEDGER_000, LEDGER_001, then jumping to LEDGER_003).
    WHY IT MATTERS:
      Prevents hidden or deleted records between blocks.
    """
    tampered_chain = copy.deepcopy(sample_5_entry_chain)
    tampered_chain[2]["entry_id"] = "LEDGER_003"

    is_valid, reason = verify_chain(tampered_chain)
    assert is_valid is False
    assert "Monotonic sequence violation at index 2" in reason


# ==============================================================================
# TEST 7: Tamper Attack - Sub-Indexed ID Rejected
# ==============================================================================
def test_tamper_sub_indexed_id_rejected(sample_5_entry_chain):
    """
    WHAT THIS TESTS:
      Simulates an agent or script creating an unauthorized sub-index
      like 'LEDGER_003_OBJ' or 'LEDGER_001_A'.
    WHY IT MATTERS:
      Specification v3.1 strictly outlaws branch IDs or sub-indices.
      Every block must follow ^LEDGER_\\d{3,}$ on a single unified spine.
    """
    tampered_chain = copy.deepcopy(sample_5_entry_chain)
    tampered_chain[3]["entry_id"] = "LEDGER_003_OBJ"

    is_valid, reason = verify_chain(tampered_chain)
    assert is_valid is False
    assert "invalid ID format 'LEDGER_003_OBJ'" in reason


# ==============================================================================
# TEST 8: Tamper Attack - Duplicate ID Injected
# ==============================================================================
def test_tamper_duplicate_id_fails(sample_5_entry_chain):
    """
    WHAT THIS TESTS:
      Simulates repeating an ID (two blocks both claiming to be LEDGER_001).
    WHY IT MATTERS:
      Guarantees uniqueness and rejects replay attacks.
    """
    tampered_chain = copy.deepcopy(sample_5_entry_chain)
    tampered_chain[2]["entry_id"] = "LEDGER_001"

    is_valid, reason = verify_chain(tampered_chain)
    assert is_valid is False
    assert "Monotonic sequence violation at index 2" in reason


# ==============================================================================
# TEST 9: Tip-Truncation & External WORM Anchoring Proof
# ==============================================================================
def test_tip_truncation_detection(sample_5_entry_chain):
    """
    WHAT THIS TESTS (CRITICAL ARCHITECTURAL PROOF):
      Demonstrates the mathematical limits of a hash chain and proves why
      external Write-Once (WORM) storage anchoring is required.
      
      Scenario:
        An attacker drops the latest tip entry (Block 4, the Judge's Remand)
        so only Blocks 0, 1, 2, and 3 remain, leaving genesis intact.
        
      Result:
        1. Without an external anchor, Blocks 0..3 still form a valid chain
           internally (because each still points to its real predecessor).
        2. But when checked against the 'expected_head' (the tip hash anchored
           to external immutable WORM storage), the tip truncation is CAUGHT instantly!
    """
    truncated_chain = copy.deepcopy(sample_5_entry_chain[:-1])  # Drop Block 4 (tip)
    original_head_hash = sample_5_entry_chain[-1]["entry_hash"]

    # 1. Internal chain math alone cannot know Block 4 was discarded:
    is_valid_internal, reason_internal = verify_chain(truncated_chain)
    assert is_valid_internal is True, "Internal chain math passes because 0..3 links are unbroken"

    # 2. External WORM anchor catches the tip truncation immediately:
    is_valid_anchored, reason_anchored = verify_chain(truncated_chain, expected_head=original_head_hash)
    assert is_valid_anchored is False
    assert "Tip truncation or head mismatch" in reason_anchored


# ==============================================================================
# TEST 10: Sequence ID Scaling Beyond 1,000 Entries (LEDGER_1000)
# ==============================================================================
def test_sequence_id_exceeding_1000_entries():
    """
    WHAT THIS TESTS:
      Verifies that sequence IDs gracefully scale beyond 3 digits (e.g. LEDGER_1000)
      without triggering regex validation errors or padding truncation.
    """
    chain = []
    # Build a fast chain of 1,001 entries
    for i in range(1001):
        append(chain, {
            "investigation_id": "inv-large-scale",
            "tenant_id": "tenant-enterprise-alpha",
            "timestamp_utc": "2026-10-24T20:00:00Z",
            "agent_role": "ROLE_INVESTIGATOR",
            "skill_invoked": "QUERY_TELEMETRY",
            "target_checklist_item": f"CHK_{i:04d}",
            "payload": {"item_index": i}
        })

    assert len(chain) == 1001
    assert chain[0]["entry_id"] == "LEDGER_000"
    assert chain[999]["entry_id"] == "LEDGER_999"
    assert chain[1000]["entry_id"] == "LEDGER_1000"

    is_valid, reason = verify_chain(chain)
    assert is_valid is True, f"1001-entry chain failed verification: {reason}"


# ==============================================================================
# TEST 11: External Key Store Strict Salt Isolation (KMS/HSM Mode)
# ==============================================================================
def test_external_key_store_strict_isolation():
    """
    WHAT THIS TESTS:
      Verifies strict external key store isolation (KMS/HSM mode):
        1. When key_store is provided, salts are written exclusively to key_store[entry_id].
        2. per_entry_salt is completely omitted from the public ledger entries.
        3. verify_chain() succeeds when provided with the external key_store.
    """
    chain = []
    key_store = {}

    for i in range(3):
        append(chain, {
            "investigation_id": "inv-kms-mode",
            "tenant_id": "tenant-enterprise-alpha",
            "timestamp_utc": "2026-10-24T20:00:00Z",
            "agent_role": "ROLE_INVESTIGATOR",
            "skill_invoked": "QUERY_TELEMETRY",
            "target_checklist_item": "CHK_001",
            "payload": {"finding": f"finding_{i}"}
        }, key_store=key_store)

    assert len(chain) == 3
    assert len(key_store) == 3

    # Assert salt is completely absent from all ledger entries
    for entry in chain:
        assert "per_entry_salt" not in entry, f"Key isolation leak: per_entry_salt found in {entry['entry_id']}"

    # Assert salts exist in external key store
    for entry_id in ("LEDGER_000", "LEDGER_001", "LEDGER_002"):
        assert entry_id in key_store
        assert len(key_store[entry_id]) == 64  # 32 bytes hex

    # Verify chain with key_store succeeds
    is_valid, reason = verify_chain(chain, key_store=key_store)
    assert is_valid is True, f"Verification failed with key_store: {reason}"


# ==============================================================================
# TEST 12: External Key Store Fail-Closed on Missing Key
# ==============================================================================
def test_external_key_store_missing_key_fails():
    """
    WHAT THIS TESTS:
      Verifies that in key_store mode, if an entry's salt is missing from the key_store,
      verify_chain() fails closed immediately without falling back to anything.
    """
    chain = []
    key_store = {}

    for i in range(3):
        append(chain, {
            "investigation_id": "inv-kms-mode",
            "tenant_id": "tenant-enterprise-alpha",
            "timestamp_utc": "2026-10-24T20:00:00Z",
            "agent_role": "ROLE_INVESTIGATOR",
            "skill_invoked": "QUERY_TELEMETRY",
            "target_checklist_item": "CHK_001",
            "payload": {"finding": f"finding_{i}"}
        }, key_store=key_store)

    # Delete salt for LEDGER_001 from key_store
    del key_store["LEDGER_001"]

    is_valid, reason = verify_chain(chain, key_store=key_store)
    assert is_valid is False
    assert "Key isolation failure: entry_id 'LEDGER_001' missing from external key_store" in reason


# ==============================================================================
# TEST 13: External Key Store Rejects Co-Located Salt in Block
# ==============================================================================
def test_external_key_store_rejects_co_located_salt():
    """
    WHAT THIS TESTS:
      Verifies that in key_store mode, if an entry has per_entry_salt co-located
      inside the block (leak attempt), verify_chain() rejects it with a key isolation violation.
    """
    chain = []
    key_store = {}

    for i in range(2):
        append(chain, {
            "investigation_id": "inv-kms-mode",
            "tenant_id": "tenant-enterprise-alpha",
            "timestamp_utc": "2026-10-24T20:00:00Z",
            "agent_role": "ROLE_INVESTIGATOR",
            "skill_invoked": "QUERY_TELEMETRY",
            "target_checklist_item": "CHK_001",
            "payload": {"finding": f"finding_{i}"}
        }, key_store=key_store)

    # Inject per_entry_salt directly into the block (violating KMS isolation)
    chain[1]["per_entry_salt"] = "leaked_salt_value"

    is_valid, reason = verify_chain(chain, key_store=key_store)
    assert is_valid is False
    assert "Key isolation violation at LEDGER_001: per_entry_salt must not be co-located" in reason


# ==============================================================================
# SECTION 8: SURVIVOR MUTANTS & STRUCTURED RESULT / WORM TESTS (FIX-01, FIX-08)
# ==============================================================================

def test_genesis_nonzero_prev_hash_rejected(sample_5_entry_chain):
    """
    Kills mutant R3-CH-7:
    Genesis block LEDGER_000 must have prev_entry_hash of strictly 64 null zeros.
    If corrupted, verify_chain() must reject it.
    """
    tampered = copy.deepcopy(sample_5_entry_chain)
    tampered[0]["prev_entry_hash"] = "1" * 64

    is_valid, reason = verify_chain(tampered)
    assert is_valid is False
    assert "Genesis block LEDGER_000 prev_entry_hash must be 64 zeros" in reason


def test_missing_in_block_salt_rejected(sample_5_entry_chain):
    """
    Kills mutant R3-CH-9:
    In standard mode (no key_store), an entry missing 'per_entry_salt' must fail closed.
    """
    tampered = copy.deepcopy(sample_5_entry_chain)
    del tampered[1]["per_entry_salt"]

    is_valid, reason = verify_chain(tampered)
    assert is_valid is False
    assert "Missing per_entry_salt at LEDGER_001" in reason


def test_verification_result_tuple_unpacking_and_anchored_attribute(sample_5_entry_chain):
    """
    Verifies that VerificationResult satisfies the 2-tuple sequence protocol
    for backward compatibility while exposing .anchored and .head_hash.
    """
    # 1. Unanchored verification (expected_head omitted)
    res_unanchored = verify_chain(sample_5_entry_chain)
    valid, reason = res_unanchored  # 2-tuple unpacking
    assert valid is True
    assert "verified successfully" in reason
    assert len(res_unanchored) == 2
    assert res_unanchored[0] is True
    assert res_unanchored.anchored is False
    assert res_unanchored.head_hash == sample_5_entry_chain[-1]["entry_hash"]

    # 2. Anchored verification (expected_head provided)
    head_hash = sample_5_entry_chain[-1]["entry_hash"]
    res_anchored = verify_chain(sample_5_entry_chain, expected_head=head_hash)
    assert res_anchored.valid is True
    assert res_anchored.anchored is True
    assert res_anchored.head_hash == head_hash


def test_worm_anchor_interface_and_verify_chain_anchored(sample_5_entry_chain):
    """
    Verifies verify_chain_anchored() using a mock WORMAnchorInterface.
    """
    head_hash = sample_5_entry_chain[-1]["entry_hash"]
    incident_id = sample_5_entry_chain[0]["investigation_id"]

    class MockWORMStore(WORMAnchorInterface):
        def __init__(self):
            self.anchors = {}

        def anchor_head(self, h: str, inc: str) -> None:
            self.anchors[inc] = h

        def verify_head(self, h: str, inc: str) -> bool:
            return self.anchors.get(inc) == h

    worm = MockWORMStore()
    worm.anchor_head(head_hash, incident_id)

    # Valid anchored check
    res = verify_chain_anchored(sample_5_entry_chain, worm, incident_id)
    assert res.valid is True
    assert res.anchored is True

    # Anchored check fails if WORM holds different hash
    worm.anchor_head("bad_hash" * 8, incident_id)
    res_bad = verify_chain_anchored(sample_5_entry_chain, worm, incident_id)
    assert res_bad.valid is False
    assert "WORM_ANCHOR_MISMATCH" in res_bad.reason


def test_append_worm_anchor_hook_invoked():
    """
    Verifies that append() invokes the worm_anchor_hook with the new block's
    calculated entry hash and investigation_id.
    """
    chain = []
    recorded_hooks = []

    def hook(h: str, inc: str) -> None:
        recorded_hooks.append((h, inc))

    entry = {
        "investigation_id": "inv-worm-hook",
        "tenant_id": "tenant-alpha",
        "timestamp_utc": "2026-10-24T20:00:00Z",
        "agent_role": "ROLE_PLANNER",
        "skill_invoked": "PROPOSE_HYPOTHESIS",
        "target_checklist_item": "CHK_001",
        "payload": {"data": "test"},
    }
    new_entry = append(chain, entry, worm_anchor_hook=hook)
    assert len(recorded_hooks) == 1
    assert recorded_hooks[0] == (new_entry["entry_hash"], "inv-worm-hook")


def test_append_unrecognized_metadata_key_rejected():
    """
    Verifies that append() rejects unrecognized fields not in ALLOWED_ENTRY_KEYS (FIX-08).
    """
    chain = []
    entry = {
        "investigation_id": "inv-schema-guard",
        "tenant_id": "tenant-alpha",
        "timestamp_utc": "2026-10-24T20:00:00Z",
        "agent_role": "ROLE_PLANNER",
        "skill_invoked": "PROPOSE_HYPOTHESIS",
        "target_checklist_item": "CHK_001",
        "payload": {"data": "test"},
        "unauthorized_malicious_metadata": 12345,
    }
    with pytest.raises(ValueError, match="Unrecognized ledger entry fields detected"):
        append(chain, entry)

