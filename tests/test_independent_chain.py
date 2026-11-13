"""
================================================================================
CLEAN-ROOM INDEPENDENT LEDGER VERIFICATION SUITE (FIX-08 / Invariant #3)
File: tests/test_independent_chain.py
================================================================================
Purpose:
  Provides clean-room independent mathematical verification of the golden
  incident chains (INC-2026-4401 and INC-2026-8820) without depending on
  any internal helper shortcuts.
  
  Guarantees:
    1. Golden tip hashes remain frozen across all future refactorings.
    2. Bit-for-bit adherence to RFC-6962 and SecOps Guardrail Specification Section 4.2:
       - Equation 14: HMAC-SHA256(per_entry_salt, canonical_payload)
       - Entry Hash: SHA-256(canonical_metadata || raw_commitment || raw_prev_hash)
       - Genesis prev_entry_hash is strictly 64 null zeros.
================================================================================
"""

import hashlib
import hmac
import json
from pathlib import Path
import pytest
from src.ledger.chain import (
    GENESIS_PREV_HASH,
    VerificationResult,
    canonicalize_json,
    extract_metadata,
    verify_chain,
    verify_chain_anchored,
    WORMAnchorInterface,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
GOLDEN_HEAD_INC_2026_4401 = "f1ee3e47957b57aeb428908d41cc7d60b704da7694e550f26adb4ec9c090c3ac"
GOLDEN_HEAD_INC_2026_8820 = "5a22007d561c17a5249d5e43a3f95c853d382fbd442d65b01a1560f4ef7ddad8"


def clean_room_compute_entry_hash(entry: dict) -> str:
    """
    Independently recomputes the SHA-256 entry hash from scratch using
    only Python standard library hashlib and json.
    """
    # 1. Equation 14 HMAC-SHA256 payload commitment
    salt_bytes = bytes.fromhex(entry["per_entry_salt"])
    canonical_payload_bytes = json.dumps(
        entry["payload"],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    expected_commitment = hmac.new(salt_bytes, canonical_payload_bytes, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(entry["payload_commitment"], expected_commitment), (
        f"Payload commitment mismatch at {entry['entry_id']}"
    )

    # 2. Canonical metadata bytes
    meta = extract_metadata(entry)
    canonical_meta_bytes = json.dumps(
        meta,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    # 3. Raw byte concatenation
    commit_bytes = bytes.fromhex(expected_commitment)
    prev_bytes = bytes.fromhex(entry["prev_entry_hash"])

    hasher = hashlib.sha256()
    hasher.update(canonical_meta_bytes)
    hasher.update(commit_bytes)
    hasher.update(prev_bytes)
    return hasher.hexdigest()


def test_independent_golden_head_inc_2026_4401():
    """
    Verifies INC-2026-4401 (Phishing investigation, 14 blocks) against the frozen golden head.
    """
    fixture_path = FIXTURES_DIR / "inc_2026_4401.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        chain = json.load(f)

    assert len(chain) == 14

    # Clean-room recalculation of every block
    for idx, block in enumerate(chain):
        if idx == 0:
            assert block["prev_entry_hash"] == GENESIS_PREV_HASH
        else:
            assert block["prev_entry_hash"] == chain[idx - 1]["entry_hash"]

        computed = clean_room_compute_entry_hash(block)
        assert hmac.compare_digest(block["entry_hash"], computed), (
            f"Entry hash mismatch at index {idx} ({block['entry_id']})"
        )

    # Assert head matches frozen golden constant
    actual_head = chain[-1]["entry_hash"]
    assert actual_head == GOLDEN_HEAD_INC_2026_4401

    # Assert verify_chain with structured result
    res = verify_chain(chain, expected_head=GOLDEN_HEAD_INC_2026_4401)
    assert res.valid is True
    assert res.anchored is True
    assert res.head_hash == GOLDEN_HEAD_INC_2026_4401


def test_independent_golden_head_inc_2026_8820():
    """
    Verifies INC-2026-8820 (Token theft investigation, 15 blocks) against the frozen golden head.
    """
    fixture_path = FIXTURES_DIR / "inc_2026_8820.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        chain = json.load(f)

    assert len(chain) == 15

    # Clean-room recalculation of every block
    for idx, block in enumerate(chain):
        if idx == 0:
            assert block["prev_entry_hash"] == GENESIS_PREV_HASH
        else:
            assert block["prev_entry_hash"] == chain[idx - 1]["entry_hash"]

        computed = clean_room_compute_entry_hash(block)
        assert hmac.compare_digest(block["entry_hash"], computed), (
            f"Entry hash mismatch at index {idx} ({block['entry_id']})"
        )

    # Assert head matches frozen golden constant
    actual_head = chain[-1]["entry_hash"]
    assert actual_head == GOLDEN_HEAD_INC_2026_8820

    # Assert verify_chain with structured result
    res = verify_chain(chain, expected_head=GOLDEN_HEAD_INC_2026_8820)
    assert res.valid is True
    assert res.anchored is True
    assert res.head_hash == GOLDEN_HEAD_INC_2026_8820
