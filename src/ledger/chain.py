"""
================================================================================
AUTONOMOUS SOC CRYPTOGRAPHIC AUDIT LEDGER (RFC-6962 & Invariant #3)
File: src/ledger/chain.py
================================================================================
Architectural Invariant:
  Invariant #3: Cryptographic Audit Ledger (Section 4.2, Autonomous SecOps Guardrail Specification v1.0)

Core Mechanisms:
  1. Strict Monotonic Sequencing: Sequential entry_id (LEDGER_000, LEDGER_001, etc.).
  2. Equation 14 Payload Commitment: HMAC-SHA256(per_entry_salt, canonical_payload).
  3. Entry Hash: Cryptographically binds (canonical_metadata + commitment + prev_hash).
  4. Genesis Anchor: The very first block's previous hash is strictly 64 zeros.
  5. Constant-Time Verification: Uses hmac.compare_digest to protect against timing attacks.
  6. Structured VerificationResult: Returns backward-compatible 2-tuple protocol while exposing .anchored.
  7. External WORM Anchoring: Supports explicit WORM storage hooks and verification interfaces.
================================================================================
"""

import hashlib
import hmac
import json
import re
import secrets
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# ------------------------------------------------------------------------------
# CONSTANTS & CONFIGURATION (as defined in docs/DESIGN_DECISIONS.md)
# ------------------------------------------------------------------------------

# Decision 2: The genesis block (LEDGER_000) has no prior block.
# We anchor it to exactly 64 hexadecimal zeros (representing 32 null bytes).
GENESIS_PREV_HASH: str = "0" * 64

# Strict Monotonic ID Pattern:
# Matches 'LEDGER_' followed by 3 or more digits (e.g. LEDGER_000, LEDGER_001).
# Rejects illegal sub-indexed formats like 'LEDGER_003_OBJ' or 'LEDGER_001_REMAND'.
ID_PATTERN: re.Pattern = re.compile(r"^LEDGER_(\d{3,})$")

# Authoritative list of fields that belong in the canonical metadata block
METADATA_FIELDS = (
    "entry_id",                # Sequential block ID (e.g., "LEDGER_000")
    "investigation_id",        # Incident investigation UUID
    "tenant_id",               # Multi-tenancy customer UUID
    "timestamp_utc",           # ISO-8601 creation time
    "agent_role",              # Role of the creating agent (e.g., "ROLE_PLANNER")
    "skill_invoked",           # Action taken (e.g., "PROPOSE_HYPOTHESIS")
    "target_checklist_item"    # Associated checklist item (e.g., "CHK_001")
)

# Fields that MUST be excluded from metadata hashing to prevent circular dependencies
EXCLUDED_FROM_METADATA = (
    "entry_hash",              # Cannot hash a block while including its own hash
    "per_entry_salt",          # Secret salt must remain separate from public metadata
    "payload_commitment",      # Bound separately into the entry hash
    "payload",                 # Sealed inside the payload commitment
    "signature"                # Applied after block is closed and hashed
)

# Permissible ledger block keys (FIX-08 schema validation allowlist)
ALLOWED_ENTRY_KEYS: Set[str] = set(METADATA_FIELDS) | set(EXCLUDED_FROM_METADATA) | {"prev_entry_hash", "incident_id"}


# ------------------------------------------------------------------------------
# STRUCTURED VERIFICATION RESULT (FIX-01)
# ------------------------------------------------------------------------------
class VerificationResult:
    """
    Structured verification result providing backward-compatible 2-tuple unpacking
    while exposing detailed audit metadata (anchored, head_hash, reason).
    
    Guarantees:
      - valid, reason = verify_chain(...) works without modification.
      - res[0], res[1], len(res) == 2 work as expected for sequence unpackers.
      - res.anchored indicates whether verification was anchored against expected_head/WORM.
    """
    def __init__(
        self,
        valid: bool,
        reason: str,
        anchored: bool = False,
        head_hash: Optional[str] = None,
    ):
        self.valid = bool(valid)
        self.reason = str(reason)
        self.anchored = bool(anchored)
        self.head_hash = head_hash

    def __iter__(self):
        yield self.valid
        yield self.reason

    def __getitem__(self, index: int) -> Any:
        return (self.valid, self.reason)[index]

    def __len__(self) -> int:
        return 2

    def __bool__(self) -> bool:
        return self.valid

    def __repr__(self) -> str:
        return f"VerificationResult(valid={self.valid}, reason='{self.reason}', anchored={self.anchored})"


class WORMAnchorInterface:
    """Interface for external Write-Once-Read-Many (WORM) storage or cloud key stores."""
    def anchor_head(self, head_hash: str, incident_id: str) -> None:
        raise NotImplementedError

    def verify_head(self, head_hash: str, incident_id: str) -> bool:
        raise NotImplementedError


# ------------------------------------------------------------------------------
# 1. CANONICAL JSON SERIALIZATION (Decision 1)
# ------------------------------------------------------------------------------
def canonicalize_json(data: Any) -> bytes:
    """
    Serializes Python dictionaries or objects into a canonical, deterministic
    byte stream (UTF-8).
    
    Why this is critical:
      In cryptography, {"a":1,"b":2} and {"b":2,"a":1} produce completely
      different hashes. By sorting keys alphabetically and stripping all
      spaces after separators, every computer generates the exact same bytes.
    """
    return json.dumps(
        data,
        sort_keys=True,           # Sort keys alphabetically: A-Z
        separators=(",", ":"),    # Strip all whitespace after commas and colons
        ensure_ascii=False        # Preserve true UTF-8 encoding
    ).encode("utf-8")


# ------------------------------------------------------------------------------
# 2. METADATA EXTRACTION
# ------------------------------------------------------------------------------
def extract_metadata(entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts the canonical metadata fields from a ledger entry.
    Filters out the payload, salt, commitment, and hash fields so they
    are not accidentally duplicated or circular.
    """
    meta = {}
    # Include standard metadata fields if present
    for key in METADATA_FIELDS:
        if key in entry:
            meta[key] = entry[key]
    
    # Include any custom metadata, skipping excluded fields
    for k, v in entry.items():
        if k not in EXCLUDED_FROM_METADATA and k not in meta:
            meta[k] = v
            
    return meta


# ------------------------------------------------------------------------------
# 3. EQUATION 14: PAYLOAD COMMITMENT
# ------------------------------------------------------------------------------
def payload_commitment(salt_hex: str, payload: Any) -> str:
    """
    Implements Equation 14 of Autonomous SecOps Guardrail Specification v1.0:
      payload_commitment = HMAC-SHA256(per_entry_salt, canonical_payload)
      
    Why HMAC-SHA256:
      Protects the payload against rainbow table attacks and length-extension
      attacks while guaranteeing mathematical proof of content integrity.
      Returns a 64-character lowercase hexadecimal string.
    """
    # Convert hex salt to 32 raw bytes
    salt_bytes = bytes.fromhex(salt_hex)
    
    # Canonicalize the payload to deterministic bytes
    if isinstance(payload, (dict, list)):
        payload_bytes = canonicalize_json(payload)
    elif isinstance(payload, bytes):
        payload_bytes = payload
    else:
        payload_bytes = str(payload).encode("utf-8")

    # Compute HMAC-SHA256
    return hmac.new(salt_bytes, payload_bytes, hashlib.sha256).hexdigest()


# ------------------------------------------------------------------------------
# 4. ENTRY HASH CALCULATION (Decision 3)
# ------------------------------------------------------------------------------
def entry_hash(metadata: Dict[str, Any], commitment: str, prev_hash: str) -> str:
    """
    Computes the authoritative entry hash linking this block to the chain.
    
    Mathematical Formula (Spec Section 4.2):
      entry_hash = SHA-256(canonical_metadata_bytes ||
                           raw_commitment_bytes ||
                           raw_prev_hash_bytes)
                           
    Why raw bytes:
      Converting the 64-character hex strings into 32 raw bytes (via fromhex)
      guarantees exact binary concatenation without string formatting ambiguities.
      Returns a 64-character lowercase hexadecimal SHA-256 digest.
    """
    meta_bytes = canonicalize_json(metadata)
    commit_bytes = bytes.fromhex(commitment)
    prev_bytes = bytes.fromhex(prev_hash)
    
    hasher = hashlib.sha256()
    hasher.update(meta_bytes)
    hasher.update(commit_bytes)
    hasher.update(prev_bytes)
    return hasher.hexdigest()


# ------------------------------------------------------------------------------
# 5. APPEND NEW ENTRY TO CHAIN
# ------------------------------------------------------------------------------
def append(
    chain: List[Dict[str, Any]],
    entry: Dict[str, Any],
    salt: Optional[str] = None,
    key_store: Optional[Dict[str, str]] = None,
    worm_anchor_hook: Optional[Callable[[str, str], None]] = None,
) -> Dict[str, Any]:
    """
    Appends a new block to the cryptographic ledger.
    
    Steps performed automatically:
      0. Validates entry keys against schema allowlist (FIX-08).
      1. Assigns or validates sequential entry_id (LEDGER_000, LEDGER_001, etc.).
      2. Links to prior block's entry_hash (or 64 zeros if Genesis block).
      3. Generates a secure 32-byte random salt (or accepts injected test salt).
      4. Key Store Isolation:
         - If key_store is provided, salt is saved strictly to key_store[entry_id]
           and omitted from the public ledger entry (KMS/HSM isolation mode).
         - If key_store is None, salt is embedded in entry['per_entry_salt']
           (Specification Listing 2 mode).
      5. Computes Equation 14 HMAC payload commitment.
      6. Computes authoritative SHA-256 entry hash over metadata + commitment + prev_hash.
      7. Appends to the chain, optionally invokes WORM anchor hook, and returns the completed block.
    """
    # 0. Validate entry keys against schema allowlist
    unexpected = set(entry.keys()) - ALLOWED_ENTRY_KEYS
    if unexpected:
        raise ValueError(f"Unrecognized ledger entry fields detected: {sorted(unexpected)}")

    new_entry = dict(entry)
    expected_index = len(chain)
    
    # 1. Resolve entry ID (auto-assign if missing, or validate strict sequence)
    if "entry_id" not in new_entry:
        new_entry["entry_id"] = f"LEDGER_{expected_index:03d}"
    else:
        m = ID_PATTERN.match(new_entry["entry_id"])
        if not m or int(m.group(1)) != expected_index:
            raise ValueError(
                f"Invalid entry_id '{new_entry['entry_id']}': must strictly be 'LEDGER_{expected_index:03d}'"
            )

    entry_id = new_entry["entry_id"]

    # 2. Resolve previous entry hash linkage
    if expected_index == 0:
        prev_hash = GENESIS_PREV_HASH
    else:
        prev_hash = chain[-1]["entry_hash"]
    new_entry["prev_entry_hash"] = prev_hash

    # 3. Resolve per-entry secret salt (32 secure random bytes = 64 hex chars)
    if salt is None:
        if "per_entry_salt" in new_entry:
            salt = new_entry["per_entry_salt"]
        else:
            salt = secrets.token_bytes(32).hex()

    # 4. Strict Key Store Isolation
    if key_store is not None:
        # Write strictly to external key store; omit from public block
        key_store[entry_id] = salt
        new_entry.pop("per_entry_salt", None)
    else:
        new_entry["per_entry_salt"] = salt

    # 5. Verify payload exists
    if "payload" not in new_entry:
        raise ValueError("Ledger entry must contain a 'payload' field")

    # 6. Compute Equation 14 payload commitment
    commitment = payload_commitment(salt, new_entry["payload"])
    new_entry["payload_commitment"] = commitment

    # 7. Compute authoritative entry hash
    meta = extract_metadata(new_entry)
    calculated_hash = entry_hash(meta, commitment, prev_hash)
    new_entry["entry_hash"] = calculated_hash

    # Add to chain
    chain.append(new_entry)

    # 8. External WORM anchor hook invocation (FIX-01)
    if worm_anchor_hook is not None:
        incident_id = str(new_entry.get("investigation_id", ""))
        worm_anchor_hook(calculated_hash, incident_id)

    return new_entry


# ------------------------------------------------------------------------------
# 6. VERIFY COMPLETE CHAIN INTEGRITY
# ------------------------------------------------------------------------------
def verify_chain(
    chain: List[Dict[str, Any]],
    expected_head: Optional[str] = None,
    key_store: Optional[Dict[str, str]] = None,
) -> VerificationResult:
    """
    Verifies the complete mathematical integrity of the cryptographic ledger.
    
    Enforces 7 strict security checks:
      1. Entry IDs strictly match ^LEDGER_\\d{3,}$ with continuous sequence (no gaps).
      2. Rejects sub-indexed IDs (e.g. LEDGER_003_OBJ).
      3. Genesis prev_entry_hash is strictly 64 zeros.
      4. Every block's prev_entry_hash strictly matches the previous block's entry_hash.
      5. Equation 14 payload commitments match recomputed values (tamper detection):
         - In external key_store mode: salt is retrieved strictly from key_store[entry_id].
           Fails closed if entry_id is missing or if salt is co-located in the block.
         - In standard mode: salt is read from entry['per_entry_salt'].
      6. Entry hashes match recomputed values over metadata (metadata tamper detection).
      7. If 'expected_head' is provided, asserts tip/head block matches (tip-truncation defense).
      
    Returns:
      VerificationResult(True, "Chain integrity verified successfully", anchored=...) if valid.
      VerificationResult(False, "<detailed failure reason>", anchored=False) if any violation is detected.
    """
    # Empty chain edge-case
    if not chain:
        if expected_head is not None:
            return VerificationResult(
                False,
                f"Empty chain cannot match expected head hash '{expected_head}'",
                anchored=False,
            )
        return VerificationResult(True, "Empty chain is valid", anchored=False)

    for idx, entry in enumerate(chain):
        entry_id = entry.get("entry_id", "")
        
        # Check 1 & 2: Validate ID format and strict sequence numbering
        m = ID_PATTERN.match(entry_id)
        if not m:
            return VerificationResult(
                False,
                f"Entry at index {idx} has invalid ID format '{entry_id}' (must match ^LEDGER_\\d{{3,}}$)",
                anchored=False,
            )
        
        sequence_num = int(m.group(1))
        if sequence_num != idx:
            return VerificationResult(
                False,
                f"Monotonic sequence violation at index {idx}: expected ID 'LEDGER_{idx:03d}', got '{entry_id}'",
                anchored=False,
            )

        # Check 3 & 4: Validate previous entry hash linkage
        recorded_prev = entry.get("prev_entry_hash", "")
        if idx == 0:
            if not hmac.compare_digest(recorded_prev, GENESIS_PREV_HASH):
                return VerificationResult(
                    False,
                    f"Genesis block {entry_id} prev_entry_hash must be 64 zeros, got '{recorded_prev}'",
                    anchored=False,
                )
        else:
            expected_prev = chain[idx - 1].get("entry_hash", "")
            if not hmac.compare_digest(recorded_prev, expected_prev):
                return VerificationResult(
                    False,
                    f"Broken hash link at {entry_id}: prev_entry_hash '{recorded_prev}' does not match "
                    f"prior entry hash '{expected_prev}'",
                    anchored=False,
                )

        # Check 5: Resolve salt and verify Equation 14 payload commitment
        if key_store is not None:
            # Strict external key store mode
            if entry_id not in key_store:
                return VerificationResult(
                    False,
                    f"Key isolation failure: entry_id '{entry_id}' missing from external key_store",
                    anchored=False,
                )
            
            if "per_entry_salt" in entry:
                return VerificationResult(
                    False,
                    f"Key isolation violation at {entry_id}: per_entry_salt must not be co-located "
                    "in the ledger entry when key_store mode is active",
                    anchored=False,
                )
            
            salt = key_store[entry_id]
        else:
            # In-block salt mode (Specification Listing 2)
            salt = entry.get("per_entry_salt")
            if not salt:
                return VerificationResult(
                    False,
                    f"Missing per_entry_salt at {entry_id}",
                    anchored=False,
                )
        
        if "payload" not in entry:
            return VerificationResult(
                False,
                f"Missing payload at {entry_id}",
                anchored=False,
            )

        expected_commitment = payload_commitment(salt, entry["payload"])
        recorded_commitment = entry.get("payload_commitment", "")
        if not hmac.compare_digest(recorded_commitment, expected_commitment):
            return VerificationResult(
                False,
                f"Tampered payload detected at {entry_id}: recorded commitment '{recorded_commitment}' "
                f"does not match computed commitment '{expected_commitment}'",
                anchored=False,
            )

        # Check 6: Recompute entry hash over metadata (detect metadata tampering)
        meta = extract_metadata(entry)
        expected_hash = entry_hash(meta, recorded_commitment, recorded_prev)
        recorded_hash = entry.get("entry_hash", "")
        if not hmac.compare_digest(recorded_hash, expected_hash):
            return VerificationResult(
                False,
                f"Tampered entry or metadata detected at {entry_id}: recorded hash '{recorded_hash}' "
                f"does not match computed hash '{expected_hash}'",
                anchored=False,
            )

    # Check 7: External WORM head anchor (detects if someone truncated tip blocks)
    actual_head = chain[-1].get("entry_hash", "")
    if expected_head is not None:
        if not hmac.compare_digest(actual_head, expected_head):
            return VerificationResult(
                False,
                f"Tip truncation or head mismatch: expected head '{expected_head}', got '{actual_head}'",
                anchored=False,
                head_hash=actual_head,
            )
        return VerificationResult(
            True,
            "Chain integrity verified successfully",
            anchored=True,
            head_hash=actual_head,
        )

    return VerificationResult(
        True,
        "Chain integrity verified successfully",
        anchored=False,
        head_hash=actual_head,
    )


# ------------------------------------------------------------------------------
# 7. EXTERNAL WORM ANCHOR VERIFICATION (FIX-01)
# ------------------------------------------------------------------------------
def verify_chain_anchored(
    chain: List[Dict[str, Any]],
    worm_anchor: WORMAnchorInterface,
    incident_id: str,
    key_store: Optional[Dict[str, str]] = None,
) -> VerificationResult:
    """
    Verifies both internal hash-chain integrity and cryptographic anchoring
    against an external WORM store. Fails closed if the head hash does not match
    the anchored state.
    """
    if not chain:
        return VerificationResult(
            False,
            "Empty chain cannot be anchored",
            anchored=False,
        )

    res = verify_chain(chain=chain, key_store=key_store)
    if not res.valid:
        return res

    current_head = chain[-1].get("entry_hash", "")
    if not worm_anchor.verify_head(current_head, incident_id):
        return VerificationResult(
            valid=False,
            reason=f"WORM_ANCHOR_MISMATCH: Head hash '{current_head}' is not anchored for incident '{incident_id}'",
            anchored=False,
            head_hash=current_head,
        )

    return VerificationResult(
        valid=True,
        reason="Chain integrity and external WORM anchor verified successfully",
        anchored=True,
        head_hash=current_head,
    )
