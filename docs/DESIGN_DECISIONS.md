# Architecture Decision Record: Cryptographic Evidence Ledger

**Document:** `docs/DESIGN_DECISIONS.md`  
**Governing Architectural Invariant:** Invariant #3 (Single Source of Truth / Cryptographic Audit Ledger)  
**System Phase:** Investigation (Dialectical Multi-Agent Investigation Arena)  
**Specification Reference:** Section 4.2 & Listing 2 (Autonomous SecOps Guardrail Specification v1.0)  
**Status:** Ratified & Locked

---

## Executive Summary: What is this document and why does it exist?

In the AI SOC platform, multiple autonomous AI agents (the Planner, Investigator, Adversary, and Judge) collaborate to investigate security incidents. Rather than communicating over an unstructured chat thread, all agent reasoning, forensic findings, objections, and judicial remands are recorded in an **immutable, hash-linked cryptographic ledger**.

While the 118-page specification defines the overall ledger structure ($\mathcal{H}_k$), it intentionally leaves several low-level cryptographic implementation details to the engineering team. In cryptography, if two systems serialize data with even a single extra space or a different key ordering, their SHA-256 hashes will differ, breaking verification.

This document formally locks **four architectural decisions** to ensure bit-for-bit determinism, cross-platform reproducibility, and tamper-resistance across the entire platform.

---

## Decision 1: Canonical Metadata Serialization

### The Problem
A JSON object like `{"b": 1, "a": 2}` can be serialized in multiple ways:
- Different key orderings: `{"a":2,"b":1}` vs `{"b":1,"a":2}`
- Whitespace variations: `{"a": 2}` vs `{"a":2}`
- Character encoding differences: Unicode escape sequences (`\u00e9`) vs raw UTF-8 bytes (`é`).

If two nodes format JSON slightly differently, their calculated SHA-256 hashes will not match, causing false tamper alarms.

### The Decision
All metadata dictionaries are serialized using Python's standard `json.dumps()` configured with strict canonical flags:

```python
canonical_metadata_bytes = json.dumps(
    metadata_dict,
    sort_keys=True,               # 1. Alphabetically sort all keys
    separators=(",", ":"),        # 2. Strip all unnecessary spaces after commas and colons
    ensure_ascii=False            # 3. Preserve raw UTF-8 characters instead of \uXXXX escapes
).encode("utf-8")                 # 4. Output deterministic raw UTF-8 bytes
```

### Scope: Which fields are included?
The canonical metadata dictionary strictly includes:
1. `entry_id` (e.g., `"LEDGER_000"`, `"LEDGER_001"`)
2. `investigation_id` (UUID string identifying the incident investigation)
3. `tenant_id` (UUID string ensuring multi-tenant isolation)
4. `timestamp_utc` (ISO-8601 string, e.g., `"2026-10-24T20:12:05Z"`)
5. `agent_role` (e.g., `"ROLE_PLANNER"`, `"ROLE_INVESTIGATOR"`, `"ROLE_ADVERSARY"`, `"ROLE_JUDGE"`)
6. `skill_invoked` (e.g., `"PROPOSE_HYPOTHESIS"`, `"QUERY_TELEMETRY"`, `"ENTER_OBJECTION"`)
7. `target_checklist_item` (e.g., `"CHK_001"` or `None`)
8. `prev_entry_hash` (hex hash of prior block, or 64 null zeros for Genesis block)

### Scope: Which fields are EXCLUDED?
The following fields are strictly **excluded** from the metadata dictionary before hashing:
- `entry_hash`: Excluded because a block cannot calculate its own hash while including its hash (prevents circular dependency).
- `per_entry_salt`: Excluded because the secret salt must be kept separate from the public metadata.
- `payload_commitment`: Excluded from metadata because it is bound separately into the entry hash.
- `payload`: Excluded because it is sealed inside the payload commitment (Equation 14).
- `signature`: Excluded because digital signatures are applied after the block is hashed and closed.

---

## Decision 2: Genesis Block `prev_entry_hash`

### The Problem
Every block in a hash chain contains a field called `prev_entry_hash` pointing to the hash of the block before it. But what does the very first block (`LEDGER_000`, the "Genesis" block) point to, since there is no block before it?

### The Decision
The genesis block's `prev_entry_hash` is explicitly defined as **64 hexadecimal zeros**:

```python
GENESIS_PREV_HASH = "0" * 64
# "0000000000000000000000000000000000000000000000000000000000000000"
```

### Rationale
- This follows the standard convention used by cryptographic hash chains (such as Git's null tree and Certificate Transparency RFC 6962).
- It provides a constant, unambiguous anchor: when the chain validator examines `LEDGER_000`, it asserts that `prev_entry_hash == GENESIS_PREV_HASH`. Any other value is rejected.

---

## Decision 3: Hash Input Concatenation & Byte Structure

### The Problem
The specification states the mathematical entry hash formula:
$$\mathcal{H}_k = \text{SHA-256}(\text{canonical\_metadata} \parallel \text{commitment} \parallel \mathcal{H}_{k-1})$$

We must define whether the inputs are concatenated as plain text strings or as raw binary bytes. String concatenation can introduce encoding ambiguities, whereas raw binary concatenation is mathematically unambiguous and compact.

### The Decision
All three components are concatenated as **raw bytes** before being passed to the SHA-256 hashing function:

```python
hash_input = (
    metadata_bytes +                   # 1. Canonical metadata UTF-8 bytes
    bytes.fromhex(payload_commitment) +# 2. 32 raw bytes decoded from 64-char hex commitment
    bytes.fromhex(prev_entry_hash)     # 3. 32 raw bytes decoded from 64-char hex previous hash
)
entry_hash = hashlib.sha256(hash_input).hexdigest()
```

### Rationale
- `payload_commitment` and `prev_entry_hash` are 64-character hexadecimal strings. Decoding them via `bytes.fromhex()` converts them into their true 32-byte binary representations.
- This prevents string-level variations (e.g. uppercase vs lowercase hex) from corrupting hash calculations and ensures strict cryptographic precision.

---

## Decision 4: Payload Commitment Formula (Equation 14)

### The Problem
The investigation payload (e.g., an agent's hypothesis, query evidence, or objection) can be large. If the full payload were included directly in the block's main hash, verifying and querying the ledger would require loading all raw data into memory. Furthermore, agents need a way to commit to their findings without prematurely exposing raw payload content.

### The Decision
Equation 14 of the specification is implemented using **HMAC-SHA256**:

$$\text{commitment} = \text{HMAC-SHA256}(\text{key}=\text{bytes.fromhex}(\text{per\_entry\_salt}),\ \text{msg}=\text{canonical\_payload\_bytes})$$

```python
# 1. Generate or receive a 32-byte secret salt (64-character hex string)
salt_bytes = bytes.fromhex(per_entry_salt)

# 2. Canonically serialize the payload (dict, list, or string)
payload_bytes = canonicalize_json(payload)

# 3. Calculate HMAC-SHA256 digest
payload_commitment = hmac.new(salt_bytes, payload_bytes, hashlib.sha256).hexdigest()
```

### Rationale
- **Secret Salt:** Each block generates a cryptographically secure 32-byte random salt (`secrets.token_bytes(32).hex()`). For deterministic regression tests and walkthrough fixtures, the salt can be explicitly supplied.
- **Tamper Evidence:** Because the HMAC uses both the secret salt and the payload, an attacker cannot modify the payload without either breaking HMAC-SHA256 or knowing the secret salt.
- **Sealed Commitments:** This allows an agent to publish a commitment to its finding first, proving it has not altered its conclusion later.

---

## 4. Chain Verification Rules

When the verification engine (`verify_chain`) evaluates a chain:
1. **Monotonic IDs:** IDs must strictly match regex `^LEDGER_\d{3,}$` and increment sequentially (`000`, `001`, `002`... with zero gaps and no sub-indices like `LEDGER_003_OBJ`).
2. **Deterministic Re-computation:** For every entry, the validator independently recalculates the Equation 14 commitment and the entry hash, checking that both match the recorded values.
3. **Constant-Time Comparison:** All hash and commitment comparisons use Python's `hmac.compare_digest` to prevent timing-attack side-channels.
4. **Tail Truncation Detection:** A hash chain alone cannot detect if the latest entries were deleted from the tail (because blocks 0 through $k-1$ still form a valid chain). To solve this, `verify_chain(chain, expected_head=...)` accepts an optional `expected_head` parameter. In production, this expected head hash is anchored to Write-Once-Read-Many (WORM) cloud storage.

