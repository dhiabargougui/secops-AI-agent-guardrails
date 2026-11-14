# Autonomous SecOps Guardrails & Cryptographic Audit Engine

Deterministic policy-as-code (OPA/Rego), cryptographic evidence ledger, and safety enforcement middleware for autonomous security operations.

---

## 1. Executive overview and problem statement

Enterprise Security Operations Centers (SOCs) face overwhelming alert volume and human triage fatigue, while machine-cadence attacks pivot across networks in seconds. Autonomous AI agents offer automated reasoning, but deploying generative models directly into production networks creates severe operational hazards: prompt injection from untrusted telemetry, hallucinated incident severity, and accidental self-inflicted outages (such as isolating a domain controller or critical database).

This repository implements and verifies the deterministic cryptographic, mathematical, and policy enforcement boundaries required to safely govern autonomous security operations. Sitting as an independent middleware layer between upstream detection/AI reasoning agents and enterprise infrastructure APIs (EDR, cloud APIs, IAM), the engine enforces five core architectural invariants:

1. **Actuation integrity:** Containment actuation can only originate from an authorized Policy Enforcement Point (PEP) evaluation. Reasoning agents possess zero direct execution credentials. Infrastructure modifications are governed through HMAC-signed containment orders verified by an in-network Order Executor with anti-replay and clock-skew protections.
2. **Cognitive anti-anchoring:** Triage heuristic scores, conformal non-conformity values, and classification thresholds are strictly projected out of agent intake handoffs. Agents audit concrete, verified telemetry observables rather than inheriting biased upstream statistical priors.
3. **Cryptographic audit ledger:** Every observation, hypothesis, telemetry query, and containment decision is committed to an append-only, tamper-evident hash chain using HMAC-SHA256 payload commitments, per-entry external KMS salts, and WORM-anchored verification.
4. **Hard autonomy ceiling ($C_A \ge 4$):** High-disruption containment actions (isolating Tier 0/1/2 hosts, disabling accounts, revoking Tier 0 sessions) are strictly barred from autonomous execution. This front-line rule overrides risk scores, model confidence, and out-of-band user fraud denials.
5. **Pre-release safety gate:** Tier 0 and Tier 1 critical assets are barred from automated closure during initial triage. Releasing holds or dismissing incidents on critical assets strictly requires Four-Eyes dual control ($E_1 \neq E_2$) from two authenticated humans, with escalation to the on-call SOC Manager upon review timeout ($T_{\text{4eyes}} = 900\,\text{s}$).

---

## 2. Verification summary and test accounting

Every component executes locally without external cloud dependencies, Docker, or live LLM network calls.

- **Pytest test suite:** 735 passed (100% green across 10 test modules).
- **Native OPA Rego test suite:** 21 passed (`policies/soc_containment_test.rego`).
- **Total passing tests:** 756 tests.
- **Code coverage:** 94% across `src/` (672 statements, 40 misses).
- **Differential parity:** 504-case full Cartesian product verified between Python reference formulas and compiled OPA Rego policy.

```
Name                           Stmts   Miss  Cover
--------------------------------------------------
src/execution/actuator.py         84      0   100%
src/ledger/chain.py              153     18    88%
src/policy/anti_anchoring.py      53      1    98%
src/policy/pep_gate.py            91      7    92%
src/policy/release_gate.py       121      1    99%
src/policy/rsem.py               170     13    92%
--------------------------------------------------
TOTAL                            672     40    94%
```

---

## 3. Architecture diagrams

The system architecture and formal verification layers are illustrated in three standalone SVG diagrams:

1. [Cryptographic Evidence Ledger (Invariant #3)](diagrams/ledger_hash_chain.svg): Illustrates HMAC-SHA256 payload commitments, metadata binding, SHA-256 block linking, external KMS salt isolation, and WORM head anchors.
2. [RSEM Decision Matrix (Invariant #4)](diagrams/rsem_decision_matrix.svg): Maps the 4 decision zones, the front-line $C_A \ge 4$ Hard Autonomy Ceiling, and the 3-state out-of-band identity attestation lifecycle.
3. [Five Core Architectural Invariants: Defense-in-Depth](diagrams/invariants_defense_in_depth.svg): Illustrates the multi-layered defense model from intake anti-anchoring to final four-eyes release gates.

---

## 4. Quickstart and reproduction instructions

The test harness runs identically on Linux, macOS, and Windows.

### Prerequisites

- Python 3.12+
- Open Policy Agent (OPA) v1.x binary:
  - **Linux / macOS:** Installed to system PATH (e.g., `/usr/local/bin/opa` or via package manager).
  - **Windows:** Pre-staged in `tools/opa.exe` or installed to system PATH. Note: In restricted virtualization sandboxes, execute with standard execution permissions due to Go runtime DLL relocation.

### Setup (Linux / macOS)

```bash
# 1. Clone repository
git clone https://github.com/dhiabargougui/secops-AI-agent-guardrails.git
cd secops-AI-agent-guardrails

# 2. Set up Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 4. Install OPA binary (if not already installed)
curl -L -o /usr/local/bin/opa https://github.com/open-policy-agent/opa/releases/download/v1.2.0/opa_linux_amd64_static
chmod +x /usr/local/bin/opa

# 5. Run tests
opa test policies/ -v
pytest -v
```

### Setup (Windows PowerShell)

```powershell
# 1. Set up Python virtual environment
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 3. Run native OPA policy tests (system PATH or pre-staged binary)
opa test policies/ -v
# or if using a repo-local binary:
# .\tools\opa.exe test policies/ -v

# 4. Run full pytest suite with coverage
pytest --cov=src -v
```

---

## 5. Invariant-to-test mapping matrix

Every architectural safety invariant is paired with dedicated automated tests:

| Invariant | Description | Implementation File | Verification Test Suite |
| :--- | :--- | :--- | :--- |
| **#1 Actuation Integrity** | Zero-credential agents; actuation requires signed orders bound to PEP `ALLOW` receipts with anti-replay nonces and clock bounds. | `src/execution/actuator.py` | `tests/test_invariants.py::TestInvariant1ActuationIntegrity` |
| **#2 Cognitive Anti-Anchoring** | Strips heuristic non-conformity scores and thresholds from intake payloads; recursive scan rejects smuggled keys. | `src/policy/anti_anchoring.py` | `tests/test_anti_anchoring.py`, `tests/test_invariants.py::TestInvariant2AntiAnchoring` |
| **#3 Cryptographic Ledger** | Append-only hash chain with HMAC commitments, isolated KMS salts, and WORM head verification. | `src/ledger/chain.py` | `tests/test_chain.py`, `tests/test_walkthroughs.py`, `tests/test_invariants.py::TestInvariant3LedgerTamperResistance` |
| **#4 Hard Autonomy Ceiling** | Disruption cost $C_A \ge 4$ strictly requires human approval. Raise-only severity (C_I = max(C_I,base, C_I(finding_class))). | `src/policy/rsem.py`, `policies/soc_containment.rego`, `src/policy/pep_gate.py` | `tests/test_rsem.py`, `tests/test_pep_gate.py`, `tests/test_invariants.py::TestInvariant4AutonomyCeilingAndSeverity` |
| **#5 Pre-Release Safety** | Tier 0/1 critical assets barred from automated close. Hold releases require Four-Eyes dual control ($E_1 \neq E_2$). | `src/policy/release_gate.py` | `tests/test_invariants.py::TestInvariant5PreReleaseSafety` |

---

## 6. Golden calculations and reference derivations

The Relative Severity Engine Model (RSEM) computes an operational risk score:

$$\text{RSEM} = 100 \times \frac{P \times C_I}{P \times C_I + C_A}$$

Where:
- $P \in [0, 1]$: Calibrated model confidence.
- $C_I \in [1, 10]$: Incident severity (governed by monotonic raise-only rules).
- $C_A \in [1, 10]$: Cost of action / operational disruption catalog.

### Decision matrix and boundary rules

| Zone | Condition | Default Decision | Special Governance Rules |
| :--- | :--- | :--- | :--- |
| **Hard Ceiling** | $C_A \ge 4$ | `ESCALATE` | Front-line override. Bars autonomous actuation across all RSEM and out-of-band states. |
| **Zone 1 (High Conviction)** | $\text{RSEM} \ge 75$ | `ALLOW` | Autonomous execution permitted. |
| **Zone 2 (Triage Ambiguity)** | $50 \le \text{RSEM} < 75$ | Identity-dependent | `PENDING`: Enforce step-up authentication.<br>`DENIED_BY_USER`: Autonomous allow.<br>`CONFIRMED_LEGITIMATE`: Stand down (`DENY`).<br>Non-identity finding: `ESCALATE`. |
| **Zone 3 (Low Conviction)** | $\text{RSEM} < 50$ | `ESCALATE` | Insufficient conviction for automated disruption; escalate to human analyst. |

### End-to-end benchmark scenarios

| Scenario | Model Conf ($P$) | Severity ($C_I$) | Disruption ($C_A$) | RSEM Score | Decision | Policy Trigger Reason |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Scenario 1: Phishing Isolate Host** | 0.990 | 8 | 2 | **79.84** (79.9) | `ALLOW` | `ZONE1_AUTONOMOUS_ALLOW` |
| **Scenario 1: Phishing Purge Message** | 0.990 | 8 | 1 | **88.79** (88.8) | `ALLOW` | `ZONE1_AUTONOMOUS_ALLOW` |
| **Scenario 1: Counterfactual (Omitting finding)** | 0.990 | 5 | 2 | **71.22** (71.3) | `ESCALATE` | `ZONE2_NON_IDENTITY_ESCALATE` |
| **Scenario 2: Lateral Movement Isolate Tier 1 Host** | 0.965 | 9 | 9 | **49.11** | `ESCALATE` | `HARD_AUTONOMY_CEILING_EXCEEDED` |
| **Scenario 2: Lateral Movement Revoke Sessions** | 0.965 | 9 | 3 | **74.33** | `ALLOW` | `ZONE2_POST_DENIAL_ALLOW` |
| **Scenario 2: Lateral Movement Block IOC** | 0.965 | 9 | 2 | **81.28** (81.3) | `ALLOW` | `ZONE1_AUTONOMOUS_ALLOW` |
| **Scenario 2: Lateral Movement Disable Account** | 0.965 | 9 | 6 | **59.14** | `ESCALATE` | `HARD_AUTONOMY_CEILING_EXCEEDED` |

---

## 7. Scope boundaries: implemented middleware vs. production infrastructure

To keep this proof of work clean, reproducible, and self-contained, implementation boundaries are explicitly defined:

| Capability | In-Scope Proof of Work Implementation | Production Infrastructure Extension |
| :--- | :--- | :--- |
| **Policy Evaluation** | In-process Python reference evaluator + embedded OPA binary subprocess. | Distributed OPA daemon / Envoy external authorization sidecar. |
| **Evidence Ledger** | In-memory append-only chain with SHA-256 verification, per-entry KMS salts, and external WORM head hashes. | Append-only database (Amazon QLDB, immudb) with S3 Object Lock. |
| **KMS Key Management** | Ephemeral 32-byte cryptographically secure random bytes (`secrets.token_bytes`). | Hardware Security Module (AWS KMS, GCP Cloud KMS, HashiCorp Vault). |
| **Actuator Execution** | Simulated executor validating cryptographic HMAC receipts, anti-replay nonces, and clock skew. | Dedicated SOAR workers with mutual TLS (mTLS) to EDR, Cloud APIs, and IAM. |
| **Four-Eyes Sign-off** | Cryptographic dual control verifying distinct approver keys, role authorization, and nonces. | Enterprise IdP (Okta / Entra ID) with FIDO2 WebAuthn authentication. |

---

## 8. Architecture records and verification reports

The technical architecture records, verification proofs, and peer review audits are maintained in this repository:

- Formal verification report: [`VERIFICATION_REPORT.md`](VERIFICATION_REPORT.md)
- Architecture decisions log: [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md)
- Adversarial review verification and audit trail: [`docs/REVIEW_VERIFICATION.md`](docs/REVIEW_VERIFICATION.md)
- Comprehensive technical report: [`docs/AGENT_REVIEW_REPORT.md`](docs/AGENT_REVIEW_REPORT.md)

---

## 9. License

This project is licensed under the Apache 2.0 License.
