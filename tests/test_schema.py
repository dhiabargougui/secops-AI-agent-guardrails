"""
================================================================================
TEST SUITE: IncidentHandoff Envelope v1.2.0 Schema & Boundary Contract
================================================================================
This test suite verifies the boundary contract (the 'airlock') separating:
  - Tier 1: Upstream Telemetry Ingestion & Filtering
  - Tier 2: Multi-Agent Investigation Arena

Key Invariants Enforced Here:
  1. Invariant #2 (Cognitive Anti-Anchoring):
     Triage risk metrics (s_score, theta) are strictly tagged as
     'non_evidentiary_for_agents: true' so they can be stripped before LLM prompting.
  2. Bounded Query Perimeter (Fix 8):
     The envelope MUST define 'query_perimeter' (hosts, users, time window),
     preventing autonomous agents from roaming across unapproved corporate data.
  3. Provenance & Anti-Replay:
     Requires valid UUID nonces, strict ISO-8601 date-time formats, and ratified
     signing service identities.
================================================================================
"""

import copy
import json
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

# Absolute path to the ratified JSON schema file
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "incident_handoff_v1_2_0.json"


@pytest.fixture
def schema():
    """
    Fixture: Loads the official IncidentHandoff JSON schema from disk.
    Parses it as a Python dictionary for validation with jsonschema.
    """
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def valid_inc_2026_4401_handoff():
    """
    Fixture: A complete, fully valid IncidentHandoff envelope modeling
    Walkthrough 1 (INC-2026-4401) from Section 4.5 of the v3.1 specification.

    Scenario Details:
      - Attack: Inbound spear-phishing email claiming to be 'security@micros0ft-update.com'.
      - Victim User: 'alice@company.com' (Finance Associate).
      - Victim Host: 'WS-ALICE-11' (Workstation, Asset Tier 3).
      - Triage Confidence Score: s_score = 0.82 (falls in ambiguous band [0.40, 0.85]).
      - Perimeter: Strictly bounded to WS-ALICE-11, alice, and a 72-hour lookback window.
    """
    return {
        # Contract version must strictly be 1.2.0
        "schema_version": "1.2.0",

        # Multi-tenancy isolation UUID for customer organization
        "tenant_id": "a0000000-0000-0000-0000-000000000001",

        # Unique cluster identifier grouping all correlated alerts for this incident
        "incident_cluster_id": "b0000000-0000-0000-0000-000000004401",

        # Routing Lane: Conformal score 0.82 routes to STANDARD_DEFERRAL (human/agent investigation)
        "routing_lane": "STANDARD_DEFERRAL",

        # Chronological audit timestamps in ISO-8601 format
        "timestamps": {
            "ingestion_timestamp_utc": "2026-10-24T20:12:01Z",
            "clustering_window_start_utc": "2026-10-24T20:10:00Z",
            "clustering_window_end_utc": "2026-10-24T20:12:01Z",
            "handoff_timestamp_utc": "2026-10-24T20:12:02Z"
        },

        # Original SIEM/EDR alert IDs aggregated into this cluster
        "source_alert_ids": ["ALT-2026-9921"],

        # Normalized OCSF v1.3 event objects (Email Inbound activity, class 4009)
        "normalized_ocsf_events": [
            {
                "class_uid": 4009,
                "activity_name": "Email Inbound",
                "sender": "security@micros0ft-update.com",
                "recipient": "alice@company.com"
            }
        ],

        # Graph correlation output: target asset, impacted scope, and criticality tier
        "graph_blast_radius": {
            "target_node": "WS-ALICE-11",
            "impacted_entities": ["WS-ALICE-11", "alice@company.com"],
            "asset_tier": 3  # Tier 3 = Workstation (lower operational blast radius)
        },

        # Identity context from directory service (Azure AD / Okta / LDAP)
        "identity_context": {
            "username": "alice",
            "email": "alice@company.com",
            "role": "Finance Associate"
        },

        # Process lineage tree captured by endpoint sensor (outlook -> child process)
        "process_lineage": [
            {
                "pid": 4820,
                "process_name": "outlook.exe"
            }
        ],

        # Asynchronous lookback windows applied during triage enrichment
        "lookback_windows_applied": {
            "email_domain_lookback_hours": 72
        },

        # Threat intelligence reputation lookups
        "enrichment_status": {
            "domain_reputation": "SUSPICIOUS",
            "whois_age_days": 2
        },

        # Sanitization audit flags (AIOpsShield stripped credentials / command truncation)
        "sanitization_truncation_flags": {
            "scrubbed_credentials": 0,
            "truncated_fields": []
        },

        # ----------------------------------------------------------------------
        # SAFETY GUARDRAIL (Fix 8): Scoped Query Perimeter
        # The Investigative Executor agent MUST reject any queries outside this scope.
        # ----------------------------------------------------------------------
        "query_perimeter": {
            "target_hosts": ["WS-ALICE-11"],
            "target_users": ["alice@company.com"],
            "lookback_window_start_utc": "2026-10-21T20:12:01Z",
            "lookback_window_end_utc": "2026-10-24T20:12:01Z"
        },

        # ----------------------------------------------------------------------
        # INVARIANT #2: Cognitive Anti-Anchoring
        # Triage metrics are tagged non_evidentiary_for_agents: True so they can
        # be safely stripped from LLM prompts. Agents must judge evidence independently.
        # ----------------------------------------------------------------------
        "evaluation_metadata": {
            "non_evidentiary_for_agents": True,
            "s_score": 0.82,            # Triage non-conformity score
            "theta_low": 0.40,          # Auto-close threshold
            "theta_high": 0.85,         # Expedited priority threshold
            "aact_action_rate": 0.05,   # Dynamic action frequency
            "aip_rarity_score": 0.91    # Adaptive incident prioritization rarity
        },

        # ----------------------------------------------------------------------
        # Transport Security & Authenticity
        # Cryptographically binds the handoff to the authorized triage gateway service.
        # ----------------------------------------------------------------------
        "transport_security": {
            "nonce": "c0000000-0000-0000-0000-000000000001",
            "sent_at": "2026-10-24T20:12:02Z",
            "signature": "3045022100e4b8...",
            "signer_identity": "PHASE1_FASTPATH_GATEWAY"
        }
    }


# ==============================================================================
# TEST 1: Schema Self-Validation
# ==============================================================================
def test_schema_itself_is_valid(schema):
    """
    WHAT THIS TESTS:
      Ensures that the JSON Schema file itself is syntactically valid and complies
      with the official JSON Schema Draft 2020-12 meta-specification.

    WHY IT MATTERS:
      If the schema has a typo in its definition keywords, all downstream
      validations become unreliable or crash at runtime.
    """
    Draft202012Validator.check_schema(schema)


# ==============================================================================
# TEST 2: Positive / Happy-Path Verification
# ==============================================================================
def test_positive_inc_2026_4401_validates(schema, valid_inc_2026_4401_handoff):
    """
    WHAT THIS TESTS:
      Feeds the authentic INC-2026-4401 walkthrough data into the validator.
      Uses jsonschema's FormatChecker() to strictly validate UUIDs and ISO-8601 dates.

    WHY IT MATTERS:
      Proves that a real-world, well-formed incident handoff generated by triage gateway
      is accepted by the boundary gate without false rejections.
    """
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    validator.validate(valid_inc_2026_4401_handoff)


# ==============================================================================
# TEST 3: Negative Test - Missing Query Perimeter
# ==============================================================================
def test_negative_missing_query_perimeter(schema, valid_inc_2026_4401_handoff):
    """
    WHAT THIS TESTS:
      Deletes the 'query_perimeter' block from an otherwise valid incident.

    WHY IT MATTERS (Fix 8):
      Without a perimeter, an AI agent could execute arbitrary, unconstrained
      SIEM queries across the entire company network. The schema must reject this.
    """
    payload = copy.deepcopy(valid_inc_2026_4401_handoff)
    del payload["query_perimeter"]

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    with pytest.raises(ValidationError) as exc_info:
        validator.validate(payload)
    assert "'query_perimeter' is a required property" in str(exc_info.value)


# ==============================================================================
# TEST 4: Negative Test - Anti-Anchoring Invariant Violation
# ==============================================================================
def test_negative_non_evidentiary_false(schema, valid_inc_2026_4401_handoff):
    """
    WHAT THIS TESTS:
      Attempts to set 'non_evidentiary_for_agents: False' in evaluation_metadata.

    WHY IT MATTERS (Invariant #2):
      If this flag is False, the pipeline might accidentally leak upstream triage metrics
      score (0.82) into the LLM prompts, destroying the agent's objectivity.
      The schema requires this field to be strictly enum: [true].
    """
    payload = copy.deepcopy(valid_inc_2026_4401_handoff)
    payload["evaluation_metadata"]["non_evidentiary_for_agents"] = False

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    with pytest.raises(ValidationError) as exc_info:
        validator.validate(payload)
    assert "False is not one of [True]" in str(exc_info.value) or "enum" in str(exc_info.value)


# ==============================================================================
# TEST 5: Negative Test - Unauthorized Signer Identity
# ==============================================================================
def test_negative_invalid_signer_identity(schema, valid_inc_2026_4401_handoff):
    """
    WHAT THIS TESTS:
      Attempts to supply an unapproved signer identity ('ROGUE_UNTRUSTED_AGENT').

    WHY IT MATTERS:
      Only authorized infrastructure services (PHASE1_FASTPATH_GATEWAY or
      SIGNING_SERVICE_HUNT_LEAD) are legally allowed to submit handoffs.
      Arbitrary scripts or unverified microservices must be blocked at the door.
    """
    payload = copy.deepcopy(valid_inc_2026_4401_handoff)
    payload["transport_security"]["signer_identity"] = "ROGUE_UNTRUSTED_AGENT"

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    with pytest.raises(ValidationError) as exc_info:
        validator.validate(payload)
    assert "ROGUE_UNTRUSTED_AGENT" in str(exc_info.value)


# ==============================================================================
# TEST 6: Negative Test - Invalid Ingress Vector
# ==============================================================================
def test_negative_invalid_ingress_vector(schema, valid_inc_2026_4401_handoff):
    """
    WHAT THIS TESTS:
      Adds an optional cadence profile with an invalid ingress_vector string.

    WHY IT MATTERS:
      When machine-cadence attacks occur, the ingress vector determines how
      defensive holds are applied (e.g. external firewall blocks vs endpoint isolation).
      Unknown or spoofed classifications must be rejected by the schema.
    """
    payload = copy.deepcopy(valid_inc_2026_4401_handoff)
    payload["cadence_profile"] = {
        "flags": ["CADENCE_MACHINE_SPEED"],
        "ingress_vector": "INVALID_INGRESS_VECTOR",  # Must be EXTERNAL_INGRESS, INTERNAL_ENDPOINT, or UNKNOWN
        "origin_ip": "198.51.100.22",
        "subject_entity_id": "WS-ALICE-11",
        "subject_entity_type": "HOST",
        "observed_identities": ["alice@company.com"],
        "detection_timestamp": "2026-10-24T20:12:01Z",
        "evidence_summary": {
            "primitive_a_retries": 12,
            "primitive_b_new_edges": 4,
            "overflow_fanout_count": 0,
            "corroborating_rule": "BURST_AUTH_FAILURE",
            "non_evidentiary_for_agents": True
        }
    }

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    with pytest.raises(ValidationError) as exc_info:
        validator.validate(payload)
    assert "INVALID_INGRESS_VECTOR" in str(exc_info.value)


# ==============================================================================
# TEST 7: Negative Test - Corrupted DateTime Format
# ==============================================================================
def test_negative_invalid_datetime_format(schema, valid_inc_2026_4401_handoff):
    """
    WHAT THIS TESTS:
      Supplies a non-ISO-8601 string ('not-a-datetime') for a timestamp field.

    WHY IT MATTERS:
      Strict timestamp parsing via FormatChecker prevents timezone confusion,
      clock-skew bypasses, and unparseable audit logs in downstream systems.
    """
    payload = copy.deepcopy(valid_inc_2026_4401_handoff)
    payload["timestamps"]["ingestion_timestamp_utc"] = "not-a-datetime"

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    with pytest.raises(ValidationError) as exc_info:
        validator.validate(payload)
    assert "not-a-datetime" in str(exc_info.value)


# ==============================================================================
# TEST 8: Schema v1.2.1 Strict AdditionalProperties Rejection (FIX-04)
# ==============================================================================
def test_schema_v1_2_1_validation_and_additional_properties_rejection(valid_inc_2026_4401_handoff):
    """
    Verifies that schemas/incident_handoff_v1_2_1.json is valid Draft 2020-12,
    validates envelopes with schema_version: "1.2.1", and rejects any injected
    additional top-level property (additionalProperties: false).
    """
    schema_v121_path = Path(__file__).resolve().parent.parent / "schemas" / "incident_handoff_v1_2_1.json"
    with open(schema_v121_path, "r", encoding="utf-8") as f:
        schema_v121 = json.load(f)

    # 1. Meta-validate schema structure
    Draft202012Validator.check_schema(schema_v121)

    # 2. Validate compliant v1.2.1 payload
    payload = copy.deepcopy(valid_inc_2026_4401_handoff)
    payload["schema_version"] = "1.2.1"
    validator = Draft202012Validator(schema_v121, format_checker=FormatChecker())
    validator.validate(payload)

    # 3. Inject unauthorized top-level property and verify rejection
    payload["unauthorized_injected_metric"] = "adversarial_leak"
    with pytest.raises(ValidationError) as exc_info:
        validator.validate(payload)
    assert "unauthorized_injected_metric" in str(exc_info.value)
