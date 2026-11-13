"""
================================================================================
TEST SUITE: Runtime Cognitive Anti-Anchoring Projection Layer
File: tests/test_anti_anchoring.py
================================================================================
Architectural Invariant:
  Invariant #2: Cognitive Anti-Anchoring (Section 3.2.1, Autonomous SecOps Guardrail Specification v1.0)

Purpose:
  Verifies that agent_view():
    1. Projects an unanchored view of incident handoffs to reasoning agents.
    2. Strips all evaluation metadata and conformal scores via strict allowlisting.
    3. Fails closed when non_evidentiary_for_agents is missing or False.
    4. Guarantees mutation isolation between the agent view and caller data.
    5. Recursively detects and rejects any forbidden triage metrics injected
       anywhere in nested dictionaries or lists.
================================================================================
"""

import copy
import pytest
from src.policy.anti_anchoring import (
    agent_view,
    CognitiveAnchoringLeakError,
    APPROVED_EVIDENTIARY_KEYS,
    FORBIDDEN_TRIAGE_KEYS,
)


# ==============================================================================
# FIXTURE: Authentic Upstream Triage Incident Handoff Envelope
# ==============================================================================

@pytest.fixture
def sample_handoff_envelope():
    """
    Constructs an authentic handoff envelope matching schema v1.2.0,
    containing both evidentiary telemetry and non-evidentiary triage metadata.
    """
    return {
        "schema_version": "1.2.0",
        "tenant_id": "e4b3c2a1-0000-4000-8000-000000000001",
        "incident_cluster_id": "f5a2b1c0-1111-4000-8000-000000000002",
        "routing_lane": "EXPEDITED_PRIORITY",
        "timestamps": {
            "ingestion_timestamp_utc": "2026-10-24T20:12:00Z",
            "clustering_window_start_utc": "2026-10-24T20:10:00Z",
            "clustering_window_end_utc": "2026-10-24T20:12:00Z",
            "handoff_timestamp_utc": "2026-10-24T20:12:02Z",
        },
        "source_alert_ids": ["ALT-001", "ALT-002"],
        "normalized_ocsf_events": [
            {
                "class_uid": 4001,
                "activity_id": 1,
                "message": "Suspicious OAuth application consent granted",
                "actor": {"user": {"name": "alice@enterprise.com"}}
            }
        ],
        "graph_blast_radius": {
            "seed_entity_id": "WS-ALICE-11",
            "entity_type": "ENDPOINT",
            "k_hop_depth": 2,
            "connected_identities": ["alice@enterprise.com"]
        },
        "identity_context": {
            "account_name": "alice@enterprise.com",
            "department": "Engineering",
            "is_privileged": False
        },
        "process_lineage": {
            "process_name": "chrome.exe",
            "process_id": 4812,
            "parent_process": "explorer.exe"
        },
        "lookback_windows_applied": {
            "identity_auth_window_hours": 72,
            "network_egress_window_hours": 24
        },
        "enrichment_status": "COMPLETED",
        "sanitization_truncation_flags": {
            "truncated": False,
            "pii_scrubbed": True
        },
        "query_perimeter": {
            "anchor_entity_id": "WS-ALICE-11",
            "lookback_minutes": 120,
            "permissible_tables": ["entra_oauth_logs", "proxy_egress_logs"]
        },
        # NON-EVIDENTIARY TRIAGE BLOCK: Must be stripped by agent_view()
        "evaluation_metadata": {
            "non_evidentiary_for_agents": True,
            "s_score": 0.885,
            "theta_low": 0.350,
            "theta_high": 0.750,
            "aact_action_rate": 0.12,
            "aip_rarity_score": 8.4
        },
        "transport_security": {
            "nonce": "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
            "sent_at": "2026-10-24T20:12:02Z",
            "signature": "mock-signature-bytes-phase1",
            "signer_identity": "PHASE1_FASTPATH_GATEWAY"
        }
    }


# ==============================================================================
# SECTION 1: PROJECTION INTEGRITY & ALLOWLIST ENFORCEMENT
# ==============================================================================

def test_valid_agent_view_projection(sample_handoff_envelope):
    """
    Verifies that agent_view() projects only evidentiary fields and completely
    omits the evaluation_metadata block and all triage scores.
    """
    view = agent_view(sample_handoff_envelope)

    # 1. Assert evidentiary fields survive with full fidelity
    assert view["tenant_id"] == "e4b3c2a1-0000-4000-8000-000000000001"
    assert view["routing_lane"] == "EXPEDITED_PRIORITY"
    assert view["query_perimeter"]["anchor_entity_id"] == "WS-ALICE-11"
    assert len(view["normalized_ocsf_events"]) == 1

    # 2. Assert evaluation metadata block is completely absent
    assert "evaluation_metadata" not in view
    assert "initial_triage" not in view

    # 3. Assert no forbidden keys exist at the top level
    for forbidden in FORBIDDEN_TRIAGE_KEYS:
        assert forbidden not in view


def test_mutation_isolation(sample_handoff_envelope):
    """
    Verifies that mutating the returned agent_view does NOT corrupt or modify
    the caller's original handoff envelope (strict deep-copy isolation).
    """
    view = agent_view(sample_handoff_envelope)

    # Mutate top-level and nested structures in the projected view
    view["routing_lane"] = "MUTATED_LANE"
    view["query_perimeter"]["lookback_minutes"] = 99999
    view["normalized_ocsf_events"].append({"class_uid": 9999, "activity_id": 99})

    # Assert original handoff is completely unchanged
    assert sample_handoff_envelope["routing_lane"] == "EXPEDITED_PRIORITY"
    assert sample_handoff_envelope["query_perimeter"]["lookback_minutes"] == 120
    assert len(sample_handoff_envelope["normalized_ocsf_events"]) == 1


def test_legacy_initial_triage_key_support(sample_handoff_envelope):
    """
    Verifies support for handoffs named 'initial_triage' instead of 'evaluation_metadata',
    ensuring it is safely quarantined and stripped.
    """
    handoff = copy.deepcopy(sample_handoff_envelope)
    handoff["initial_triage"] = handoff.pop("evaluation_metadata")

    view = agent_view(handoff)
    assert "initial_triage" not in view
    assert "evaluation_metadata" not in view
    assert view["tenant_id"] == handoff["tenant_id"]


# ==============================================================================
# SECTION 2: FAIL-CLOSED PRECONDITION CHECKS
# ==============================================================================

def test_missing_triage_block_rejected(sample_handoff_envelope):
    """
    Fails closed if the envelope lacks an evaluation_metadata / initial_triage block.
    """
    handoff = copy.deepcopy(sample_handoff_envelope)
    del handoff["evaluation_metadata"]

    with pytest.raises(ValueError, match="Missing required 'evaluation_metadata' / 'initial_triage' block"):
        agent_view(handoff)


def test_missing_non_evidentiary_flag_rejected(sample_handoff_envelope):
    """
    Fails closed if the non_evidentiary_for_agents flag is missing from triage block.
    """
    handoff = copy.deepcopy(sample_handoff_envelope)
    del handoff["evaluation_metadata"]["non_evidentiary_for_agents"]

    with pytest.raises(ValueError, match="'non_evidentiary_for_agents' must be strictly True"):
        agent_view(handoff)


def test_false_non_evidentiary_flag_rejected(sample_handoff_envelope):
    """
    Fails closed if non_evidentiary_for_agents is False.
    """
    handoff = copy.deepcopy(sample_handoff_envelope)
    handoff["evaluation_metadata"]["non_evidentiary_for_agents"] = False

    with pytest.raises(ValueError, match="'non_evidentiary_for_agents' must be strictly True"):
        agent_view(handoff)


def test_non_dict_handoff_rejected():
    """
    Fails closed if input handoff is not a dictionary.
    """
    with pytest.raises(ValueError, match="Handoff must be a dictionary"):
        agent_view("not_a_dict")

    with pytest.raises(ValueError, match="Handoff must be a dictionary"):
        agent_view(None)


# ==============================================================================
# SECTION 3: RECURSIVE LEAK GUARD SECURITY TESTS
# ==============================================================================

def test_nested_leak_guard_catches_s_score_in_query_perimeter(sample_handoff_envelope):
    """
    Verifies that if s_score is injected into a nested dictionary (e.g. query_perimeter),
    the recursive leak guard intercepts it and raises CognitiveAnchoringLeakError.
    """
    poisoned_handoff = copy.deepcopy(sample_handoff_envelope)
    poisoned_handoff["query_perimeter"]["s_score"] = 0.999

    with pytest.raises(CognitiveAnchoringLeakError, match="Forbidden triage metric 's_score' detected"):
        agent_view(poisoned_handoff)


def test_nested_leak_guard_catches_theta_in_list(sample_handoff_envelope):
    """
    Verifies that if a conformal threshold (theta_high) is injected inside a list
    (e.g. normalized_ocsf_events), the leak guard detects it.
    """
    poisoned_handoff = copy.deepcopy(sample_handoff_envelope)
    poisoned_handoff["normalized_ocsf_events"][0]["injected_metric"] = {
        "theta_high": 0.85
    }

    with pytest.raises(CognitiveAnchoringLeakError, match="Forbidden triage metric 'theta_high' detected"):
        agent_view(poisoned_handoff)


def test_nested_leak_guard_catches_custom_theta_pattern(sample_handoff_envelope):
    """
    Verifies that if an unlisted conformal threshold matching pattern (e.g. theta_custom_99)
    is injected, the pattern leak guard detects it.
    """
    poisoned_handoff = copy.deepcopy(sample_handoff_envelope)
    poisoned_handoff["normalized_ocsf_events"][0]["injected_metric"] = {
        "theta_custom_99": 0.50
    }

    with pytest.raises(CognitiveAnchoringLeakError, match="Conformal threshold key 'theta_custom_99' detected"):
        agent_view(poisoned_handoff)


def test_nested_leak_guard_catches_aip_rarity_score(sample_handoff_envelope):
    """
    Verifies detection of aip_rarity_score nested in process_lineage.
    """
    poisoned_handoff = copy.deepcopy(sample_handoff_envelope)
    poisoned_handoff["process_lineage"]["aip_rarity_score"] = 9.9

    with pytest.raises(CognitiveAnchoringLeakError, match="Forbidden triage metric 'aip_rarity_score' detected"):
        agent_view(poisoned_handoff)


def test_string_value_leak_guard_catches_embedded_score(sample_handoff_envelope):
    """
    Verifies that embedding triage metric assignments in free-form string values
    (e.g. notes: 's_score=0.99') is caught by the scoped value scanner (FIX-04/FIX-05).
    """
    # Embedded s_score in query perimeter notes
    poisoned = copy.deepcopy(sample_handoff_envelope)
    poisoned["query_perimeter"]["notes"] = "Investigation context: suspicious lead with s_score=0.99"
    with pytest.raises(CognitiveAnchoringLeakError, match="Forbidden triage score assignment"):
        agent_view(poisoned)

    # Embedded theta_high in event message
    poisoned2 = copy.deepcopy(sample_handoff_envelope)
    poisoned2["normalized_ocsf_events"][0]["message"] = "Alert triggered under theta_high: 0.85"
    with pytest.raises(CognitiveAnchoringLeakError, match="Forbidden triage score assignment"):
        agent_view(poisoned2)


def test_schema_version_support_and_rejection(sample_handoff_envelope):
    """
    Verifies support for v1.2.0 and v1.2.1 schema versions, and rejection of unknown versions.
    """
    # v1.2.1 is accepted
    handoff_v121 = copy.deepcopy(sample_handoff_envelope)
    handoff_v121["schema_version"] = "1.2.1"
    view = agent_view(handoff_v121)
    assert view["schema_version"] == "1.2.1"

    # Unsupported version is rejected fail-closed
    handoff_v2 = copy.deepcopy(sample_handoff_envelope)
    handoff_v2["schema_version"] = "2.0.0"
    with pytest.raises(ValueError, match="Unsupported schema version: '2.0.0'"):
        agent_view(handoff_v2)


# ==============================================================================
# SECTION: FAIL-CLOSED BRANCH COVERAGE (FIX-09)
# ==============================================================================

def test_leak_guard_catches_suspicion_score_and_triage_score(sample_handoff_envelope):
    """
    Verifies that keys ending in _score or named suspicion_score/triage_score
    are detected and rejected by the recursive leak guard.
    """
    p1 = copy.deepcopy(sample_handoff_envelope)
    p1["query_perimeter"]["suspicion_score"] = 0.88
    with pytest.raises(CognitiveAnchoringLeakError, match="Triage scoring key 'suspicion_score' detected"):
        agent_view(p1)

    p2 = copy.deepcopy(sample_handoff_envelope)
    p2["identity_context"]["triage_score"] = 0.75
    with pytest.raises(CognitiveAnchoringLeakError, match="Triage scoring key 'triage_score' detected"):
        agent_view(p2)
