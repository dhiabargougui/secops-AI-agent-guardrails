"""
================================================================================
RUNTIME COGNITIVE ANTI-ANCHORING PROJECTION LAYER
File: src/policy/anti_anchoring.py
================================================================================
Architectural Invariant:
  Invariant #2: Cognitive Anti-Anchoring (Section 3.2.1, Autonomous SecOps Guardrail Specification v1.0)

Purpose:
  Enforces a strict runtime airlock boundary between Upstream Telemetry Triage and Autonomous Agent Investigation.

  Autonomous LLM investigation agents (Planner, Investigator, Adversary, Judge)
  must reason purely from raw evidentiary facts (OCSF telemetry, query perimeters,
  graph topologies, identity context). They must NEVER observe triage risk metrics
  (e.g., s_score, theta_high, theta_low, aip_rarity_score) that could induce
  confirmation bias or cognitive anchoring.

Security Architecture:
  1. Fail-Closed Precondition: Validates that the handoff envelope explicitly
     asserts 'non_evidentiary_for_agents: true'. Fails closed otherwise.
  2. Strict Allowlist Projection: Constructs the agent view exclusively from an
     explicit allowlist of evidentiary fields, completely omitting triage blocks.
  3. Recursive Leak Guard: Deeply traverses every nested dictionary and list in
     the projected output to mathematically prove zero forbidden triage keys leak
     into the agent prompt context.
================================================================================
"""

import copy
import re
from typing import Any, Dict, List, Set


# ==============================================================================
# SECURITY EXCEPTIONS & CONTRACT CONSTANTS
# ==============================================================================

class CognitiveAnchoringLeakError(ValueError):
    """Raised when a forbidden triage metric leaks into an agent view projection."""
    pass


# Strict allowlist of top-level evidentiary keys permissible in agent context.
# Any key not explicitly listed here is excluded during projection.
APPROVED_EVIDENTIARY_KEYS: Set[str] = {
    "schema_version",
    "incident_id",
    "incident_cluster_id",
    "tenant_id",
    "routing_lane",
    "timestamps",
    "source_alert_ids",
    "normalized_ocsf_events",
    "graph_blast_radius",
    "identity_context",
    "process_lineage",
    "lookback_windows_applied",
    "enrichment_status",
    "sanitization_truncation_flags",
    "query_perimeter",
    "cadence_profile",
    "transport_security",
    "observables",
    "metadata",
}

# Triage block names in the handoff envelope
TRIAGE_BLOCK_KEYS: Set[str] = {
    "evaluation_metadata",
    "initial_triage",
}

# Specific forbidden metric keys that must never appear anywhere in agent view
FORBIDDEN_TRIAGE_KEYS: Set[str] = {
    "s_score",
    "aip_score",
    "aip_rarity_score",
    "aact_action_rate",
    "theta_low",
    "theta_high",
    "theta_admit",
    "theta_defer",
    "non_evidentiary_for_agents",
}

# Regex pattern matching any theta threshold variants (e.g. theta_*, theta)
THETA_PATTERN: re.Pattern = re.compile(r"^theta(_.*)?$", re.IGNORECASE)

# Regex pattern matching embedded triage metric assignments in string values (FIX-04 / FIX-05)
TRIAGE_ASSIGNMENT_PATTERN: re.Pattern = re.compile(
    r"\b(?:s_score|aip_score|aip_rarity_score|theta_high|theta_low|theta_admit|theta_defer)\s*[:=]",
    re.IGNORECASE,
)

# Supported airlock contract schema versions
SUPPORTED_SCHEMA_VERSIONS: Set[str] = {"1.2.0", "1.2.1"}


# ==============================================================================
# RECURSIVE LEAK GUARD
# ==============================================================================

def assert_no_triage_leaks(node: Any, current_path: str = "$") -> None:
    """
    Recursively inspects an object tree (dicts, lists, primitives) to guarantee
    that no forbidden triage metrics, suspicion scores, or conformal thresholds
    exist anywhere in the data structure.
    
    Raises:
      CognitiveAnchoringLeakError: If any forbidden key is detected.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            key_str = str(key)
            field_path = f"{current_path}.{key_str}"

            # 1. Exact match against forbidden key catalog
            if key_str.lower() in FORBIDDEN_TRIAGE_KEYS:
                raise CognitiveAnchoringLeakError(
                    f"Invariant #2 Breach: Forbidden triage metric '{key_str}' detected at '{field_path}'."
                )

            # 2. Pattern match against any theta threshold
            if THETA_PATTERN.match(key_str):
                raise CognitiveAnchoringLeakError(
                    f"Invariant #2 Breach: Conformal threshold key '{key_str}' detected at '{field_path}'."
                )

            # 3. Pattern match against suspicion score fields
            if key_str.lower() == "s_score" or key_str.lower().endswith("_score"):
                if key_str.lower() in ("s_score", "aip_score", "suspicion_score", "triage_score"):
                    raise CognitiveAnchoringLeakError(
                        f"Invariant #2 Breach: Triage scoring key '{key_str}' detected at '{field_path}'."
                    )

            # Recurse into child
            assert_no_triage_leaks(value, field_path)

    elif isinstance(node, list):
        for index, item in enumerate(node):
            assert_no_triage_leaks(item, f"{current_path}[{index}]")

    elif isinstance(node, str):
        if TRIAGE_ASSIGNMENT_PATTERN.search(node):
            raise CognitiveAnchoringLeakError(
                f"Invariant #2 Breach: Forbidden triage score assignment detected in string value at '{current_path}': '{node}'."
            )


# ==============================================================================
# AIRLOCK PROJECTION: AGENT_VIEW()
# ==============================================================================

def agent_view(handoff: Dict[str, Any]) -> Dict[str, Any]:
    """
    Constructs an isolated, unanchored view of an incident handoff envelope
    for autonomous multi-agent reasoning.
    
    Contract & Invariant Guarantees:
      1. Fail-Closed Precondition:
         Asserts that handoff['evaluation_metadata']['non_evidentiary_for_agents']
         (or handoff['initial_triage']['non_evidentiary_for_agents']) is True.
         Raises ValueError if missing, False, or malformed.
      2. Strict Allowlist Projection:
         Deep-copies only approved evidentiary fields. The triage block is omitted.
      3. Mutation Isolation:
         Returns a fresh deep-copy. Modifying the agent view cannot corrupt
         the caller's original handoff data.
      4. Recursive Leak Guard:
         Walks the projected tree to prove zero forbidden keys survive.
         
    Parameters:
      - handoff: Dict conforming to IncidentHandoffEnvelope schema.
      
    Returns:
      - Sanitized Dict containing only evidentiary fields for agent ingestion.
      
    Raises:
      - ValueError: If handoff fails airlock preconditions.
      - CognitiveAnchoringLeakError: If any forbidden triage key leaks into the output.
    """
    if not isinstance(handoff, dict):
        raise ValueError(f"Handoff must be a dictionary, got {type(handoff).__name__}")

    # 0. Fail-Closed Schema Version Validation
    schema_version = handoff.get("schema_version")
    if schema_version is not None and schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError(
            f"Unsupported schema version: '{schema_version}'. Supported versions: {sorted(SUPPORTED_SCHEMA_VERSIONS)}."
        )

    # 1. Locate triage block
    triage_block = handoff.get("evaluation_metadata")
    if triage_block is None:
        triage_block = handoff.get("initial_triage")

    if triage_block is None or not isinstance(triage_block, dict):
        raise ValueError(
            "Airlock contract violation: Missing required 'evaluation_metadata' / 'initial_triage' block."
        )

    # 2. Fail-Closed Precondition: Assert non_evidentiary_for_agents is strictly True
    non_evidentiary = triage_block.get("non_evidentiary_for_agents")
    if non_evidentiary is not True:
        raise ValueError(
            f"Airlock contract violation: 'non_evidentiary_for_agents' must be strictly True (got {non_evidentiary}). "
            "Triage metrics cannot be safely quarantined."
        )

    # 3. Strict Allowlist Projection (Deep-Copy)
    projected_view: Dict[str, Any] = {}
    for key, value in handoff.items():
        if key in APPROVED_EVIDENTIARY_KEYS:
            projected_view[key] = copy.deepcopy(value)

    # 4. Defensive check: Ensure no triage block was accidentally captured
    for forbidden_top_level in TRIAGE_BLOCK_KEYS:
        if forbidden_top_level in projected_view:
            del projected_view[forbidden_top_level]

    # 5. Recursive Leak Guard: Mathematically prove zero forbidden keys survive
    assert_no_triage_leaks(projected_view, current_path="$")

    return projected_view

