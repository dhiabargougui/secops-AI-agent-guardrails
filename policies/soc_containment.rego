# Autonomous AI SOC Platform — Policy Enforcement Point (PEP)
# Autonomous SecOps Guardrails Policy Specification
# policies/soc_containment.rego
#
# Production Rego policy governing automated containment directives.
# Implements Invariant #4 (Hard Autonomy Ceiling), Table 21 Disruption Costs,
# and Table 22 Decision Zones with 3-state Out-of-Band (OOB) authentication.

package soc.containment

import rego.v1

# Default fail-closed fallback for unmapped directives, missing inputs,
# or out-of-range RSEM scores.
default result := {
    "decision": "ESCALATE",
    "reason": "NO_MATCHING_RULE"
}

# Authoritative Containment Action Disruption Cost Catalog (Table 21).
# Keys: action_type -> asset_tier (0: Tier 0 Crown Jewels, 1: Tier 1 Mission-Critical,
# 2: Tier 2 Business-Operational, 3: Tier 3 Isolated/Test).
cost_catalog := {
    "ISOLATE_HOST": {0: 10, 1: 9, 2: 5, 3: 2},
    "REVOKE_ACTIVE_SESSIONS": {0: 5, 1: 3, 2: 2, 3: 1},
    "ENFORCE_STEP_UP_AUTH": {0: 2, 1: 2, 2: 1, 3: 1},
    "BLOCK_IOC": {0: 3, 1: 2, 2: 1, 3: 1},
    "PURGE_MESSAGE": {0: 2, 1: 1, 2: 1, 3: 1},
    "DISABLE_ACCOUNT": {0: 9, 1: 6, 2: 4, 3: 3}
}

# Normalized tier index mapping supporting integer indices and canonical string tiers.
resolved_tier := input.asset_tier if {
    is_number(input.asset_tier)
}
resolved_tier := 0 if { input.asset_tier == "Tier 0" }
resolved_tier := 1 if { input.asset_tier == "Tier 1" }
resolved_tier := 2 if { input.asset_tier == "Tier 2" }
resolved_tier := 3 if { input.asset_tier == "Tier 3" }
resolved_tier := 0 if { input.asset_tier == "0" }
resolved_tier := 1 if { input.asset_tier == "1" }
resolved_tier := 2 if { input.asset_tier == "2" }
resolved_tier := 3 if { input.asset_tier == "3" }

# Authoritative Cost of Action (C_A) Resolution.
# Fails closed to 10 (HARD_AUTONOMY_CEILING_EXCEEDED -> ESCALATE) if unmapped.
# Untrusted input.cost_of_action is never evaluated.
default cost_of_action := 10

cost_of_action := cost_catalog[input.action_type][resolved_tier] if {
    cost_catalog[input.action_type][resolved_tier]
}

# Refinement 1: Authoritative Identity Action Classification.
# Derived directly inside Rego for defense-in-depth; untrusted input.is_identity_action
# is ignored.
identity_actions := {
    "REVOKE_ACTIVE_SESSIONS",
    "ENFORCE_STEP_UP_AUTH",
    "DISABLE_ACCOUNT"
}

default is_identity_action := false

is_identity_action if {
    input.action_type in identity_actions
}

# Refinement 3: RSEM Bound Validation Guard.
# Ensures RSEM is a numeric probability-scaled risk score in [0.0, 100.0].
# Out-of-range or non-numeric RSEM inputs fail closed to default result.
valid_rsem if {
    is_number(input.rsem)
    input.rsem >= 0
    input.rsem <= 100
}

# -----------------------------------------------------------------------------
# Decision Rules (Table 22 Gating Engine)
# Mutually exclusive by construction across C_A, RSEM, action type, and OOB status.
# -----------------------------------------------------------------------------

# Rule 1: Hard Autonomy Ceiling (Invariant #4)
# High-impact containment directives (C_A >= 4) unconditionally escalate to
# human Expert. Evaluated before any Zone 2 OOB branch; user confirmation can
# never override the Hard Autonomy Ceiling.
result := {
    "decision": "ESCALATE",
    "reason": "HARD_AUTONOMY_CEILING_EXCEEDED"
} if {
    cost_of_action >= 4
}

# Rule 2: Zone 1 Autonomous Execution (C_A <= 3, RSEM >= 75)
# Low-disruption actions with high risk conviction execute autonomously.
result := {
    "decision": "ALLOW",
    "reason": "ZONE1_AUTONOMOUS_ALLOW"
} if {
    cost_of_action <= 3
    valid_rsem
    input.rsem >= 75
}

# Rule 2b: Zone 2 Post-OOB Denial Execution (C_A <= 3, 50 <= RSEM < 75)
# User actively denied initiating the suspicious authentication activity,
# confirming credential theft / unauthorized access. Directive executes autonomously.
result := {
    "decision": "ALLOW",
    "reason": "ZONE2_POST_DENIAL_ALLOW"
} if {
    cost_of_action <= 3
    valid_rsem
    input.rsem >= 50
    input.rsem < 75
    is_identity_action
    input.oob_status == "DENIED_BY_USER"
}

# Rule 2c: Zone 2 Confirmed Legitimate Stand-Down (C_A <= 3, 50 <= RSEM < 75)
# User actively confirmed legitimate ownership of the activity (false positive).
# Containment stands down, avoiding unwarranted operational disruption.
result := {
    "decision": "STAND_DOWN",
    "reason": "OOB_CONFIRMED_LEGITIMATE"
} if {
    cost_of_action <= 3
    valid_rsem
    input.rsem >= 50
    input.rsem < 75
    is_identity_action
    input.oob_status == "CONFIRMED_LEGITIMATE"
}

# Rule 3: Zone 2 Gray Zone Identity Step-Up (C_A <= 3, 50 <= RSEM < 75)
# Identity actions in the gray zone require out-of-band attestation before execution.
result := {
    "decision": "OOB_REQUIRED",
    "reason": "ZONE2_OOB_STEP_UP"
} if {
    cost_of_action <= 3
    valid_rsem
    input.rsem >= 50
    input.rsem < 75
    is_identity_action
    input.oob_status == "PENDING"
}

# Rule 4: Zone 2 Gray Zone Non-Identity Action (C_A <= 3, 50 <= RSEM < 75)
# Non-identity actions (e.g., host isolation, message purge) have no user OOB
# channel and must escalate to a human analyst.
result := {
    "decision": "ESCALATE",
    "reason": "ZONE2_NON_IDENTITY_ESCALATE"
} if {
    cost_of_action <= 3
    valid_rsem
    input.rsem >= 50
    input.rsem < 75
    not is_identity_action
}

# Rule 5: Zone 3 Gatekeeper Escalation (C_A <= 3, RSEM < 50)
# Insufficient risk conviction prevents autonomous execution; escalates to Tier-2 SOC.
result := {
    "decision": "ESCALATE",
    "reason": "ZONE3_GATEKEEPER_ESCALATE"
} if {
    cost_of_action <= 3
    valid_rsem
    input.rsem < 50
}

