# Autonomous AI SOC Platform — Policy Enforcement Point (PEP) Tests
# policies/soc_containment_test.rego
#
# Native Rego test suite verifying soc_containment.rego behavior
# against all decision zones, autonomy ceiling limits, and OOB states.

package soc.containment_test

import rego.v1
import data.soc.containment

# -----------------------------------------------------------------------------
# Rule 1: Hard Autonomy Ceiling (C_A >= 4) Tests
# -----------------------------------------------------------------------------

test_rule1_ceiling_tier0_isolate if {
    res := containment.result with input as {
        "action_type": "ISOLATE_HOST",
        "asset_tier": 0,
        "rsem": 95.0,
        "oob_status": "PENDING"
    }
    res.decision == "ESCALATE"
    res.reason == "HARD_AUTONOMY_CEILING_EXCEEDED"
}

test_rule1_ceiling_tier1_isolate if {
    res := containment.result with input as {
        "action_type": "ISOLATE_HOST",
        "asset_tier": 1,
        "rsem": 85.0,
        "oob_status": "PENDING"
    }
    res.decision == "ESCALATE"
    res.reason == "HARD_AUTONOMY_CEILING_EXCEEDED"
}

test_rule1_ceiling_tier2_isolate if {
    res := containment.result with input as {
        "action_type": "ISOLATE_HOST",
        "asset_tier": 2,
        "rsem": 80.0,
        "oob_status": "PENDING"
    }
    res.decision == "ESCALATE"
    res.reason == "HARD_AUTONOMY_CEILING_EXCEEDED"
}

test_rule1_ceiling_tier0_revoke if {
    res := containment.result with input as {
        "action_type": "REVOKE_ACTIVE_SESSIONS",
        "asset_tier": 0,
        "rsem": 99.0,
        "oob_status": "DENIED_BY_USER"
    }
    res.decision == "ESCALATE"
    res.reason == "HARD_AUTONOMY_CEILING_EXCEEDED"
}

test_rule1_ceiling_tier2_disable_account if {
    res := containment.result with input as {
        "action_type": "DISABLE_ACCOUNT",
        "asset_tier": 2,
        "rsem": 95.0,
        "oob_status": "PENDING"
    }
    res.decision == "ESCALATE"
    res.reason == "HARD_AUTONOMY_CEILING_EXCEEDED"
}

test_rule1_ceiling_unmapped_action_fails_closed if {
    res := containment.result with input as {
        "action_type": "UNMAPPED_EXPERIMENTAL_ACTION",
        "asset_tier": 3,
        "rsem": 99.0,
        "oob_status": "DENIED_BY_USER"
    }
    res.decision == "ESCALATE"
    res.reason == "HARD_AUTONOMY_CEILING_EXCEEDED"
}

test_rule1_ceiling_overrides_confirmed_legitimate if {
    res := containment.result with input as {
        "action_type": "REVOKE_ACTIVE_SESSIONS",
        "asset_tier": 0,
        "rsem": 65.0,
        "oob_status": "CONFIRMED_LEGITIMATE"
    }
    res.decision == "ESCALATE"
    res.reason == "HARD_AUTONOMY_CEILING_EXCEEDED"
}

# -----------------------------------------------------------------------------
# Rule 2: Zone 1 Autonomous Execution (C_A <= 3, RSEM >= 75) Tests
# -----------------------------------------------------------------------------

test_rule2_zone1_tier3_isolate if {
    res := containment.result with input as {
        "action_type": "ISOLATE_HOST",
        "asset_tier": 3,
        "rsem": 79.9,
        "oob_status": "PENDING"
    }
    res.decision == "ALLOW"
    res.reason == "ZONE1_AUTONOMOUS_ALLOW"
}

test_rule2_zone1_tier3_purge if {
    res := containment.result with input as {
        "action_type": "PURGE_MESSAGE",
        "asset_tier": 3,
        "rsem": 88.8,
        "oob_status": "PENDING"
    }
    res.decision == "ALLOW"
    res.reason == "ZONE1_AUTONOMOUS_ALLOW"
}

test_rule2_zone1_exact_75_boundary if {
    res := containment.result with input as {
        "action_type": "BLOCK_IOC",
        "asset_tier": 2,
        "rsem": 75.0,
        "oob_status": "PENDING"
    }
    res.decision == "ALLOW"
    res.reason == "ZONE1_AUTONOMOUS_ALLOW"
}

# -----------------------------------------------------------------------------
# Rule 2b, 2c, 3: Zone 2 Gray Zone Identity Actions (C_A <= 3, 50 <= RSEM < 75)
# -----------------------------------------------------------------------------

test_rule2b_zone2_post_denial_allow if {
    res := containment.result with input as {
        "action_type": "REVOKE_ACTIVE_SESSIONS",
        "asset_tier": 1,
        "rsem": 74.3,
        "oob_status": "DENIED_BY_USER"
    }
    res.decision == "ALLOW"
    res.reason == "ZONE2_POST_DENIAL_ALLOW"
}

test_rule2c_zone2_confirmed_legitimate_stand_down if {
    res := containment.result with input as {
        "action_type": "REVOKE_ACTIVE_SESSIONS",
        "asset_tier": 1,
        "rsem": 74.3,
        "oob_status": "CONFIRMED_LEGITIMATE"
    }
    res.decision == "STAND_DOWN"
    res.reason == "OOB_CONFIRMED_LEGITIMATE"
}

test_rule3_zone2_oob_step_up_pending if {
    res := containment.result with input as {
        "action_type": "REVOKE_ACTIVE_SESSIONS",
        "asset_tier": 1,
        "rsem": 74.3,
        "oob_status": "PENDING"
    }
    res.decision == "OOB_REQUIRED"
    res.reason == "ZONE2_OOB_STEP_UP"
}

test_rule3_zone2_exact_50_boundary if {
    res := containment.result with input as {
        "action_type": "ENFORCE_STEP_UP_AUTH",
        "asset_tier": 0,
        "rsem": 50.0,
        "oob_status": "PENDING"
    }
    res.decision == "OOB_REQUIRED"
    res.reason == "ZONE2_OOB_STEP_UP"
}

# -----------------------------------------------------------------------------
# Rule 4: Zone 2 Gray Zone Non-Identity Actions (C_A <= 3, 50 <= RSEM < 75)
# -----------------------------------------------------------------------------

test_rule4_zone2_non_identity_escalate if {
    res := containment.result with input as {
        "action_type": "ISOLATE_HOST",
        "asset_tier": 3,
        "rsem": 71.3,
        "oob_status": "PENDING"
    }
    res.decision == "ESCALATE"
    res.reason == "ZONE2_NON_IDENTITY_ESCALATE"
}

test_rule4_caller_injected_identity_flag_ignored if {
    # Refinement 1: Caller falsely passes is_identity_action = true for ISOLATE_HOST
    res := containment.result with input as {
        "action_type": "ISOLATE_HOST",
        "asset_tier": 3,
        "rsem": 71.3,
        "is_identity_action": true,
        "oob_status": "DENIED_BY_USER"
    }
    # Must still escalate as non-identity because Rego derives is_identity_action internally
    res.decision == "ESCALATE"
    res.reason == "ZONE2_NON_IDENTITY_ESCALATE"
}

# -----------------------------------------------------------------------------
# Rule 5: Zone 3 Gatekeeper Escalation (C_A <= 3, RSEM < 50) Tests
# -----------------------------------------------------------------------------

test_rule5_zone3_gatekeeper_escalate if {
    res := containment.result with input as {
        "action_type": "ISOLATE_HOST",
        "asset_tier": 3,
        "rsem": 49.99,
        "oob_status": "PENDING"
    }
    res.decision == "ESCALATE"
    res.reason == "ZONE3_GATEKEEPER_ESCALATE"
}

test_rule5_zone3_low_conviction if {
    res := containment.result with input as {
        "action_type": "BLOCK_IOC",
        "asset_tier": 3,
        "rsem": 15.0,
        "oob_status": "PENDING"
    }
    res.decision == "ESCALATE"
    res.reason == "ZONE3_GATEKEEPER_ESCALATE"
}

# -----------------------------------------------------------------------------
# Fallback / Boundary Guards (Refinement 3)
# -----------------------------------------------------------------------------

test_guard_out_of_range_rsem_high_fails_closed if {
    res := containment.result with input as {
        "action_type": "ISOLATE_HOST",
        "asset_tier": 3,
        "rsem": 150.0,
        "oob_status": "PENDING"
    }
    res.decision == "ESCALATE"
    res.reason == "NO_MATCHING_RULE"
}

test_guard_out_of_range_rsem_negative_fails_closed if {
    res := containment.result with input as {
        "action_type": "ISOLATE_HOST",
        "asset_tier": 3,
        "rsem": -10.0,
        "oob_status": "PENDING"
    }
    res.decision == "ESCALATE"
    res.reason == "NO_MATCHING_RULE"
}

test_guard_missing_rsem_fails_closed if {
    res := containment.result with input as {
        "action_type": "ISOLATE_HOST",
        "asset_tier": 3,
        "oob_status": "PENDING"
    }
    res.decision == "ESCALATE"
    res.reason == "NO_MATCHING_RULE"
}

