package sentryx.zta

import rego.v1

config := data.enterprise.zta

subject := object.get(input, "subject", {})
device := object.get(input, "device", {})
input_risk := object.get(input, "risk", {})
input_resource := object.get(input, "resource", {})

role := object.get(subject, "role", "")
department := object.get(subject, "department", "")
resource_name := object.get(input_resource, "name", "")
action := object.get(input, "action", "")

role_policy := object.get(config.roles, role, {})
resource_policy := object.get(config.resources, resource_name, {})
device_policy := object.get(resource_policy, "device", {})

risk_score := score if {
  score := object.get(input_risk, "siem_score", config.risk.default_score)
  is_number(score)
} else := config.risk.default_score

high_risk if {
  risk_score >= config.risk.deny_score
}

threat_match if {
  object.get(input_risk, "threat_intel_match", false) == true
}

impossible_travel if {
  object.get(input_risk, "impossible_travel", false) == true
}

known_role if {
  config.roles[role]
}

known_resource if {
  config.resources[resource_name]
}

department_allowed if {
  department in object.get(role_policy, "departments", [])
}

action_allowed if {
  action in object.get(object.get(role_policy, "resources", {}), resource_name, [])
}

resource_attributes_match if {
  object.get(input_resource, "type", "") == object.get(resource_policy, "type", "")
  object.get(input_resource, "criticality", "") == object.get(resource_policy, "criticality", "")
}

mfa_ok if {
  not object.get(resource_policy, "required_mfa", false)
}

mfa_ok if {
  object.get(resource_policy, "required_mfa", false)
  object.get(subject, "mfa", false) == true
}

device_managed_ok if {
  not object.get(device_policy, "managed", false)
}

device_managed_ok if {
  object.get(device_policy, "managed", false)
  object.get(device, "managed", false) == true
}

device_edr_ok if {
  object.get(device_policy, "edr_status", "") == ""
}

device_edr_ok if {
  object.get(device, "edr_status", "") == object.get(device_policy, "edr_status", "")
}

device_patch_ok if {
  object.get(device_policy, "patch_level", "") == ""
}

device_patch_ok if {
  object.get(device, "patch_level", "") == object.get(device_policy, "patch_level", "")
}

resource_risk_ok if {
  risk_score <= object.get(resource_policy, "max_risk_score", config.risk.medium_score)
}

blocking_reasons contains "Risk score is too high" if {
  high_risk
}

blocking_reasons contains "Threat intelligence match exists" if {
  threat_match
}

blocking_reasons contains "Impossible travel detected" if {
  impossible_travel
}

blocking_reasons contains "Unknown role" if {
  not known_role
}

blocking_reasons contains "Unknown resource" if {
  not known_resource
}

blocking_reasons contains "Department is not allowed for this role" if {
  known_role
  not department_allowed
}

blocking_reasons contains "Action is not allowed for this role and resource" if {
  known_role
  known_resource
  not action_allowed
}

blocking_reasons contains "Resource attributes do not match inventory" if {
  known_resource
  not resource_attributes_match
}

blocking_reasons contains "MFA is required" if {
  known_resource
  not mfa_ok
}

blocking_reasons contains "Device is not managed as required" if {
  known_resource
  not device_managed_ok
}

blocking_reasons contains "EDR status does not meet policy" if {
  known_resource
  not device_edr_ok
}

blocking_reasons contains "Patch level does not meet policy" if {
  known_resource
  not device_patch_ok
}

blocking_reasons contains "Risk score exceeds resource limit" if {
  known_resource
  not high_risk
  not resource_risk_ok
}

deny_policy_id := "policy-deny-high-risk" if {
  high_risk
} else := "policy-deny-threat-intel-match" if {
  threat_match
} else := "policy-deny-impossible-travel" if {
  impossible_travel
} else := "policy-deny-access-requirements" if {
  count(blocking_reasons) > 0
}

deny_policy_name := object.get(config.policy_names, deny_policy_id, "Enterprise deny policy")

allow_reasons := [
  "Role and department matched",
  "Action is allowed for role and resource",
  "MFA requirement satisfied",
  "Device trust requirements satisfied",
  "Risk score is within allowed threshold",
  "Resource inventory matched"
]

decision := {
  "decision": "deny",
  "policyId": deny_policy_id,
  "policyName": deny_policy_name,
  "reason": sort([reason | reason := blocking_reasons[_]]),
  "riskScore": risk_score
} if {
  count(blocking_reasons) > 0
}

decision := {
  "decision": "allow",
  "policyId": "policy-enterprise-allow",
  "policyName": object.get(config.policy_names, "policy-enterprise-allow", "Enterprise allow policy"),
  "reason": allow_reasons,
  "riskScore": risk_score
} if {
  count(blocking_reasons) == 0
}
