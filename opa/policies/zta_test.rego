package sentryx.zta

import rego.v1

allow_input := {
  "subject": {
    "user": "ali.valiyev",
    "role": "analyst",
    "department": "SOC",
    "mfa": true
  },
  "device": {
    "managed": true,
    "edr_status": "healthy",
    "patch_level": "ok",
    "ip": "10.10.80.55"
  },
  "risk": {
    "siem_score": 20,
    "threat_intel_match": false,
    "impossible_travel": false
  },
  "resource": {
    "type": "database",
    "name": "incident_db",
    "criticality": "high"
  },
  "action": "read"
}

test_allow_soc_analyst_incident_read if {
  result := decision with input as allow_input

  result.decision == "allow"
  result.policyId == "policy-enterprise-allow"
  result.riskScore == 20
}

test_deny_high_risk if {
  high_risk_input := object.union_n([
    allow_input,
    {
      "risk": {
        "siem_score": 90,
        "threat_intel_match": false,
        "impossible_travel": false
      }
    }
  ])

  result := decision with input as high_risk_input

  result.decision == "deny"
  result.policyId == "policy-deny-high-risk"
  "Risk score is too high" in result.reason
}

test_deny_default_unknown_role if {
  guest_input := object.union_n([
    allow_input,
    {
      "subject": {
        "user": "vali.karimov",
        "role": "guest",
        "department": "HR",
        "mfa": true
      }
    }
  ])

  result := decision with input as guest_input

  result.decision == "deny"
  result.policyId == "policy-deny-access-requirements"
  "Unknown role" in result.reason
}

test_deny_threat_intel if {
  threat_input := object.union_n([
    allow_input,
    {
      "risk": {
        "siem_score": 20,
        "threat_intel_match": true,
        "impossible_travel": false
      }
    }
  ])

  result := decision with input as threat_input

  result.decision == "deny"
  result.policyId == "policy-deny-threat-intel-match"
  "Threat intelligence match exists" in result.reason
}

test_deny_impossible_travel if {
  travel_input := object.union_n([
    allow_input,
    {
      "risk": {
        "siem_score": 20,
        "threat_intel_match": false,
        "impossible_travel": true
      }
    }
  ])

  result := decision with input as travel_input

  result.decision == "deny"
  result.policyId == "policy-deny-impossible-travel"
  "Impossible travel detected" in result.reason
}
