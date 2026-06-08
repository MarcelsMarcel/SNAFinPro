# compliance/policies/cc6_7_secrets.rego
# SOC 2 CC6.7 — Logical and Physical Access Controls: Credential Protection
# ISO 27001 A.8.12 — Data Leakage Prevention
#
# Control: No hardcoded secrets, credentials, or API keys
# must exist in the codebase before merge.

package compliance.soc2.cc6_7

import rego.v1

# Default deny — secure by default
default allow := false

# Allow only if no secrets were found
allow if {
	input.secrets_scan.status == "passed"
	input.secrets_scan.secrets_found == 0
}

# Emit structured violation evidence when control fails
violation contains evidence if {
	not allow
	evidence := {
		"control_id":     "CC6.7",
		"framework":      "SOC2",
		"iso_mapping":    "A.8.12",
		"title":          "Credential & Secret Protection",
		"status":         "violated",
		"reason":         "Hardcoded secrets or credentials detected in codebase",
		"actor":          input.pipeline.actor,
		"commit":         input.pipeline.commit,
		"run_id":         input.pipeline.run_id,
		"timestamp":      input.pipeline.timestamp,
		"tool":           input.secrets_scan.tool,
		"secrets_found":  input.secrets_scan.secrets_found,
	}
}

# Emit pass evidence when control is satisfied
pass contains evidence if {
	allow
	evidence := {
		"control_id":    "CC6.7",
		"framework":     "SOC2",
		"iso_mapping":   "A.8.12",
		"title":         "Credential & Secret Protection",
		"status":        "passed",
		"actor":         input.pipeline.actor,
		"commit":        input.pipeline.commit,
		"run_id":        input.pipeline.run_id,
		"timestamp":     input.pipeline.timestamp,
		"tool":          input.secrets_scan.tool,
		"secrets_found": input.secrets_scan.secrets_found,
	}
}
