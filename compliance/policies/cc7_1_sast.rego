# compliance/policies/cc7_1_sast.rego
# SOC 2 CC7.1 — System Monitoring: Vulnerability Detection
# ISO 27001 A.8.8 — Management of Technical Vulnerabilities
#
# Control: SAST scan must pass with zero critical/high findings
# before code is allowed to merge.

package compliance.soc2.cc7_1

import rego.v1

# Default deny — secure by default
default allow := false

# Allow only if SAST scan passed with zero critical findings
allow if {
	input.sast_scan.status == "passed"
	input.sast_scan.critical_findings == 0
}

# Emit structured violation evidence when control fails
violation contains evidence if {
	not allow
	evidence := {
		"control_id":        "CC7.1",
		"framework":         "SOC2",
		"iso_mapping":       "A.8.8",
		"title":             "SAST Vulnerability Detection",
		"status":            "violated",
		"reason":            "SAST scan did not pass or found critical findings",
		"actor":             input.pipeline.actor,
		"commit":            input.pipeline.commit,
		"run_id":            input.pipeline.run_id,
		"timestamp":         input.pipeline.timestamp,
		"tool":              input.sast_scan.tool,
		"critical_findings": input.sast_scan.critical_findings,
	}
}

# Emit pass evidence when control is satisfied
pass contains evidence if {
	allow
	evidence := {
		"control_id":        "CC7.1",
		"framework":         "SOC2",
		"iso_mapping":       "A.8.8",
		"title":             "SAST Vulnerability Detection",
		"status":            "passed",
		"actor":             input.pipeline.actor,
		"commit":            input.pipeline.commit,
		"run_id":            input.pipeline.run_id,
		"timestamp":         input.pipeline.timestamp,
		"tool":              input.sast_scan.tool,
		"critical_findings": input.sast_scan.critical_findings,
	}
}
