# compliance/policies/cc9_2_cve.rego
# SOC 2 CC9.2 — Risk Mitigation: Vendor & Third-Party Management
# ISO 27001 A.5.20 — Addressing Information Security within Supplier Agreements
#
# Control: No critical or high CVEs in third-party dependencies
# before deployment proceeds.

package compliance.soc2.cc9_2

import rego.v1

# Default deny — secure by default
default allow := false

# Allow only if no critical/high CVEs found in dependencies
allow if {
	input.sca_scan.status == "passed"
	input.sca_scan.critical_cve == 0
}

# Emit structured violation evidence when control fails
violation contains evidence if {
	not allow
	evidence := {
		"control_id":   "CC9.2",
		"framework":    "SOC2",
		"iso_mapping":  "A.5.20",
		"title":        "Third-Party Dependency CVE Management",
		"status":       "violated",
		"reason":       "Critical or high CVEs found in dependencies",
		"actor":        input.pipeline.actor,
		"commit":       input.pipeline.commit,
		"run_id":       input.pipeline.run_id,
		"timestamp":    input.pipeline.timestamp,
		"tool":         input.sca_scan.tool,
		"critical_cve": input.sca_scan.critical_cve,
	}
}

# Emit pass evidence when control is satisfied
pass contains evidence if {
	allow
	evidence := {
		"control_id":   "CC9.2",
		"framework":    "SOC2",
		"iso_mapping":  "A.5.20",
		"title":        "Third-Party Dependency CVE Management",
		"status":       "passed",
		"actor":        input.pipeline.actor,
		"commit":       input.pipeline.commit,
		"run_id":       input.pipeline.run_id,
		"timestamp":    input.pipeline.timestamp,
		"tool":         input.sca_scan.tool,
		"critical_cve": input.sca_scan.critical_cve,
	}
}
