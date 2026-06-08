# ComplianceAsCode Pipeline
### Automated SOC 2 & ISO 27001 Evidence Collection in CI/CD
**Server and Network Administration — COMP6842001 — Binus University**

---

## What this is

Every time code is pushed or a PR is opened, this pipeline automatically:

1. Runs **Semgrep** (SAST) → maps to SOC 2 **CC7.1** / ISO 27001 **A.8.8**
2. Runs **Gitleaks** (secrets scan) → maps to SOC 2 **CC6.7** / ISO 27001 **A.8.12**
3. Runs **Trivy** (dependency CVE scan) → maps to SOC 2 **CC9.2** / ISO 27001 **A.5.20**
4. Evaluates each result against **OPA/Rego policies**
5. Generates **structured evidence artifacts** (JSON) per control with SHA-256 hash
6. Uploads all evidence to **GitHub Artifacts** with 90-day retention
7. **Blocks the pipeline** if any control is violated

This turns every pipeline run into an auditable compliance record — without any manual work.

---

## Repository Structure

```
.github/workflows/
  compliance-pipeline.yml    ← Main pipeline

compliance/
  policies/
    cc7_1_sast.rego          ← OPA policy: SAST control
    cc6_7_secrets.rego       ← OPA policy: Secrets control
    cc9_2_cve.rego           ← OPA policy: CVE control
  scripts/
    generate_evidence.py     ← Evidence artifact generator

src/
  index.js                   ← Demo Express app

package.json
```

---

## Controls Implemented

| SOC 2  | ISO 27001 | What it checks            | Tool     |
|--------|-----------|---------------------------|----------|
| CC7.1  | A.8.8     | No critical SAST findings | Semgrep  |
| CC6.7  | A.8.12    | No hardcoded secrets      | Gitleaks |
| CC9.2  | A.5.20    | No critical CVEs          | Trivy    |

---

## Evidence Artifact Format

Each pipeline run produces one JSON per control:

```json
{
  "control_id": "CC7.1",
  "iso_mapping": "A.8.8",
  "framework": "SOC2",
  "status": "passed",
  "pipeline": {
    "actor": "marcelsmarcel",
    "commit": "abc123...",
    "run_id": "12345678",
    "ref": "refs/heads/main"
  },
  "scan": {
    "tool": "semgrep",
    "findings": 0
  },
  "collected_at": "2026-06-08T10:23:00Z",
  "sha256": "a3f9b2..."
}
```

---

## How to trigger

Push any commit to `main` or open a PR — the pipeline runs automatically.

To see results: **GitHub → Actions tab → ComplianceAsCode Pipeline**

To download evidence: **Actions run → Artifacts → compliance-evidence-{run_id}**
