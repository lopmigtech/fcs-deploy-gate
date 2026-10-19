# fcs-deploy-gate

A GitHub Actions pipeline that runs the CrowdStrike Falcon Cloud Security CLI (`fcs`) against infrastructure changes before they deploy, so that deployments which would generate findings in CrowdStrike are stopped in CI rather than discovered later.

Agent-facing conventions for this repo live in `AGENTS.md` and `docs/agents/`.
