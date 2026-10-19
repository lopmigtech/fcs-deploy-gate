# fcs-deploy-gate

GitHub Actions pipeline that runs the CrowdStrike Falcon Cloud Security CLI (`fcs`) against infrastructure changes before they deploy, and blocks any deployment that would create findings in CrowdStrike.

## Agent skills

### Issue tracker

Issues live in this repo's GitHub Issues at `github.com/lopmigtech/fcs-deploy-gate` (use the `gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Canonical names, unchanged (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `GLOSSARY.md` and `docs/adr/` at the repo root, created lazily by `/domain-modeling`. See `docs/agents/domain.md`.
