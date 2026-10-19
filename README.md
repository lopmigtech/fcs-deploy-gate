# fcs-deploy-gate

A pre-apply Gate that runs the CrowdStrike Falcon Cloud Security CLI (`fcs`) against Terraform source before it deploys, so that a Deployment which would create IOMs in CrowdStrike is stopped in CI rather than discovered in the console later. One Python core does the work; thin GitHub Actions and GitLab CI adapters call it (ADR 0004).

Vocabulary is defined in `GLOSSARY.md`; decisions with lasting consequences are in `docs/adr/`. Agent-facing conventions live in `AGENTS.md` and `docs/agents/`.

## How the Gate decides

What exists today is Whole-tree Scope through the run entry point, exercised with a fake CLI and fixture reports. Exclusions, Change-aware Scope, and the pinned CLI download are tracked as later tickets.

```sh
fcs-deploy-gate --path infra/prod --region us-gov-1 [--mode enforcing|advisory] \
    [--blocking-threshold critical,high,medium[,informational]] [--work-dir fcs-gate] \
    --fcs-binary /path/to/fcs
```

1. **The scan.** The Gate launches `fcs scan iac` from the scanned directory with a JSON report, `--fail-on` set to count every severity, and the Falcon region. The CLI never receives the Falcon client id or secret in its environment; the Gate strips them before launching it.
2. **A result or an error.** A scan attempt counts as a result only when the CLI exits 0 or 40 and the report parses. Any other exit code, a missing report, or a report the Gate cannot interpret is a blocked Verdict carrying an error message. The Gate fails closed and has no bypass (ADR 0001).
3. **Findings.** The report's rule detections become Findings with rule id `iac/<rule_uuid>`. Secrets become high-severity Findings with rule id `secret/<type>`. Policy violations become Findings at their stated severity with rule id `policy/<id>`. Severities are lower-cased, `low` is read as `informational`, and anything else is a report error. File paths are normalised relative to the scanned root.
4. **The Verdict.** A Finding at or above the Blocking threshold is a Blocking finding; any Blocking finding is a blocked Verdict. The threshold defaults to critical, high and medium. A Consumer may add informational but cannot remove any of the three defaults.
5. **Exit codes.** Enforcing mode exits 1 on a blocked Verdict. Advisory mode reports the same Verdict, prints a warning, and exits 0. Any configuration mistake (threshold, scope, mode, region, scan path) exits 2 in both modes before a scan is attempted.
6. **Outputs.** The work directory receives `verdict.json`, `summary.md` and the raw `fcs-report.json`. The summary is printed to the job log, appended to `GITHUB_STEP_SUMMARY` when that variable is set, and `verdict` plus `blocking_count` are appended to `GITHUB_OUTPUT`.

A clear Verdict means no IaC Findings at or above the Blocking threshold. It does not yet mean that no IOM will appear: which IaC rules correspond to IOMs in the tenant has not been measured (ADR 0005).

## Development

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest            # offline: the suite refuses to open sockets
mypy
ruff check && ruff format --check
```

The fake CLI is `tests/fake_fcs.py`; fixture reports are under `tests/fixtures/reports/`. CI runs the suite on Python 3.11 and 3.12 on every push and pull request.
