# fcs-deploy-gate

A pre-apply Gate that runs the CrowdStrike Falcon Cloud Security CLI (`fcs`) against Terraform source before it deploys, so that a Deployment which would create IOMs in CrowdStrike is stopped in CI rather than discovered in the console later. One Python core does the work; thin GitHub Actions and GitLab CI adapters call it (ADR 0004).

Vocabulary is defined in `GLOSSARY.md`; decisions with lasting consequences are in `docs/adr/`. Agent-facing conventions live in `AGENTS.md` and `docs/agents/`.

## How the Gate decides

What exists today is Whole-tree Scope through the run entry point with Exclusions, exercised with a fake CLI and fixture reports. Change-aware Scope and the pinned CLI download are tracked as later tickets.

```sh
fcs-deploy-gate --path infra/prod --region us-gov-1 [--mode enforcing|advisory] \
    [--blocking-threshold critical,high,medium[,informational]] \
    [--no-block-on-unscanned-files] [--work-dir fcs-gate]
```

Until the pinned CLI download lands (ticket 5), the Gate refuses to run unless `--fcs-binary` names an `fcs` executable. That flag is the seam the test suite uses to substitute the fake CLI; adapters must never forward it.

1. **The scan.** The Gate launches `fcs scan iac` from the scanned directory with a JSON report, `--fail-on` set to count every severity, and the Falcon region. The CLI never receives the Falcon client id or secret in its environment; the Gate strips them before launching it.
2. **A result or an error.** A scan attempt counts as a result only when the CLI exits 0 or 40 and the report parses. Any other exit code, a missing report, or a report the Gate cannot interpret is a blocked Verdict carrying an error message. The Gate fails closed and has no bypass (ADR 0001).
3. **Findings.** The report's rule detections become Findings with rule id `iac/<rule_uuid>`. Secrets become high-severity Findings with rule id `secret/<type>`. Policy violations become Findings at their stated severity with rule id `policy/<id>`. Severities are lower-cased, `low` is read as `informational`, and anything else is a report error. File paths are normalised relative to the scanned root.
4. **The Verdict.** A Finding at or above the Blocking threshold that no active Exclusion covers is a Blocking finding; any Blocking finding is a blocked Verdict. The threshold defaults to critical, high and medium. A Consumer may add informational but cannot remove any of the three defaults.
5. **Files the CLI could not scan.** The report's count of files the CLI failed to scan is shown in the summary and the verdict document. By default a non-zero count blocks the Verdict, since Findings in those files are unknown; `--no-block-on-unscanned-files` reports the count without blocking. Files the CLI skips by design, such as gitignored ones, are not counted.
6. **Exit codes.** Enforcing mode exits 1 on a blocked Verdict. Advisory mode reports the same Verdict, prints a warning, and exits 0. Any configuration mistake (threshold, scope, mode, region, scan path) exits 2 in both modes before a scan is attempted.
7. **Outputs.** The work directory receives `verdict.json`, `summary.md` and the raw `fcs-report.json`. The summary is printed to the job log, appended to `GITHUB_STEP_SUMMARY` when that variable is set, and `verdict` plus `blocking_count` are appended to `GITHUB_OUTPUT`.

## Exclusions

An Exclusion is a version-controlled, approved, expiring exemption for one specific Finding. Exclusions live in a single file, `.fcs-gate.yml`, at the Consumer repository root: the scanned directory or its nearest ancestor that holds `.git` (a directory, or the file a worktree or submodule carries). When nothing holds `.git`, the Gate says so on stderr and reads the file from the scanned directory. A missing file means no Exclusions.

```yaml
exclusions:
  - rule: iac/9c7e2b14-6a3f-4d58-b2e9-1f0a4c8d6e35   # rule id as the Gate reports it
    resource: aws_s3_bucket.logs                     # type.name; this and/or file
    file: logging.tf                                 # path relative to the scanned directory
    reason: The logs bucket is the access-log target itself; logging it would recurse.
    expires: 2027-06-30                              # YAML date or "YYYY-MM-DD"
    approved_by: security-reviewer@example.gov       # the approving Security team member
```

- Every field named by an entry must match the Finding: the rule id exactly, the resource as `type.name`, the file as the path the Gate reports. At least one of `resource` or `file` is required; `reason` and `approved_by` must be non-empty.
- An Exclusion applies through its expiry date and stops the day after. Dates are compared as UTC calendar days.
- Stale exclusions are reported, never dropped silently: entries that have expired, and entries that match no Finding in the current scan. When two entries cover one Finding, the first in the file is the one recorded; the second still counts as matched.
- Any malformation (unknown keys, missing fields, an unparseable date, the wrong shape) exits 2 in both modes, before any scan.
- Exclusions change the Verdict only. The scan runs against the tenant's full Policy, no CLI exclusion or filter flag is ever passed, and the console always sees the unfiltered scan. Console exemptions govern IOMs on deployed resources; Exclusions govern Findings on resources about to be deployed.
- Consumers must route `.fcs-gate.yml` to the Security team through code ownership with required approval on the protected default branch (GitHub `CODEOWNERS`; GitLab Code Owners). The Gate does not enforce this; the file's `approved_by` is the audit trail.

The summary and `verdict.json` list excluded Findings paired with their Exclusion, and the stale Exclusions with why they are stale.

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
