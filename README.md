# fcs-deploy-gate

A pre-apply Gate that runs the CrowdStrike Falcon Cloud Security CLI (`fcs`) against Terraform source before it deploys, so that a Deployment which would create IOMs in CrowdStrike is stopped in CI rather than discovered in the console later. One Python core does the work; thin GitHub Actions and GitLab CI adapters call it (ADR 0004).

Vocabulary is defined in `GLOSSARY.md`; decisions with lasting consequences are in `docs/adr/`. Agent-facing conventions live in `AGENTS.md` and `docs/agents/`.

## GitHub quick start

Add one job to the deploy workflow and make the apply job depend on it. The Gate runs in parallel with `plan`, so it adds nothing to the critical path.

```yaml
jobs:
  gate:
    uses: lopmigtech/fcs-deploy-gate/.github/workflows/gate.yml@v0.1.0
    with:
      path: infra/prod
      region: us-gov-1
      scope: whole-tree          # or change-aware
      mode: enforcing            # or advisory while burning down a backlog
    secrets:
      falcon-client-id: ${{ secrets.FALCON_CLIENT_ID }}
      falcon-client-secret: ${{ secrets.FALCON_CLIENT_SECRET }}

  apply:
    needs: [plan, gate]
    ...
```

Run it on `pull_request` (the Enforcing block prevents the merge) and on the push that deploys (the hard stop). Pin the tag: tags are immutable semver and there is no moving major tag.

| Input | Required | Default | Meaning |
|---|---|---|---|
| `path` | yes | | Terraform directory to scan, relative to the repository root |
| `region` | yes | | Falcon region: `us-1`, `us-2`, `eu-1`, `us-gov-1`, `us-gov-2` |
| `scope` | no | `whole-tree` | `whole-tree` or `change-aware` |
| `baseline-ref` | no | event default | Change-aware only: an explicit Baseline ref; otherwise the pull request base, or the push's previous commit |
| `blocking-threshold` | no | `critical,high,medium` | Severities that block; `informational` may be added, nothing removed |
| `mode` | no | `enforcing` | `enforcing` or `advisory` |
| `project-name` | no | `owner/name` | Project name for the console upload (the form CrowdStrike's own action recommends) |

Secrets `falcon-client-id` and `falcon-client-secret` are the CI client (scopes below), held as organisation secrets scoped to Consumer repositories and passed explicitly. Outputs `verdict` (`clear` or `blocked`) and `blocking-count` are available to downstream jobs; the summary is in the job summary; `verdict.json`, `summary.md` and the raw reports are the `fcs-deploy-gate-<path>` artifact, one per scanned root. Run the Gate on `pull_request`, never `pull_request_target`: that event checks out the base branch, and the action refuses it.

In Change-aware Scope on GitHub the Baseline is the pull request's base commit (the checkout is the merge commit, so that is the change's merge base in effect) or the push's previous commit, unless `baseline-ref` names one. A Baseline ref that cannot be fetched, such as one a force push removed, is a blocked Verdict with a message, not a silent job failure.

The reusable workflow is one job with a fifteen-minute timeout and read-only contents permission; its single step calls the composite action in this repository, which checks out the change, installs the Gate from its own checkout, resolves the Baseline through the core, checks the Baseline out into a worktree outside the workspace when the Scope is change-aware, runs the core with the work directory under the runner's temporary directory, and uploads the artifacts even when the run fails. The Consumer organisation must allow this repository's workflows and actions to be used by other repositories (repository settings, Actions, Access: "Accessible from repositories in the organization").

## GitLab quick start

Include the template at a tag and make the apply job depend on the gate job. The job runs in merge-request pipelines and in default-branch pipelines, before apply.

```yaml
include:
  - project: security/fcs-deploy-gate      # the Gate project's path on your GitLab instance
    ref: v0.1.0
    file: /gitlab/fcs-deploy-gate.gitlab-ci.yml

variables:
  FCS_GATE_REGION: us-gov-1
  FCS_GATE_PATH: infra/prod
  FCS_GATE_SCOPE: change-aware            # or whole-tree
  FCS_GATE_MODE: advisory                 # flip to enforcing when the backlog is down

apply:
  stage: deploy
  needs: [plan, fcs-deploy-gate]
  ...
```

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `FCS_GATE_REGION` | yes | | Falcon region |
| `FCS_GATE_PATH` | no | `.` | Terraform directory to scan |
| `FCS_GATE_SCOPE` | no | `whole-tree` | `whole-tree` or `change-aware` |
| `FCS_GATE_MODE` | no | `enforcing` | `enforcing` or `advisory` |
| `FCS_GATE_BLOCKING_THRESHOLD` | no | `critical,high,medium` | Severities that block |
| `FCS_GATE_PROJECT_NAME` | no | `$CI_PROJECT_PATH` | Project name for the console upload |
| `FCS_GATE_BASELINE_REF` | no | pipeline default | Change-aware only: an explicit Baseline ref; otherwise the merge request's diff base, or the push's previous commit |
| `FCS_GATE_IMAGE` | instance | `$CI_REGISTRY/mirror/python:3.12` | The mirrored Python image the job runs on (it needs `git`) |
| `FCS_GATE_PROJECT` | instance | `security/fcs-deploy-gate` | The Gate project's path on the instance (a pull mirror of this repository) |

What the instance must provide, once:

- **Credentials.** `FALCON_CLIENT_ID` and `FALCON_CLIENT_SECRET` as masked (hidden) CI variables on the group that owns the Consumer projects. To run the Gate in merge-request pipelines they must be unprotected, because those pipelines run on unprotected source branches; that makes the group's membership the trust boundary for the CI client, which is exactly why the client holds only the download and IaC scopes (see "API clients"): a member who exfiltrates it can scan and upload, not read IOMs or assets. A stricter estate keeps the variables protected and runs the Gate only in default-branch pipelines, giving up the merge-request block. The core reads them from the environment; the template never echoes them.
- **Job-token allowlist.** The Gate project must allow the Consumer projects (Settings, CI/CD, Job token permissions; a group entry covers them all) so the job can clone it with `CI_JOB_TOKEN`, and the users who trigger pipelines need read access to the Gate project.
- **Image mirror.** A mirror of `python:3.12` (the full image, which carries `git`) in the internal registry, named by `FCS_GATE_IMAGE`. The default assumes GitLab's own container registry (`$CI_REGISTRY`); point it elsewhere if the mirror lives in another registry, and allow the pull if that registry is another project's.
- **Package index.** The job installs the Gate and PyYAML with `pip`, so runners need egress to PyPI or `PIP_INDEX_URL` set to an internal mirror.
- **Stages and defaults.** The job runs in stage `test`; a pipeline whose `stages:` omits it must override `fcs-deploy-gate: { stage: <yours> }`. The job sets an empty `before_script`, so a Consumer's default `before_script` never runs on the Python image.
- **Pipelines must succeed.** On each Consumer project, "Pipelines must succeed" under merge request settings, so an Enforcing block prevents the merge; the default-branch job before apply is the hard stop.
- **Code Owners.** A `CODEOWNERS` entry routing `.fcs-gate.yml` to the Security team, with Code Owner approval required on the protected default branch (Premium or Ultimate), so no Exclusion merges without them.
- **CI lint.** Run the instance's CI Lint (CI/CD, Pipeline editor, Validate) against a Consumer pipeline that includes the template before the first live run; that check cannot run here.

Artifacts `verdict.json`, `summary.md` and the raw reports are kept under `fcs-gate/` on success and failure for the instance's default retention; the summary is also in the job log. The work directory is outside the checkout and copied in afterwards.

## How the Gate decides

The core is complete through the run entry point: both Scopes, Exclusions, and the real CLI path (token, pinned download, retries). The suite proves it offline with a fake Falcon API and a fake CLI; the first live run happens in the work environment.

```sh
fcs-deploy-gate run --path infra/prod --region us-gov-1 [--mode enforcing|advisory] \
    [--scope whole-tree|change-aware] [--baseline-dir DIR --baseline-ref REF | --baseline-error MSG] \
    [--blocking-threshold critical,high,medium[,informational]] \
    [--no-block-on-unscanned-files] [--project-name NAME] [--work-dir fcs-gate]
```

`--fcs-binary` is the seam the test suite uses to substitute the fake CLI: it skips the download and the token. Adapters never forward it.

1. **The CLI.** The Gate reads `FALCON_CLIENT_ID` and `FALCON_CLIENT_SECRET` from its environment, obtains a short-lived token from the region's API host, resolves the pinned CLI version through the download API, checks that the hash the API reports equals the pinned SHA-256 before downloading a byte, checks the downloaded archive against it too, and extracts only the `fcs` member (ADR 0003). The download is attempted up to three times with waits of ten then thirty seconds; exhausting them is a blocked Verdict. The Gate refuses to run while the pin is empty.
2. **The scan.** The Gate launches `fcs scan iac` from the scanned directory with a JSON report, `--fail-on` set to count every severity, the Falcon region, the token, a 300-second scan timeout, and upload to the console enabled under the project name (default: the repository directory name). The client secret and id never reach the CLI, in its arguments or its environment. Proxy variables (`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`) reach the Gate's own HTTP calls.
3. **A result or an error.** A scan attempt counts as a result only when the CLI exits 0 or 40, the report parses, and the report shows the tenant's cloud rules were in force: a positive `stats.rule_stats.rules_enabled` (field names provisional until the first live run). The CLI silently falls back to local rules on a bad token or missing region, and the exit code and report then look normal. Whether the CLI printed "Fetching custom rules from Falcon Cloud" is recorded in `verdict.json` alongside the statistics for the first live run to calibrate against, but is never trusted on its own, since CLI output can echo content from the scanned tree. Any other outcome is a scan error, retried up to three times with the same waits; exhausting them is a blocked Verdict carrying the last error. The Gate fails closed and has no bypass (ADR 0001): an outage halts Enforcing Deployments until it recovers, and a Consumer that cannot tolerate that runs in Advisory mode, consciously.
4. **Findings.** The report's rule detections become Findings with rule id `iac/<rule_uuid>`. Secrets become high-severity Findings with rule id `secret/<type>`. Policy violations become Findings at their stated severity with rule id `policy/<id>`. Severities are lower-cased, `low` is read as `informational`, and anything else is a report error. File paths are normalised relative to the scanned root.
5. **Scope.** In Whole-tree Scope (the default) every Finding in the scanned path is considered. In Change-aware Scope the Gate also scans the Baseline, the Consumer's source as it was before the change, and considers only Findings whose identity (rule id, normalised file, resource type, resource name; the line number is ignored) is absent from the Baseline. A resource that was renamed or moved is therefore new; one that only shifted lines is not. The Baseline scan is never uploaded. See "Baseline" below.
6. **The Verdict.** A considered Finding at or above the Blocking threshold that no active Exclusion covers is a Blocking finding; any Blocking finding is a blocked Verdict. The threshold defaults to critical, high and medium. A Consumer may add informational but cannot remove any of the three defaults.
7. **Files the CLI could not scan.** The report's count of files the CLI failed to scan is shown in the summary and the verdict document. By default a non-zero count blocks the Verdict, since Findings in those files are unknown; `--no-block-on-unscanned-files` reports the count without blocking. Files the CLI skips by design, such as gitignored ones, are not counted.
8. **Exit codes.** Enforcing mode exits 1 on a blocked Verdict. Advisory mode reports the same Verdict, prints a warning, and exits 0. Any configuration mistake (threshold, scope, mode, region, scan path, missing credentials, an empty pin, a malformed Exclusion file) exits 2 in both modes before any network call or scan.
9. **Outputs.** The work directory receives `verdict.json`, `summary.md`, the raw `fcs-report.json` and, in Change-aware Scope, `fcs-report-baseline.json`. The summary is printed to the job log, appended to `GITHUB_STEP_SUMMARY` when that variable is set, and `verdict` plus `blocking_count` are appended to `GITHUB_OUTPUT`.

## API clients, the pin and the bounds

Two Falcon API clients exist and are never the same one:

| Client | Where it lives | Scopes | Used for |
|---|---|---|---|
| CI client | Organisation (GitHub) or group (GitLab) secrets, scoped to Consumer repositories | Cloud Security Tools Download: READ; Infrastructure as Code: READ and WRITE | The Gate: CLI download, scan with cloud rules, upload |
| Mapping client | A laptop, never CI | CSPM registration: READ; Cloud Security Policies: READ; Cloud Security API Detections: READ; Cloud Security API Assets: READ | The IaC-rule-to-IOM mapping measurement (ADR 0005) |

CSPM registration WRITE is never granted to either. A leaked CI credential can download the CLI and scan; it cannot enumerate the tenant's IOMs or assets.

**The pin.** The CLI version and the SHA-256 of its linux/amd64 archive are constants in `src/fcs_deploy_gate/download.py`. To fill or bump them, from a machine with the CI client's credentials in the environment:

```sh
fcs-deploy-gate pin --region us-gov-1 [--version X.Y.Z]
```

It prints `version=`, `sha256=`, `file_name=` and `size=` for the published release (the pinned version by default). Put the values in the constants by pull request, with a note on rule and severity changes between versions. The Gate refuses to download while the hash is empty, and refuses to use an archive whose reported or actual hash differs from it.

**The token on the command line.** The CLI takes the short-lived token as one argument, `--falcon-token`, its documented interface. ADR 0003's "credentials in the environment" refers to the long-lived client secret, which never reaches the CLI at all; the token lives thirty minutes, and the Gate redacts it from any CLI output it quotes.

**Bounds.** Three attempts with waits of ten then thirty seconds, for the download and for each scan separately; a 300-second scan timeout passed to the CLI; a 60-second timeout on each of the Gate's own HTTP calls. Adapters set a fifteen-minute job timeout.

## Baseline

Change-aware Scope needs the Consumer repository checked out at the Baseline ref in a second directory, which the adapter does and passes as `--baseline-dir`, with the ref as `--baseline-ref`. The core scans the scanned path's counterpart inside it, so Finding paths from both scans share one root; a path that did not exist at the Baseline is a new root, and every Finding in it is new. The ref comes from one place:

```sh
fcs-deploy-gate resolve-baseline --pipeline merge-request|branch \
    --explicit-ref "$REF" --merge-base "$MERGE_BASE" --previous-commit "$BEFORE_SHA"
```

It prints one line, `ref=<ref>` or `error=<message>`, and exits 0 either way, so an adapter can append it to its outputs and pass the result on without logic of its own. The precedence is: an explicit ref the Consumer names wins; otherwise, in a merge-request or pull-request pipeline, the merge base with the target branch; otherwise, in a branch pipeline, the commit before the push. An empty value or an all-zeros commit is unusable. A first push to a branch has no previous commit, so it needs an explicit ref.

The previous-commit default assumes a branch pipeline on a protected branch that is fed by gated merges: a Finding introduced by one merge is new, and blocked, in that pipeline. On an unprotected branch two pushes in a row would advance the Baseline past an unfixed Finding, which is why the merge-request pipeline compares against the merge base instead, and why tracking the last deployed ref is deferred rather than solved by "previous commit".

An error line is passed to `run` as `--baseline-error`. A Change-aware run with a Baseline error, without a Baseline directory, or whose Baseline scan does not complete, is a blocked Verdict carrying the message (ADR 0001, ADR 0002): there is no way to fall back to scanning the whole tree silently. In Whole-tree Scope the Baseline inputs are ignored.

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
