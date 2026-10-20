# `fcs scan iac` contract: inputs, exit codes, SARIF, credentials

Research date: 2026-10-19. All URLs were accessed on that date. This is the
second, focused pass after `docs/research/fcs-cli.md` (cited below as
"fcs-cli.md §N"). It does not restate what that file establishes; it answers
four questions and tries to close the gaps listed in its "Unverified or not
found" section. Where the only evidence is a CrowdStrike-written client (the
GitHub Action's scripts, the VS Code and IntelliJ plugins), that is said, because
code shows what one client does, not what the CLI guarantees. Two third-party
pipelines are quoted once, clearly labelled, as corroboration only.

The CLI is still closed source and its reference documentation is still behind
the Falcon login (fcs-cli.md "Unverified or not found"); no verbatim
`fcs scan iac --help` exists in any public source. Everything below is built
from CrowdStrike-published code, maintainer statements in CrowdStrike issue
trackers, the CrowdStrike developer center, and GitHub's own documentation.

## Sources

Ids start at T1 so they do not collide with S1-S16 in fcs-cli.md.

| Id | Source | Version / date the claim applies to |
|----|--------|-------------------------------------|
| T1 | fcs-action issue #48, comment by user `nareshmarella` 2025-11-19 (`gh api repos/CrowdStrike/fcs-action/issues/48/comments`): verbatim `github/codeql-action/upload-sarif` validator output quoting the CLI's JSON report | FCS CLI 2.1.5 (`fcs_version` in the quoted report); fcs-action v2.0.2 |
| T2 | fcs-action PR #83 "fix: correct falcon_token handling in fcs-scan.sh", body by maintainer `ryanjpayne`, merged 2026-07-21 | "Verified live against FCS CLI 3.4.2" |
| T3 | fcs-action PR #82 "feat!: support fcs cli release 4.0.0" (merged 2026-07-28) and PR #29 "feat!: Latest FCS CLI with Image Assessment" (merged 2025-08-14) | FCS CLI 4.0.0 / 2.0.x |
| T4 | fcs-action `fcs-scan.sh` at tag v1.0.2 (`fix_sarif`), PR #9 "fix: fixing sarif informationuri issue temporarily" (2024-08-13), PR #11, PR #13, PR #31 | fcs-action v1.0.2 (2024-08-13), CLI 0.x |
| T5 | fcs-action `fcs-scan.sh` at v2.0.0 (lines 27-104, 374-375) and v5.0.4 (lines 8-57, 268-304, 348-352, 490-549); `action.yml` at v2.0.2 (no default for `fail_on` or `timeout`) | as tagged |
| T6 | fcs-action `README.md` v5.0.4 (= fcs-cli.md S1), sections "Create a CrowdStrike API Client", "IaC Scanning Parameters", "Controlling Pipeline Flow with FCS CLI Exit Codes", "SARIF Output Transformation" | fcs-action v5.0.4 |
| T7 | fcs-action `json_to_sarif_converter.py` v5.0.4 (= fcs-cli.md S6), lines 15-54, 103-205, 795-848, 849-925, 978-1050 | fcs-action v5.0.4 |
| T8 | fcs-action PRs #86, #87, #89, #91 (bodies) | fcs-action v5.0.1-v5.0.4; mention CLI 3.3.1 |
| T9 | fcs-action issue #24 (maintainer `carlosmmatos` quoting CLI help, 2025-04-25) and PR #78/#79 (image exit code) | CLI 0.47.1 / 1.0.0; fcs-action v4.0.0 |
| T10 | fcs-action `tests/README.md` v5.0.4 | fcs-action v5.0.4 |
| T11 | VS Code extension https://github.com/CrowdStrike/vscode-falcon-cloud-security `main`: `src/core/cliManager.ts` (lines 59-63, 562-592, 760-795), `src/utils/fileTypeDetector.ts` (lines 20-55), `src/types/index.ts`, `src/providers/downloadWebviewProvider.ts` (lines 225-229), `src/core/helpManager.ts` (lines 801-806), `src/utils/constants.ts`, `package.json` | PR #10 "mirror plugin source for CLI v4.2.3"; `CLI_VERSION` 3.0.0-4.2.3 |
| T12 | IntelliJ plugin https://github.com/CrowdStrike/intellij-falcon-cloud-security `main`: `src/test/kotlin/.../services/FCSExitCodeHandlingTest.kt` (lines 1-33, 159-162), `services/FCSFileScanTriggerService.kt` (lines 178-206), `src/test/kotlin/.../FCSRealBinaryIntegrationTest.kt` (lines 38-53, 168-172), `services/FCSConfigurationService.kt` (lines 19-25, 181-300), `src/main/resources/documentation.md`, `src/main/resources/scripts/fcs_download.sh` (lines 383-404), `README.md` | PR #8 "mirror plugin source for CLI v4.2.3"; first published as "Initial release v3.2.0" 2026-07-09 |
| T13 | CrowdStrike developer center, Downloads collection https://developer.crowdstrike.com/api-reference/collections/downloads/ | live page |
| T14 | CrowdStrike developer center, Cloud Snapshots collection https://developer.crowdstrike.com/api-reference/collections/cloud-snapshots/ (holds the `/iac/` operations); FalconPy `src/falconpy/_endpoint/_cloud_snapshots.py`; gofalcon `falcon/client/cspg_iacapi/cspg_iacapi_client.go` | live page; `main` |
| T15 | CrowdStrike developer center, OAuth2 collection https://developer.crowdstrike.com/api-reference/collections/oauth2/ | live page |
| T16 | CrowdStrike developer center, Container Sensor Pull script https://developer.crowdstrike.com/falcon-sensor/scripts/bash/container-sensor-pull/ | live page |
| T17 | CrowdStrike Terraform provider docs `docs/resources/cloud_security_iac_custom_rule.md` (https://github.com/CrowdStrike/terraform-provider-crowdstrike) | `main` |
| T18 | GitHub Docs, "SARIF support for code scanning" https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning | live page |
| T19 | GitHub Docs, "Uploading a SARIF file to GitHub" https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github | live page |
| T20 | GitHub Docs, "Customizing your advanced setup for code scanning" (triggers) https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/customizing-your-advanced-setup-for-code-scanning | live page |
| T21 | GitHub REST API, "Upload an analysis as SARIF data" https://docs.github.com/en/rest/code-scanning/code-scanning#upload-an-analysis-as-sarif-data | API version 2022-11-28 |
| T22 | GitHub Docs, troubleshooting SARIF uploads: `.../troubleshoot-sarif-uploads/file-too-large`, `.../results-exceed-limit`, `.../sarif-invalid` under https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/ | live pages |
| T23 | `github/codeql-action` `main`: `upload-sarif/action.yml`, `src/upload-lib.ts` (lines 457-477, 587-637, 757-763), `src/fingerprints.ts` (lines 163-168, 245-291) | `main` |
| T24 | Third-party, NOT primary, corroboration only: `mile9299/log4jCICD` `Jenkinsfile` (commit 34d57105, 2025-10-17) and `yogeshsunny05/iac-fcs-pipeline` `Jenkinsfile` (commit 1ffc5129, 2026-02-17) | as dated |
| T25 | CrowdStrike product page https://www.crowdstrike.com/en-us/platform/cloud-security/iac/ | live page |

---

## 1. What `fcs scan iac` accepts

### Platforms and file types

The `--platforms` enum is unchanged from fcs-cli.md §2 (`Ansible`,
`AzureResourceManager`, `CloudFormation`, `Crossplane`, `DockerCompose`,
`Dockerfile`, `GoogleDeploymentManager`, `Kubernetes`, `OpenAPI`, `Pulumi`,
`ServerlessFW`, `Terraform`; T11 README, T12 README). The CrowdStrike marketing
page names only "Terraform, AWS CloudFormation, and others" (T25). The new
evidence on concrete file types is the full default pattern lists the two IDE
plugins feed to the CLI, which are broader than the README tables quoted in
fcs-cli.md §2:

- VS Code `DEFAULT_FILE_PATTERNS` (T11 `fileTypeDetector.ts` lines 20-35):
  `*.tf`, `*.tfvars`; `*.yaml`, `*.yml`; `*.json`; `Dockerfile`, `*.dockerfile`;
  `docker-compose.yml|yaml`, `compose.yml|yaml`; `*.ts`, `*.js`, `*.py`, `*.go`,
  `*.cs` (comment: "Pulumi (multiple languages)"); `serverless.yml|yaml`;
  `azuredeploy.json`, `*.parameters.json` (Azure ARM); `*.jinja` (Google
  Deployment Manager); `openapi.json|yaml`, `swagger.json|yaml`; `*.bicep`.
- IntelliJ `DEFAULT_FILE_PATTERNS` (T12 `FCSConfigurationService.kt` lines
  19-25): `*.tf`, `*.tfvars`, `*.tfstate`, `*.json`, `*.yaml`, `*.yml`, `*.xml`,
  `*.hcl`, `*.rego`, `*.dockerfile`, `*.jinja`, `*.bicep`, `Dockerfile`. The
  plugin's detection test asserts `terraform.tfstate` and `serverless.yml` are
  IaC files (T12 `FCSIaCFileDetectionTest.kt` lines 52, 81-82).
- IntelliJ's bundled help page (T12 `documentation.md`, "Supported File Types")
  is the first CrowdStrike text that names Helm: "Terraform (`.tf`, `.tfvars`);
  CloudFormation (`.json`, `.yaml`, `.yml`); Kubernetes manifests (`.yaml`,
  `.yml`); Helm charts; Docker files (`Dockerfile`); Serverless Framework files
  (`serverless.yml`); Azure Resource Manager templates (`.json`); Bicep files
  (`.bicep`); Pulumi (TypeScript, JavaScript, Python, Go)".

So, per input type asked about:

| Input | Evidence | Status |
|-------|----------|--------|
| Terraform `.tf`, `.tfvars`, local modules | Both plugins; `Terraform` platform (T11, T12); CLI resolves modules (`--module-cache`, fcs-cli.md §2) | confirmed |
| Terraform `.hcl`, `.tfstate` | IntelliJ patterns only (T12) | inferred (plugin passes them; CLI handling unknown) |
| CloudFormation YAML/JSON | Platform enum; both plugins (T11, T12) | confirmed |
| Kubernetes manifests | Platform enum; both plugins (T11, T12) | confirmed |
| Helm charts | Named only in T12 `documentation.md`; no `--platforms` value; neither plugin has a `Chart.yaml`/`templates/` pattern (covered by `*.yaml`) | inferred: raw template YAML is handed to the CLI; whether it renders Go templates is unknown |
| Dockerfile, compose | Platform enum; both plugins (T11, T12) | confirmed |
| Bicep | Both plugins pass `*.bicep` (T11, T12); still no `--platforms` value (fcs-cli.md §2) | inferred |
| ARM | `AzureResourceManager` platform; `azuredeploy.json`, `*.parameters.json` (T11) | confirmed |
| Terraform plan (`terraform show -json` or binary) | No mention in any CrowdStrike source: not in either plugin's patterns, help pages, README, action inputs, PR bodies, or the product page (T3, T6, T11, T12, T25; web search 2026-10-19 "fcs scan iac terraform plan / plan.json / tfplan" found nothing) | unverified; see below |

On plan files specifically: a plan JSON is a `.json` file, so the CLI will
accept it as an input path and try its JSON parsers (CloudFormation, ARM,
OpenAPI), but nothing suggests it recognises the `planned_values` /
`resource_changes` schema; a binary plan is a zip archive that matches no
pattern. The CLI's design is source-oriented: it downloads Terraform modules
during a scan (`--module-cache`, "Cache downloaded Terraform modules to disk
across scans", T6; listed as a 4.0.x IaC input in T3), which a plan-based
scanner would not need. Treat plan scanning as unsupported until a login-walled
doc or a test says otherwise.

### Multiple `--path`, `.gitignore`, remote modules, limits

- Multiple paths: VS Code passes one `--path` per file with the comment "Add
  each path as a separate argument (CLI expects multiple --path arguments or
  directories)" (T11 lines 573-576); IntelliJ passes a single `--path` with
  comma-joined paths (`getScanPaths().joinToString(",")`, T12 lines 190-191).
  Both clients are validated against CLI 4.2.3, so both spellings work.
  Confirmed by client code.
- `.gitignore`: auto-excluded since CLI 4.0.x, `--exclude-gitignore` disables
  (fcs-cli.md §2; T3 lists `exclude_gitignore` as a 4.0.x input). The report
  counts what was skipped: `stats.files_stats {total, failed_to_scan, skipped}`
  (`"total": 78, "failed_to_scan": 0, "skipped": 9` in the CLI 2.1.5 report,
  T1). Confirmed.
- Remote modules: only the `--module-cache` flag text (T3, T6) shows modules
  are downloaded. No source says what happens when a registry is unreachable;
  the one documented silent degradation is for rules, not modules ("the scan
  silently fell back to local rules only", T2). Inferred.
- File size: `--max-file-size` default 100 MB (fcs-cli.md §2). The flag
  predates 4.0: the CLI 2.1.5 report echoes `"max-file-size": 100` among its
  effective flags with no such input set (T1; T5 action.yml v2.0.2 has no
  `max_file_size` input). The "4.0.x+" label in T6 is about the action input.
  Confirmed.
- File count: no limit found in any source. The VS Code extension's 10 MB
  cap is on CLI stdout, not files (T11 `constants.ts` `MAX_CLI_OUTPUT`).
  Unverified (none found).
- Effective-flag echo: the JSON report carries a `flags` object with the
  effective `fail-on`, `max-file-size`, `output-path`, `path`, `policy-rule`,
  `report-formats`, `timeout` (T1, CLI 2.1.5). A gate can read back what the
  CLI actually used instead of trusting its own argument list.
- Timeout default: the same report shows `"timeout": 500` with no `timeout`
  input set and no action default (T1, T5), so 500 s was the CLI 2.1.5 default;
  the README and VS Code now say 300 (fcs-cli.md §6). The default changed
  between CLI generations; pass `--timeout` explicitly.

Status: platforms, Terraform source, CloudFormation, Kubernetes, Dockerfile,
ARM: confirmed. Bicep, Helm, `.tfstate`/`.hcl`: inferred from plugin patterns
only. Terraform plan files: unverified, no evidence of support. Multiple
`--path`: confirmed (both spellings). `.gitignore` and `--max-file-size`:
confirmed. Remote module behaviour and any file-count limit: unverified.

## 2. Exit codes and severity thresholds

### `--fail-on` syntax and default

Syntax is as in fcs-cli.md §3 (`--fail-on critical=N,high=N,medium=N,informational=N`;
JSON config key `fail-on` as an array). New evidence settles the default
(fcs-cli.md gap 3): the CLI 2.1.5 report pasted in T1 came from a workflow
(quoted in the same issue) with no `fail_on` input, and fcs-action v2.0.2 sets
no default for `fail_on` (T5), yet the report's `flags` block reads

```
"fail-on": ["critical=1", "high=1", "medium=1", "informational=1"]
```

so the all-ones default is the CLI's own, at least in 2.1.5. Confirmed
(user-pasted CLI output).

### `>=` or `>`

No CLI text states it. The README explains `fail_on: 'critical=1,high=1,medium=1,informational=1'`
as "This configuration will cause a non-zero exit code if ANY issues are found
at these severity levels" (T6 "How Exit Codes Work"), which only holds if the
test is `count >= N`. IntelliJ suppresses the failing code with `=100` for all
four levels ("Add fail-on flag to avoid exit code 40", T12 lines 223-225), which
is consistent with either. Inferred: `>=`.

### Exit-code table

Four CrowdStrike-authored statements exist, and they do not agree with each
other on the middle of the range:

| Code | VS Code `cliManager.ts` (T11, CLI 4.2.3 era) | IntelliJ `FCSExitCodeHandlingTest.kt` (T12, "EXIT CODE CONTRACT (from FCS CLI docs)") | IntelliJ runtime (T12 trigger service, real-binary test) |
|------|--------------------------------------------|------------------------------------------------------------------------------------|-----------------------------------------------------------|
| 0 | "Clean scan, no findings" | "scan completed, no findings" | success |
| 1 | "Scan completed with warnings" (in `VALID_SCAN_EXIT_CODES`) | "general error" | failure |
| 2 | "Scan completed with warnings" | "invalid arguments" | failure |
| 10 | "informational findings" | "binary/config error" | failure |
| 20 | "medium findings" | "auth error" | failure |
| 30 | "high findings" | "network error" | failure |
| 40 | "critical findings"; separately "Successful scan WITH findings (this is normal!)" | "scan completed WITH findings (success — findings are normal output, not an error)"; `SUCCESS_CODES = setOf(0, 40)` | not special-cased |
| 50 | not mentioned | not mentioned | accepted as a completed scan: `if (exitCode != 0 && exitCode != 50)` treats everything else as "Scan failed"; the real-binary integration test asserts `exitCode == 0 || exitCode == 50` on fixture files and `!= 0 && != 50` on a nonexistent path |
| 201-207 | "Genuine CLI errors" | not mentioned | not mentioned |

Two third-party Jenkins pipelines (T24, not primary) agree with the VS Code
severity-band reading: one maps, "based on CrowdStrike FCS documentation",
`0` to success, `30` to "found policy violations", `40` to "found critical
policy violations", anything else to failure (mile9299, 2025-10-17); the other
treats `exitCode >= 30` as "found vulnerabilities" (yogeshsunny05, 2026-02-17).

What is consistent across every source: `0` means a completed scan with
nothing that trips `--fail-on`; `40` means a completed scan whose findings
tripped `--fail-on` (IntelliJ sets `=100` thresholds precisely "to avoid exit
code 40"); and some non-zero values are real errors. What is not settled:
whether 10/20/30 are lower severity bands (VS Code, both third parties) or
error classes (IntelliJ test comment); what 50 is (observed by IntelliJ as a
successful completion of a real 3.x/4.x binary with thresholds at 100, so
plausibly "completed, findings present, thresholds not tripped", but that is a
guess); and whether errors are 1-30 or 201-207. The IntelliJ comment claims to
quote the CLI docs; the VS Code comment is equally CrowdStrike-authored and was
re-mirrored for CLI 4.2.3 (T11 PR #10), so neither can be preferred.

Other codes seen in CrowdStrike sources: image scans exit `2` when the image
assessment policy fails (T9 #78/#79; fcs-cli.md §3), which is unrelated to IaC.
CLI error strings observed (exit code not shown): `Error: unknown argument(s)
for --exclude-severities: low, info` (T9 #24), `invalid target path: <token>`
(T2), `write permission check on output path: ./reports failed` (T8 #91).

### Secrets and thresholds

No source says secrets count toward `--fail-on`. Evidence that they cannot be
counted by a `severity=N` threshold: `detection_summary` has exactly `total`,
`critical`, `high`, `medium`, `informational` (T11 `types/index.ts`; the T1
report shows `"detection_summary": {"total": 0}`), with no secrets field; the
converter reads `type`, `file_path`, `line_number`, `confidence`,
`pattern_matched`, `entropy_score`, `remediation` from each IaC secret and
hard-codes the SARIF level to `error` with the comment "Secrets in IaC are
always high severity" rather than reading a severity (T7 lines 795-848); and
neither IDE plugin parses `secrets_analysis` at all (T11 `linter.ts`, T12
`FCSResultsService.kt` contain no reference to secrets). So secrets carry no
severity in the JSON (inferred) and the only lever is `--disable-secrets-scan`.
Whether the CLI adds secrets to `total` or trips the exit code on them is
unverified.

### Can a scan error be told from "findings present" by exit code alone?

Partly. `0` and `40` are unambiguous across all sources. For anything else the
two CrowdStrike readings conflict, so a gate should not decide on the code
alone. Two reliable secondary signals exist: (1) the JSON report is written
only when the scan completed, and VS Code treats "exit 0 and no report" as "no
IaC content found" and "non-zero and no report" as an error (T11 lines
597-611); (2) the stdout line `Results saved to file: <path>` (ANSI-bold, may
be preceded by `\r`; T5 v5.0.4 lines 49-57, T8 #89) marks a written report on
CLI 2.3.x and 4.x, but CLI 3.3.1 did not print it (T8 #86), so do not depend on
it across versions.

Status: default `--fail-on` all-ones: confirmed (T1). `>=`: inferred. `0` =
clean and `40` = thresholds tripped: confirmed by three independent CrowdStrike
sources. `20`: observed 2026-10-20 on the first live scan (CLI 4.2.3, pinned,
us-gov-1, a Terraform directory with one Lambda function, `--fail-on` all-ones):
the scan reached 100%, wrote its JSON report and exited 20; the report's highest
Severity was medium (one Finding) with six informational, which confirms the VS
Code severity-band reading and not IntelliJ's "auth error". The same report named
resources by their `name` attribute, unresolved (`/aws/lambda/${local.function_name}`,
`fcs-gate-pilot-<unknown-sufix>` from `name_prefix`), by the Terraform label when
there is no `name` (`pilot` for a function with `function_name`), and `n/a` for an
account-level rule. Attributes are read as written: `tags = local.tags` still raised
"Resource Not Using Tags" on every resource, and a literal map did not (same scans).
"IAM Access Analyzer Not Enabled" (resource `n/a`) was raised on two of four scans of
the same module and not on the other two, with no change in the module that explains
it; a Consumer's Exclusion for it is then reported stale on the scans that lack it.
The upload with the token: confirmed 2026-10-20, the same scan appeared in the console's
IaC scan view under the `--project-name` given, with the KMS and retention Findings on
the log group as in the report. The Gate now accepts 0, 10, 20, 30 and 40 as completed
when a report was written. Meaning of 1, 2, 50, 201-207: unverified (conflicting CrowdStrike
comments). Secrets in thresholds: unverified (inferred not
countable). Error-vs-findings by code alone: unverified beyond {0, 40}.

## 3. SARIF and GitHub code scanning

### (a) Does the CLI emit SARIF itself, and what is in it?

Yes. `sarif` is an allowed `--report-formats` value for IaC (fcs-cli.md §5),
and in 2024 the action used it directly: fcs-action v1.0.2's `fcs-scan.sh` ran
`fcs iac scan --report-formats sarif`, then `fix_sarif` searched the output
directory for `*-scan-results.sarif` and patched it with

```
jq 'if .runs[0].tool.driver.informationUri == "" then
      .runs[0].tool.driver.informationUri = "https://crowdstrike.com" else . end'
```

under the comment "TODO: Remove these functions when upstream fix is in place"
(T4; PR #9 "Add fix for issue with sarif uri. Eventually this will be fixed
upstream"). That is the only public look at the native file: SARIF with
`runs[0].tool.driver`, output name `<something>-scan-results.sarif`, and an
empty `informationUri`, which is not a valid URI and fails schema validation.
The README's "SARIF Output Transformation" list (T6) names `informationUri`,
result `level` values outside `error|warning|note|none`, an unsupported `type`
property on results, and results lacking a `locations` array. Those are
SARIF-only properties that do not exist in the JSON report the converter
actually reads, so the list can only describe the native SARIF; it is the best
public description of its defects, but it dates from the CLI 0.x/1.x era and
nothing shows whether CLI 4.x fixed them. Image scans also have native SARIF
(`--format sarif`; T10 "Different output formats (JSON, SARIF, CycloneDX)").

### (b) What GitHub code scanning requires of a SARIF file

From GitHub's own documentation (T18, T19, T20, T21, T22, T23):

- Format: SARIF `2.1.0` only; required properties must have explicit values
  ("The empty string is not supported for required properties") (T18).
- Required properties (T18, "Required" column): `sarifLog`: `$schema`,
  `version`, `runs[]`. `run`: `tool.driver`, `results[]`. `toolComponent`:
  `name`, `rules[]`. `reportingDescriptor`: `id`, `shortDescription.text`,
  `fullDescription.text`, `help.text` (`name` optional, max 255 chars;
  descriptions max 1,024 chars). `result`: `message.text`, `locations[]`,
  `partialFingerprints`. `physicalLocation`: `artifactLocation.uri`,
  `region.startLine`, `region.startColumn`, `region.endLine`,
  `region.endColumn`. The page is internally inconsistent: its minimal example
  omits `endLine`/`endColumn`, and it describes fallback behaviour when
  `partialFingerprints` is absent (below), so "Required" there means "needed
  for full functionality" rather than "rejected if missing".
- Locations: "At least one location is required for code scanning to display
  a result"; only the first location is used; relative URIs resolve from the
  repository root; absolute URIs are relativised only via `checkout_path` /
  `checkout_uri` / `invocations[0].workingDirectory.uri`, and an absolute URI
  whose scheme differs from the source root causes rejection; symlinked files
  cannot be displayed (T18).
- `partialFingerprints`: only `primaryLocationLineHash` is used, to match
  results across runs; "If the `upload-sarif` action receives a file without
  fingerprints, it tries to populate them from source files"; via the REST API
  without fingerprints, alerts still appear "but duplicates may appear" (T18).
  The action computes the hash only when the URI resolves to an existing file
  in the checkout ("Unable to compute fingerprint for non-existent file", T23
  `fingerprints.ts`).
- `security-severity`: on rules tagged `security`; valid range above 0.0 to
  10.0; mapping above 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low;
  zero or out of range means no severity (T18).
- `category`: `runAutomationDetails.id` is split at its last `/` into category
  and run id; optional; the `upload-sarif` `category` input ("String used by
  Code Scanning for matching the analyses", T23) is the usual way to set it.
  Uploading a second file with the same tool and category for a commit
  overwrites the earlier results, and multiple files for the same tool and
  category in one run make "the run ... fail" (T19).
- Limits (T18, T21, T22): 20 runs per file; 25,000 results per run (only the
  top 5,000 kept, by severity); 25,000 rules per run; 100 tool extensions per
  run; 1,000 locations per result (100 kept); 20 tags per rule (10 kept);
  10,000 thread-flow locations per result (1,000 kept); 1,000,000 alerts per
  repository. Exceeding a hard maximum rejects the whole file ("Analysis SARIF
  file rejected due to result limits" etc., T22). File size: 10 MB
  gzip-compressed ("SARIF file is too large", `413`, T22); the REST endpoint
  takes the file gzip-compressed then Base64-encoded, 1,000 requests per hour
  per user or app installation, `validate` flag available (T21).
- Workflow: `permissions: security-events: write` "required for all
  workflows", `actions: read` "only required for workflows in private
  repositories" (T19). Private or internal repositories need GitHub Code
  Security (formerly Advanced Security) enabled (T22 `ghas-required`).
- Events: the upload page names `push` and `scheduled` (T19); the advanced
  setup page documents `push`, `pull_request` ("results appear as alerts in a
  pull request check"; scanning the merge commit "will produce more efficient
  and accurate results"), `merge_group` for merge queues, and `schedule` (T20);
  the REST API accepts `refs/heads/<branch>`, `refs/tags/<tag>`,
  `refs/pull/<n>/merge`, `refs/pull/<n>/head` (T21), and the `upload-sarif`
  `ref`/`sha` inputs are "Ignored for pull requests from forks" (T23).
- Validation: `upload-sarif` validates every non-CodeQL file against the OASIS
  SARIF 2.1.0 JSON schema before upload (`validateSarifFileSchema`, "Validating
  <file>", T23 `upload-lib.ts`), then adds fingerprints, checks that runs have
  unique categories, gzips and base64-encodes. The T1 transcript shows this
  step rejecting a file with `instance is not allowed to have the additional
  property "fcs_version"` (and `path`, `project_name`, `scan_type`, `flags`,
  `stats`): that file was the CLI's JSON report written to a `.sarif` path by
  an action bug fixed in v5.0.3 (T8 #89), so it demonstrates the validator, not
  a native-SARIF defect. Rejected files also surface as "SARIF file is
  invalid" (T22).

### (c) Why the action converts, and what the converter produces

The converter exists because native SARIF did not pass GitHub: v1.0.2 patched
`informationUri` (T4); v2.0.0 replaced that with "Python based JSON-to-Sarif
conversion tool to resolve GitHub Sarif compliance issues" (T3 PR #29) and
from then on never asks the CLI for SARIF (`prepare_report_formats_for_cli`
rewrites `sarif` to `json`, T5). Later GitHub-ingestion fixes were all on the
converted output: PR #31 "fix iac and uri concerns", #49 and #73
`security-severity`, #86/#87/#89/#91 file discovery (T8). Against the
requirements in (b), the v5.0.4 converter (T7) emits:

| Requirement | Converted SARIF (IaC) |
|-------------|------------------------|
| `$schema`, `version`, `runs` | `https://json.schemastore.org/sarif-2.1.0.json`, `2.1.0`, one run per JSON report |
| `tool.driver` | `name` "CrowdStrike FCS", `version` from `scanner_version` or `fcs_version` (fallback "1.0.0"), `informationUri` "https://crowdstrike.com", `rules[]` |
| Rules | `iac/<rule_uuid>`, `secret/<type>`, `policy/<policy_id>`; `shortDescription.text`, `fullDescription.text`; `help.text` (+ `help.markdown`) for rule detections and secrets, no `help` for policy violations; `properties.tags` (3-4 tags), `precision` "high", `security-severity` as a numeric string |
| Results | `ruleId`, `level` (critical/high -> `error`, medium -> `warning`, low/informational -> `note`), `message.text`, one location |
| Location: rule detections | `artifactLocation.uri` = `quote(detection.file, safe='')`, `region.startLine` only (no columns, no `endLine`) |
| Location: secrets, policy violations | `artifactLocation.uri` = `"unknown"`, no region |
| `partialFingerprints` | not emitted (no occurrence in the file) |
| `automationDetails` | not emitted; category comes from the `upload-sarif` `category` input or GitHub's auto-generated one |
| `originalUriBaseIds` | not emitted; URIs are taken as relative to the repository root |

Two caveats come straight from that code. First, `encode_uri_for_github` uses
`quote(uri, safe='')`, which encodes `/` as well: `modules/vpc/main.tf`
becomes `modules%2Fvpc%2Fmain.tf` and `./main.tf` becomes `.%2Fmain.tf`
(T7 lines 15-27; checked with Python's `urllib.parse.quote`). The comment says
the intent is to escape colons in the first path segment. Whether GitHub and
the action's fingerprint resolver decode `%2F` back to a path separator is not
stated in T18 or T23; if they do not, alerts will not map to files, PR
annotations will not appear, and fingerprints will not be computed. Second,
with no `partialFingerprints`, de-duplication across uploads depends entirely
on the action's fallback, which needs the file to exist at the given URI; for
`"unknown"` locations (every secret and policy violation) it never will, so
those alerts may duplicate on every upload (T18, T23).

Evidence that the converted file is ingested: the fcs-action repository itself
pushes it to code scanning (PR #13 "ci: enable sarif push"; the
`github-advanced-security` bot comments on PRs #13 and #31, T4), the README
example uploads it with `github/codeql-action/upload-sarif@v3` (T6), and the
v4.0.1/v5.0.x fixes were driven by what users saw in the Code Scanning UI
(T8). No public workflow log of a successful upload was found.

Conclusion:

- Native CLI SARIF: cannot be confirmed to ingest. It failed GitHub's
  validation in 2024 for an empty `informationUri` (T4), the README attributes
  three further GitHub-incompatibilities to it (T6), no CrowdStrike client has
  requested it since v2.0.0, and there is no public sample from CLI 4.x. Treat
  it as untested; if used, run it through `upload-sarif`'s schema validation or
  the REST `validate` flag first.
- Converted SARIF (action's `json_to_sarif_converter.py`): ingests, with the
  caveats above (percent-encoded slashes, no fingerprints, `"unknown"`
  locations without regions for secrets and policy violations, `startLine`
  only, no category, 5,000-result cap per run, and the README's example guard
  `if: steps.fcs.outputs.exit-code != 0` which never uploads a clean scan so
  alerts never auto-close, fcs-cli.md §5).
- Both: not demonstrated. Neither: not the case for the converted file.

Status: (a) native SARIF exists: confirmed; its current content: unverified.
(b) GitHub requirements: confirmed (GitHub docs). (c) converter rationale:
confirmed (T3, T4); converted-file ingestion: confirmed by CrowdStrike's own
use, with the file-mapping caveat unverified.

## 4. Credentials and API scopes

### Scopes by operation

| Step | Scope (verbatim where the source gives it) | Evidence | Status |
|------|--------------------------------------------|----------|--------|
| (a) Download the CLI via `FetchFilesDownloadInfoV2` (`GET /csdownloads/combined/files-download/v2`) | "Cloud Security Tools Download: READ" | T13 lists the scope on the operation; T3 PR #59 "Update required API scopes to include `Cloud Security Tools Download`"; fcs-cli.md §8-9 | confirmed |
| (a') Deprecated download operations (`DownloadFile`, `EnumerateFile`, `FetchFilesDownloadInfo` v1) | "Infrastructure as Code (IaC): READ", all "This operation is deprecated." | T13 | confirmed (avoid) |
| (a'') Pulling the `fcs` container image with `falcon-container-sensor-pull.sh -t fcs` | "Sensor Download (read)" and "Infrastructure as Code (read)" ("the minimum required to retrieve the images") | T16 | confirmed, but a different delivery path (fcs-cli.md §9) |
| (b) IaC scan with cloud custom rules | "Infrastructure as Code: READ & WRITE", "For IaC scanning only" | T6 scope table; T12 README lists only Cloud Security Tools Download READ and Infrastructure as Code READ & WRITE for an IaC-only client; T11 help page "Infrastructure as Code: Read / Write" | confirmed as the documented set; READ-only sufficiency unverified |
| (c) Upload results | same "Infrastructure as Code: READ & WRITE" | T6; no finer statement anywhere | inferred (WRITE presumably for upload) |

What the public API exposes under the IaC scope: the developer center files
the `/iac/` operations under the Cloud Snapshots collection (T14):
`CombinedDetections` `GET /iac/combined/detections/v1` ("Search IaC Detections
using a query in Falcon Query Language", scope "Infrastructure as Code (IaC):
READ") and `GetCredentialsIAC` `GET /iac/entities/image-registry-credentials/v1`
(same scope). FalconPy's `_cloud_snapshots.py` and gofalcon's `cspg_iacapi`
client carry the same two operations and nothing else under `/iac/` (T14). No
public operation fetches rules or uploads scan results, so the CLI uses
endpoints that are not in the public SDKs; their scope cannot be mapped from
FalconPy. The one adjacent public data point is the CrowdStrike Terraform
provider's `crowdstrike_cloud_security_iac_custom_rule` resource, which needs
"Cloud Security Policies | Read & Write" and "Infrastructure-as-Code | Read &
Write", is "custom Rego policies", and says "Currently only Terraform is
supported" for `iac_framework` (T17). That is the console-side management of
the cloud custom rules the CLI fetches; whether the CLI's fetch needs the
Cloud Security Policies scope too is unverified (the README and plugins do not
list it, and PR #83 saw "Fetching custom rules from Falcon Cloud" with a token
whose scopes are not stated, T2).

Observable behaviour when auth or region is missing on a 3.x/4.x CLI: no hard
error; "the scan silently fell back to local rules only" (T2). A gate that
depends on cloud rules must check for the "Fetching custom rules from Falcon
Cloud" line (T2) or compare `stats.rule_stats` across runs (T1 shows
`total_rules`, `rules_enabled`, `rules_failed_to_execute`), because the exit
code and report will look normal.

### Token lifetime and `--falcon-token`

- OAuth2: `POST /oauth2/token` (`oauth2AccessToken`) with `client_id`,
  `client_secret`, optional `member_cid`; the token has a "standard 30-minute
  expiry" and can be revoked early via `POST /oauth2/revoke` with basic auth
  (T15). Confirmed. One token therefore covers download plus a scan whose
  `--timeout` default is 300 s (fcs-cli.md §6).
- `--falcon-token`: accepted by the CLI. A CrowdStrike maintainer tested it
  live against CLI 3.4.2 (T2): the CLI documents a `BEARER <token>` form but
  "accepts the bare token"; the token must be one argument (split at the
  space it became `invalid target path: <token>`); and "the CLI requires a
  region (or a configured profile) to resolve the API base URL when
  `--falcon-token` is used", otherwise it silently uses local rules. The action
  therefore passes `--falcon-token <t>` plus `--falcon-region <r>` as separate
  quoted arguments (T5 v5.0.4 lines 494-507). Confirmed.

### Environment variables the CLI reads

- `FCS_CLIENT_ID`, `FCS_CLIENT_SECRET`: exported by the action immediately
  before every CLI invocation since v2.0.0 (`export FCS_CLIENT_ID="$INPUT_FALCON_CLIENT_ID"`,
  `export FCS_CLIENT_SECRET="$FALCON_CLIENT_SECRET"`, T5 v2.0.0 lines 374-375,
  v5.0.4 lines 532-533), while `--client-id`/`--client-secret` flags are
  passed only when `upload_results` is true (T5 lines 348-352). Since CLI 4.x
  fetches cloud rules on every scan without upload (fcs-cli.md §6), the
  no-upload path authenticates through those variables (or a profile). Two
  third-party pipelines run the bare CLI or its container with only
  `FCS_CLIENT_ID`/`FCS_CLIENT_SECRET` in the environment and no credential
  flags (`docker run -e FCS_CLIENT_ID -e FCS_CLIENT_SECRET ... scan iac -p
  <path> --fail-on "high=20" --falcon-region <r> --upload-results`;
  `fcs.exe scan iac --path . --upload`; T24, not primary). Confirmed as the
  names CrowdStrike's own client sets; the CLI's reading of them is inferred
  from the no-upload path and the third-party corroboration.
- `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, `FALCON_CLOUD`, `FCS_VERSION`,
  `FCS_MAX_VERSION`: read by the IntelliJ download script (T12 `fcs_download.sh`
  lines 383-388, which also `unset`s the two credentials after reading them)
  and offered by the VS Code download form ("Tip: You can also set credentials
  via environment variables: `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`,
  `FALCON_CLOUD`, `FCS_VERSION`, `HTTPS_PROXY`", T11 `downloadWebviewProvider.ts`
  lines 225-229). These are consumed by the plugins' own download step, not
  by the CLI. The action's `FALCON_CLIENT_SECRET` likewise feeds the download
  script (fcs-cli.md §7). Whether the CLI itself also reads `FALCON_*` is
  unverified; no CrowdStrike code relies on it.
- `HTTPS_PROXY` / `HTTP_PROXY`: IntelliJ copies `HTTPS_PROXY` into both
  variables on the CLI process (T12 `FCSFileScanTriggerService.kt` lines
  183-187), so the CLI honours proxy variables. Confirmed by client code.
- No other `FCS_`/`FALCON_` variable appears in any CrowdStrike source
  (`gh search code --owner CrowdStrike 'FCS_CLIENT_ID'` returns only
  `fcs-action/fcs-scan.sh`).

Status: download scope: confirmed. Scan and upload scopes: confirmed as the
documented READ & WRITE set; minimum set, and any Cloud Security Policies
requirement: unverified. Token lifetime 30 minutes: confirmed. `--falcon-token`:
confirmed (live test by maintainer). `FCS_CLIENT_ID`/`FCS_CLIENT_SECRET`:
confirmed as what the action sets, inferred as what the CLI reads; `FALCON_*`
for the CLI: unverified.

## Gaps still open

1. A verbatim `fcs scan iac --help` for any 4.x version (all flag knowledge
   is still the subset CrowdStrike clients exercise).
2. The exit-code table: the meaning of 1, 2, 10, 20, 30, 50 and 201-207. Two
   CrowdStrike-authored comments conflict; only 0 and 40 are safe.
3. Whether `--fail-on` compares `>=` (inferred from README prose only).
4. Whether secrets findings affect `total` or the exit code.
5. Terraform plan files (JSON or binary) as input: no evidence either way;
   likely unsupported.
6. Helm, Bicep, `.tfstate`: named by plugin docs/patterns, not by a CLI
   enum; rendering behaviour for Helm unknown.
7. Native CLI SARIF content for CLI 4.x and whether GitHub ingests it.
8. Whether GitHub decodes the converter's `%2F`-encoded paths; whether CLI
   `file` values are relative to the repository root or to `--path`.
9. The minimum scope set for a scan without upload, and whether cloud-rule
   fetching needs Cloud Security Policies READ in addition to IaC.
10. Whether the CLI reads `FALCON_CLIENT_ID`/`FALCON_CLIENT_SECRET`; whether
    `--upload` or `--upload-results` is the 4.x IaC spelling (both appear in
    CrowdStrike and third-party invocations).
11. What exit code 50 denotes.

## Implications for the gate

- Decide on the JSON report, not the exit code: treat `0` as pass, `40` as
  "thresholds tripped", require the report file to exist, and classify any
  other code as a scan error to be investigated rather than as pass or fail.
- Read `flags.fail-on` and `stats.rule_stats` back out of the report to
  prove which thresholds and how many rules were actually in force; a missing
  region or bad token degrades silently to local rules.
- Pass `--fail-on`, `--timeout` and `--falcon-region` explicitly; the CLI's
  defaults have changed between generations (timeout 500 -> 300) and the
  region is required for token auth and cloud rules.
- Scan Terraform source, not plans. If the pipeline only has a plan at gate
  time, the gate must run earlier, on the module source.
- Secrets will not be governed by `--fail-on`; decide separately whether
  `secrets_analysis.secrets` being non-empty blocks a deploy.
- Prefer the converted SARIF for GitHub code scanning; before relying on
  file-level annotations, test one upload with a nested path and confirm the
  alert maps to the file (the `%2F` encoding question); upload on clean runs
  too so alerts auto-close; set `category` per repository/branch.
- Grant the API client exactly Cloud Security Tools Download READ and
  Infrastructure as Code READ & WRITE; pin the CLI version via `file_version`
  and bump deliberately.
- Supply credentials as `FCS_CLIENT_ID`/`FCS_CLIENT_SECRET` (or a short-lived
  `--falcon-token` with `--falcon-region`), never as `--client-secret` on the
  command line; a token lives 30 minutes, which is enough for download plus a
  default 300 s scan.
- Give the job `security-events: write` (plus `actions: read` on private
  repositories), keep the gzip-compressed SARIF under 10 MB, and expect at
  most 5,000 results per run to survive on the GitHub side.
- Budget for silent degradation: log the "Fetching custom rules from Falcon
  Cloud" line and the `files_stats.skipped` count on every run so a regression
  in rule coverage or `.gitignore` exclusions is visible.
