# CrowdStrike FCS CLI and `fcs-action`: primary-source research

Research date: 2026-10-19. All URLs below were accessed on that date unless noted.

Scope: what the CrowdStrike Falcon Cloud Security CLI (`fcs`) and the official
`CrowdStrike/fcs-action` GitHub Action actually do, established only from
sources CrowdStrike publishes. Where a claim comes from code CrowdStrike wrote
(the action's shell scripts, the VS Code and IntelliJ plugins, the FalconPy /
gofalcon SDK endpoint tables) rather than from prose documentation, that is
stated, because code shows what one client does, not what the CLI guarantees.

The CLI itself is closed source. There is no `fcs` or `fcs-cli` repository in
the CrowdStrike GitHub organisation (checked with `gh api repos/CrowdStrike/{fcs,fcs-cli,falcon-cloud-security-cli}` -> 404, and `gh search repos --owner CrowdStrike fcs`), and no verbatim `fcs --help` dump exists in any public CrowdStrike source. The product documentation at `docs.crowdstrike.com` and `falcon.crowdstrike.com/documentation` is behind a login wall (see "Unverified or not found").

## Sources

| Id | Source | Version / commit the claim applies to |
|----|--------|---------------------------------------|
| S1 | `README.md` of https://github.com/CrowdStrike/fcs-action (raw: https://raw.githubusercontent.com/CrowdStrike/fcs-action/v5.0.4/README.md) | fcs-action v5.0.4 (2026-10-07); documents FCS CLI 2.2.x, 2.3.x, 4.0.x behaviour |
| S2 | `action.yml` https://raw.githubusercontent.com/CrowdStrike/fcs-action/v5.0.4/action.yml | fcs-action v5.0.4 |
| S3 | `fcs-scan.sh` https://raw.githubusercontent.com/CrowdStrike/fcs-action/v5.0.4/fcs-scan.sh | fcs-action v5.0.4 |
| S4 | `fcs_download.sh` https://raw.githubusercontent.com/CrowdStrike/fcs-action/v5.0.4/fcs_download.sh | fcs-action v5.0.4 |
| S5 | `CHANGELOG.md` and Releases: https://github.com/CrowdStrike/fcs-action/releases (also `gh api repos/CrowdStrike/fcs-action/releases` and `/tags`) | v1.0.0 (2024-07-12) through v5.0.4 (2026-10-07) |
| S6 | `json_to_sarif_converter.py` https://raw.githubusercontent.com/CrowdStrike/fcs-action/v5.0.4/json_to_sarif_converter.py | fcs-action v5.0.4 |
| S7 | `tests/README.md`, `tests/config.json` at v5.0.4; `.github/workflows/release.yml` at v5.0.4 | fcs-action v5.0.4 |
| S8 | Older fcs-action files: `README.md` at v4.0.2 and v1.1.0; `fcs-scan.sh` and `fcs-pull.sh` at v1.1.0; `fcs_download.py` at v2.0.3 | as tagged |
| S9 | fcs-action issues with CrowdStrike-maintainer replies: #24, #38, #47, #58, #75, #78 (`gh issue view N -R CrowdStrike/fcs-action`) | 2025-04 to 2026-04 |
| S10 | https://github.com/CrowdStrike/vscode-falcon-cloud-security : `README.md`, `package.json` (extension 4.2.3), `src/core/cliManager.ts`, `src/utils/constants.ts`, `src/providers/codeActionProvider.ts`, `src/types/index.ts`, `src/core/helpManager.ts`, `src/test/suite/code-action-simple.test.ts` | `main` on 2026-10-19; extension validated for CLI 3.0.0 to 4.2.3 |
| S11 | https://github.com/CrowdStrike/intellij-falcon-cloud-security : `README.md`, `src/main/resources/scripts/fcs_download.sh`, `services/FCSConfigurationService.kt`, `services/FCSFileScanTriggerService.kt`, `services/FCSBinaryService.kt`, `services/FCSResultsService.kt` | `main` on 2026-10-19; plugin validated for CLI 3.0.0 to 4.2.3 |
| S12 | CrowdStrike Developer Center, Downloads API collection: https://developer.crowdstrike.com/api-reference/collections/downloads/ | live page |
| S13 | FalconPy endpoint table https://raw.githubusercontent.com/CrowdStrike/falconpy/main/src/falconpy/_endpoint/_downloads.py | `main` |
| S14 | gofalcon: `falcon/client/downloads_api/downloads_api_client.go`, `falcon/models/models_combined_files_download_response.go`, `falcon/models/models_combined_file_download_resource.go` (https://github.com/CrowdStrike/gofalcon) | `main` |
| S15 | GitHub Marketplace listing https://github.com/marketplace/actions/crowdstrike-fcs-cli-github-action | shows v5.0.4 as Latest, publisher CrowdStrike, verified creator |
| S16 | Login-walled CrowdStrike docs (not readable; listed in the last section) | n/a |

---

## 1. Which `fcs` subcommands exist

Established from code that invokes the binary, not from a help dump.

| Subcommand | What it does | Evidence |
|-----------|--------------|----------|
| `fcs scan iac [flags]` | Scans IaC files/dirs/git repos for misconfigurations and secrets, writes report(s), exits per `--fail-on`. | S3 line 516: `$FCS_CLI_BIN scan iac $args "${secure_args[@]}"`. S10 `cliManager.ts` builds `['scan', 'iac', '--report-formats', 'json', '--output-path', tempDir, '--policy-rule', 'local', '--path', ...]`. S11 `FCSConfigurationService.kt` `command.add("scan"); command.add("iac")`. |
| `fcs scan image <image> [flags]` | Scans a container image (vulnerabilities, malware, secrets, detections), optionally SBOM; exit code set by the tenant's Image Assessment policy. | S3 line 519: `$FCS_CLI_BIN scan image $INPUT_IMAGE $args`. S1 "Image Scans" section. S7 `tests/README.md` references `./fcs scan image --help`. |
| `fcs version` | Prints the version; output has the form `fcs version: X.Y.Z`. | S10 README "run `fcs version`"; S11 `FCSBinaryService.kt` runs `binaryPath version` and strips the prefix `"fcs version: "`. |
| `fcs migrate-config` | Migrates the CLI v2 config `~/.crowdstrike/fcs_profiles.json` to the v3+ format `~/.crowdstrike/fcs.json`. | S10 `cliManager.ts` lines 512-526 and `helpManager.ts` line 743/968. |

Verb order changed between CLI generations. fcs-action v1.1.0 ran `$FCS_CLI_BIN iac scan $args` (S8, `fcs-scan.sh` at v1.1.0, line 149); from fcs-action v2.0.0 ("Latest FCS CLI with Image Assessment", breaking, S5) the action runs `fcs scan iac`. So `fcs iac scan` is the CLI 0.x/1.x spelling; CLI 2.x+ is `fcs scan iac`. The README's compatibility table (S1) says CLI >= 2.0.0 needs action >= 2.0.0.

Not found in any public CrowdStrike source: any other top-level subcommand (no `configure`, `login`, `rules`, `policy`, etc. are referenced anywhere), and no verbatim `--help` text except two option stanzas quoted by a maintainer in S9 #24 (see Q3).

## 2. Supported IaC platforms and file types for `fcs scan iac`

Platform names accepted by `--platforms` / `--exclude-platforms` (S1 "Supported Platforms"; identical list in S10 README `fcs.platforms` and S11 README "Platforms"):

`Ansible`, `AzureResourceManager`, `CloudFormation`, `Crossplane`, `DockerCompose`, `Dockerfile`, `GoogleDeploymentManager`, `Kubernetes`, `OpenAPI`, `Pulumi`, `ServerlessFW`, `Terraform`.

File types the IDE plugins hand to the CLI (these are the plugins' own filters, so they are a lower bound on what the CLI parses, not a CLI spec):

- VS Code (S10 README "Supported file types", extension 4.2.3): Terraform `.tf`, `.tfvars`; YAML `.yaml`, `.yml` (Kubernetes, Ansible, CloudFormation); JSON `.json` (CloudFormation, Azure ARM, OpenAPI); `Dockerfile`, `.dockerfile`; `docker-compose.yml`, `compose.yml`; Azure Bicep `.bicep`. Default `fcs.filePatterns`: `["*.tf", "*.tfvars", "*.yaml", "*.yml", "*.json", "Dockerfile"]`.
- IntelliJ (S11 README): "JSON, YAML, XML, Dockerfile, HCL, Bicep, Properties".

Observations relevant to the gate:

- Bicep is listed by both IDE plugins as a supported file type but is not a value in the `--platforms` enum; whether it is reported under `AzureResourceManager` is not stated.
- Helm charts are not mentioned anywhere. Terraform plan JSON is not mentioned anywhere (see Q10).
- `path` accepts a local file, a local directory, or `git::<git repo>` (S2 `path` description; S3 `path_exists` accepts anything matching `^git::`).
- The CLI resolves Terraform modules: `--module-cache` "Reuse downloaded Terraform modules across scans via a persistent on-disk cache" (S2; CLI 4.0.x+ per S1). This implies network egress for remote modules during a scan.
- Since CLI 4.0.x the CLI auto-excludes paths listed in `.gitignore`; `--exclude-gitignore` disables that (S1 "New Inputs (FCS CLI 4.0.x)", S2). Files larger than `--max-file-size` (default 100 MB) are skipped (S1, S2).

## 3. `--fail-on` semantics and exit codes

Syntax (CLI flag `--fail-on`, action input `fail_on`):

- Comma-separated `severity=N` pairs: `--fail-on critical=1,high=1,medium=1,informational=1` (S1 "How Exit Codes Work"; S3 line 280 maps `INPUT_FAIL_ON` to `--fail-on`). README examples: `critical=5,high=10` and `high=10,medium=70` (S1).
- In the JSON config file it is an array: `"fail-on": ["critical=1", "high=1", "medium=1", "informational=1"]` (S1 "Run scan with configuration file").
- Severity names: `critical`, `high`, `medium`, `informational`. There is no `low` since CLI 1.0.0. A maintainer quoted CLI help text in S9 #24 (2025-04-25): for v1.0.0 `--exclude-severities strings   exclude results with provided severities from scan / allowed values: critical, high, medium, informational`, versus 0.47.1 `--severities strings ... allowed values: high, medium, low, info`. IntelliJ maps LOW to informational for the same reason (S11 `FCSConfigurationService.kt`: "LOW is not a valid CLI argument").

Default: S1 input table lists the default as `critical=1, high=1, medium=1, informational=1`. `action.yml` sets no default for `fail_on` (S2), so when the input is empty the action passes no flag and the CLI's own default applies; S1 asserts that default is the all-ones value. Not confirmed from CLI help.

Counts, not just presence: the number is a per-severity count threshold. The README example `high=10,medium=70` (S1) only makes sense as counts, and IntelliJ passes `--fail-on critical=100,high=100,medium=100,informational=100` with the comment "Add fail-on flag to avoid exit code 40" (S11 `FCSConfigurationService.kt` lines 223-225 and 283-285), i.e. setting the threshold high enough suppresses the failing exit code. Whether the comparison is `>=` or `>` is not documented.

Exit codes. The prose docs (S1 "IaC Scans") say only:

- `0`: "Scan completed with no issues matching your `fail_on` criteria"
- Non-zero: "Scan found issues that match your `fail_on` criteria, or an error occurred"

Specific values appear only in CrowdStrike's IDE-plugin code comments, which disagree with each other:

- VS Code `cliManager.ts` (S10): `VALID_SCAN_EXIT_CODES = [0, 1, 2, 10, 20, 30, 40]` with comment "0: no findings, 1-2: warnings, 10: informational findings, 20: medium findings, 30: high findings, 40: critical findings — all indicate a completed scan", and separately "0: Clean scan, no findings / 1-2: Scan completed with warnings / 40: Successful scan WITH findings (this is normal!) / 201-207: Genuine CLI errors / null: Process was killed or crashed".
- IntelliJ `FCSFileScanTriggerService.kt` (S11): `if (exitCode != 0 && exitCode != 50)` treats 0 and 50 as a completed scan; and the config service comment says the high `--fail-on` thresholds exist "to avoid exit code 40".

Reading those together: a scan that trips `--fail-on` exits with a value in the 10-40 band keyed to the highest matched severity (40 = critical) and errors are >= 200, but the exact table (and what 50 means) is unverified. Treat "non-zero" as the only contract and parse the JSON `detection_summary` for the real decision.

The action never propagates the CLI exit code to the job. S3 captures `${PIPESTATUS[0]}` and writes `exit-code=$exit_code` to `$GITHUB_OUTPUT` (lines 524-525); the script has no `set -e` and does not `exit` with that value. S1 states it explicitly: "The exit code of the action itself should remain `0` which denotes a successful run of the action, while the output `exit-code` reflects the result of the FCS CLI scan." A gate built on the action must therefore read `steps.<id>.outputs.exit-code` and fail deliberately.

`fail_on` applies to IaC only. For image scans the exit code is set by the tenant's Image Assessment policy (S1 "Image Scans"; S9 #58 maintainer 2025-12-18: "the `fail_on` parameter is not a valid option for Image scanning, only for IaC"; S9 #78 observed exit `2` from an image scan).

## 4. `--upload-results` and `--project-owners`

Flags as passed by the action (S3):

- IaC (line 351): `--upload-results --client-id <id> --client-secret <secret> --falcon-region <region>`
- Image (line 482): `--upload --client-id <id> --client-secret <secret> --falcon-region <region>`
- `--project-owners <a@x,b@y>`: "Comma-separated list of project owners to notify (max 5)" (S2). Example values are email addresses (S1).
- `--project-name <name>`: "Name of the project for identification in Falcon console" (S2); added in fcs-action v2.1.0 (S5). S1 recommends `project_name: '${{ github.repository }}/${{ github.ref_name }}'` "to distinguish scan results across repositories and branches".

Flag-name discrepancy: both IDE plugins pass `--upload` (not `--upload-results`) for IaC scans (S10 `cliManager.ts` line 592; S11 `FCSConfigurationService.kt` lines 220, 280), and the VS Code setting that enables it is annotated "**Note:** This setting is not yet fully supported — leave disabled" (S10 `package.json`, `fcs.uploadResults`). Which spelling CLI 4.x accepts for IaC is unverified; the action (v5.0.4, targeting CLI 4.0.x) uses `--upload-results`.

What is uploaded and where it appears: S1 says only "Upload scan results to the CrowdStrike Falcon Console" and links the IaC documentation page, which is login-walled (`https://falcon.crowdstrike.com/login/?unilogin=true&next=/documentation/page/e08ea90a/infrastructure-as-code-security#u253ccc1`). The console location, the data model of an uploaded scan, and what "notify" does for project owners are not described in any public source.

Upload is not required for the scan to run: `upload_results` defaults to `false` (S2) and the IDE plugins scan without it. But note the CLI still talks to the Falcon API during an IaC scan unless cloud rules are disabled (Q6), and the action always exports `FCS_CLIENT_ID` / `FCS_CLIENT_SECRET` into the CLI's environment (S3 lines 532-533).

Whether a failed upload changes the exit code: not found in any source.

## 5. Report formats, SARIF, output paths

IaC formats for `--report-formats`: `json`, `csv`, `junit`, `sarif` (S1 input table; same list in S8 README v1.1.0). Image formats for `--format`: `json`, `sarif`, `cyclonedx-json`, one at a time (S1; S3 maps `REPORT_FORMATS` to `--format` for image and `OUTPUT_PATH` to `--output`).

SARIF via the action is generated by the action, not by the CLI. S3 `prepare_report_formats_for_cli` replaces `sarif` with `json` before invoking the CLI (lines 27-40), rewrites an `output_path` ending in `.sarif` to `.json` (lines 300-303), then after the scan parses the CLI's stdout lines `Results saved to file: <path>` (ANSI codes stripped; lines 49-57), and converts each `.json` with `python3 "$GITHUB_ACTION_PATH/json_to_sarif_converter.py"` (line 126). This has been the design since at least v2.0.3 ("handle output path filenames for IaC SARIF conversion", S5); v1.0.2 was "fixing sarif informationuri issue temporarily" (S5), which suggests the CLI's native SARIF did not pass GitHub validation. S1 "SARIF Output Transformation" lists what the converter changes for GitHub: `informationUri` set to `https://crowdstrike.com`, levels normalised to `error|warning|note|none`, unsupported `type` properties removed, every result given a `locations` array with URI `"unknown"`.

Converter details useful for a gate (S6):

- SARIF 2.1.0, `$schema` `https://json.schemastore.org/sarif-2.1.0.json`; tool driver name `CrowdStrike FCS`; version from `scanner_version` or `fcs_version`.
- Rule ids: `iac/<rule_uuid>` for `rule_detections`, `secret/<type>` for `secrets_analysis.secrets`, `policy/<policy_id>` for `policy_violations`; each rule gets a `security-severity` property (GitHub uses it for severity display, fixed in v2.0.3 and v4.0.1, S5).
- Secrets are always emitted at level `error` ("Secrets in IaC are always high severity", S6 line 823).
- `python3` must exist on the runner for SARIF (S3 line 126). The runner also needs `curl`, `jq`, `tar`, `unzip` for the download step (S4 line 345).

S1's example uploads with `github/codeql-action/upload-sarif@v3` guarded by `if: steps.fcs.outputs.exit-code != 0`. That guard means a clean scan uploads nothing, so GitHub never sees a "fixed" result; drop the guard if you want alerts to auto-close.

Output location (`--output-path` for IaC):

- Default when omitted: `~/.crowdstrike/reports/` (S1 "Important Changes in FCS CLI 2.2.0"). Image default: `~/.crowdstrike/image_assessment/reports/` (S1).
- CLI >= 2.2.0: with more than one format the path must be a directory; a file path "Will fail" (S1). With a single format a file path is allowed.
- The CLI announces each written file on stdout as `Results saved to file: <path>` (S3 lines 49-57). The action creates the output directory beforehand (S3 `ensure_output_directory`; fix in v5.0.4, S5).
- The action creates `$HOME/.crowdstrike/log` "that FCS expects" (S4 lines 286-288).

IaC JSON report shape (from S10 `types/index.ts`, "matching actual CLI output structure", and S6): top level `fcs_version`, `path`, `scan_uuid`, `detection_summary {total, critical, high, medium, informational}`, `rule_detections[] {rule_name, rule_uuid, rule_category, description, severity (Critical|High|Medium|Low|Informational), platform, cloud_provider, service, rule_type, detections[] {file, line, resource_type, resource_name, issue_type, reason, recommendation}}`, `secrets_analysis.secrets[] {type, ...}`, `policy_violations[] {policy_id, policy_name, policy_type, description, severity}`, and a legacy `violations` key for older CLIs. `repository_details.name` may be present (S6).

## 6. Policy, rule selection, exclusions, suppression, secrets

Rule sources:

- The CLI ships a local rule set and can additionally fetch "cloud-based custom rules" from the tenant. In CLI < 4.0 this was opt-in via `--policy-rule` with allowed values `local` (default) and `default-iac-alert-rule` (S8 README v4.0.2 line 187: "IaC scanning policy rule | No | `local` | Allowed values: local, default-iac-alert-rule"; introduced in fcs-action v1.1.0, S5).
- CLI 4.0.x: "Cloud-based custom rules are now applied automatically on every IaC scan. The `policy_rule` input is **deprecated and ignored**." Opt out with `--disable-custom-rules` ("Disable fetching cloud-based rules; scan with local rules only", S2), which S1 frames as the option for "air-gapped or firewall-restricted environments" (S1). So by default a 4.x scan needs network access to the Falcon API and the IaC scope even without upload.
- The IDE plugins (validated up to CLI 4.2.3) still pass `--policy-rule local` (S10, S11, where IntelliJ comments it "required"). Whether 4.x errors, ignores, or honours it is unverified; the action stopped sending it.
- Managing those cloud rules in the console is described in a login-walled release note (S9 #24 cites `https://falcon.crowdstrike.com/support/release-notes/release-notes-manage-infrastructure-as-code-rules-in-falcon-cloud-security`).

Filters (CLI flag names from S3 `set_parameters`, semantics from S2):

| Flag | Meaning |
|------|---------|
| `--categories` / `--exclude-categories` | Include/exclude by rule category. Values (S1): Access Control, Availability, Backup, Best Practices, Build Process, Encryption, Insecure Configurations, Insecure Defaults, Networking and Firewall, Observability, Resource Management, Secret Management, Supply-Chain, Structure and Semantics. |
| `--platforms` / `--exclude-platforms` | Include/exclude by platform (list in Q2). |
| `--severities` / `--exclude-severities` | Include/exclude by severity: critical, high, medium, informational. |
| `--exclude-paths` | "Exclude paths from scan, accepts a comma-separated list (e.g. './sample-dir-to-omit/*,sample-file.tf')" (S2). |
| `--exclude-gitignore` | Disable the default exclusion of `.gitignore`d paths (CLI 4.0.x+). |
| `--max-file-size <MB>` | Skip larger files; default 100 (CLI 4.0.x+). |
| `--config <file>` | JSON config. Keys seen: `path`, `fail-on` (array), `output-path`, `report-formats` (array), `timeout` (S1 example; S7 `tests/config.json` uses `path`, `output-path`, `report-formats`). The action gives `--path` precedence and, when only `config` is given, reads `.path` from it with `jq` (S3 lines 212-223). |
| `--disable-secrets-scan` | Turn off secrets detection (S2). |
| `--disable-custom-rules` | Local rules only (CLI 4.0.x+). |
| `--module-cache` | Persist downloaded Terraform modules (CLI 4.0.x+). |
| `--timeout <s>` | Scan timeout; default 300 s (S1; S10 `package.json`: "Default matches the CLI default of 300 seconds"). v1.1.0 README said 500 (S8). |
| `--profile <name>` | Named profile from `~/.crowdstrike/fcs.json`; default `default` (S1, S10 helpManager). |
| `--falcon-token <t>`, `--falcon-region <r>`, `--client-id`, `--client-secret`, `--verbose` | Auth and logging (S3). `--falcon-token` "needs a region (or profile) to resolve the API base URL" (S3 comment, line 505). |

Per-file or inline suppression: the VS Code extension's "Suppress" code action inserts `# fcs:ignore <ruleId> - Accepted risk` above the offending line (comment character per language) or a `"_fcs_ignore": "<ruleId>"` field in JSON (S10 `codeActionProvider.ts` lines 319-341; tests in `code-action-simple.test.ts`). Nothing in the extension, the action, or any SDK reads those markers, and a GitHub-wide code search (`gh search code 'fcs:ignore'`, `'_fcs_ignore'`) finds them only in that extension. Whether the CLI honours them is unverified. The only confirmed suppression mechanisms are the CLI-level filters above and (for cloud rules) rule management in the console.

Secrets scanning: on by default; `--disable-secrets-scan` turns it off (S2; S11 README "Exclude Secrets: Skip secrets detection in scans"). Results land in `secrets_analysis.secrets[]` (S6). Whether secret findings count toward `--fail-on` severity thresholds, and at what severity, is not documented; the SARIF converter treats them as `error` / high.

## 7. The official `CrowdStrike/fcs-action`

Versions: latest release v5.0.4 (2026-10-07); floating tags `v5`, `v5.0` exist and are re-pointed on every release by `release.yml` (`git tag -d`, `git push origin :vN`, re-tag; S7). Full tag list (S5): v1.0.0 to v1.0.6, v1.1.0, v2.0.0 to v2.0.3, v2.1.0, v3.0.0, v4.0.0 to v4.0.2, v5.0.0 to v5.0.4, plus `v1 v1.0 v1.1 v2 v2.0 v2.1 v3 v3.0 v4 v4.0 v5 v5.0`. Marketplace shows v5.0.4 as Latest, publisher CrowdStrike, verified creator (S15). On supply chain, the maintainer declined immutable releases because floating major tags stay mutable and said they "Recommend full semver pinning in README examples" and pin their own external actions to SHAs (S9 #75, 2026-03-30). Major-version history: v2.0.0 = CLI 2.x (`scan image`), v3.0.0 = switch to `csdownloads/combined/files-download/v2` and the Cloud Security Tools Download scope, v4.0.0 = CLI 2.2.0 support, v5.0.0 = CLI 4.0.0 support (S5). S1 says it is "not a formal CrowdStrike product" but "maintained by CrowdStrike".

Inputs (S2, all `required: false` unless noted; blank default means none set in `action.yml`):

| Input | Default | Scan | Description (abridged from S2) |
|-------|---------|------|--------------------------------|
| `falcon_client_id` | (required) | both | API client ID |
| `falcon_region` | `us-1` (required) | both | `us-1`, `us-2`, `eu-1`, `us-gov-1`, `us-gov-2` |
| `version` | latest | both | FCS CLI version to download |
| `bin_path` | `$RUNNER_TEMP` | both | where the binary is placed |
| `scan_type` | `iac` | both | `iac` or `image` |
| `path` | | iac | file, dir, or `git::<repo>` (required unless `config`) |
| `config` | | iac | config file path |
| `categories`, `exclude_categories`, `platforms`, `exclude_platforms`, `severities`, `exclude_severities`, `exclude_paths` | | iac | filters (Q6) |
| `fail_on` | (none; README documents CLI default all `=1`) | iac | `severity=N,...` |
| `output_path` | (CLI default) | both | IaC: file or dir; image: must end `.json`, `.sarif`, `.cdx.json` |
| `report_formats` | (CLI default `json`) | both | IaC: json,csv,junit,sarif; image: one of json,sarif,cyclonedx-json |
| `policy_rule` | `local` | iac | deprecated, ignored by CLI 4.x; still has a default in action.yml but S3 no longer forwards it |
| `disable_custom_rules` | `false` | iac | local rules only |
| `exclude_gitignore` | `false` | iac | |
| `max_file_size` | (CLI default 100) | iac | MB |
| `module_cache` | `false` | iac | |
| `disable_secrets_scan` | `false` | iac | |
| `project_owners` | | iac | up to 5 |
| `project_name` | | iac | |
| `timeout` | (CLI default 300) | both | seconds |
| `upload_results` | `false` | both | |
| `falcon_token` | | both | bearer token, bypasses OAuth2 for the scan step only |
| `verbose` | `false` | both | |
| `profile` | (CLI default `default`) | both | |
| `image` | | image | required for image |
| `socket`, `platform`, `temp_dir`, `vulnerability_only` (`false`), `sbom_only` (`false`), `scan_only` (`false`), `strict_digest` (`false`), `minimum_score`, `minimum_severity`, `minimum_exprt`, `exclude_vulnerabilities`, `vuln_fixable_only` (`false`), `report_sort_by`, `show_full_description` (`false`), `show_full_detection_details` (`false`), `minimum_detection_severity`, `no_color` (`false`) | | image | image-only options |

Environment: `FALCON_CLIENT_SECRET` is required and must come from the job `env` (S1, S4 lines 326-332).

Outputs (S2): exactly one, `exit-code`, "Exit code of the FCS CLI tool. For IaC scans, determined by the fail_on parameter. For image scans, determined by the image assessment policy configured in the Falcon console."

What it does, step by step (composite action, S2 `runs`):

1. `fcs_download.sh` (S4):
   1. Resolves the API host from `falcon_region`: `us-1` -> `api.crowdstrike.com`, `us-2` -> `api.us-2.crowdstrike.com`, `eu-1` -> `api.eu-1.crowdstrike.com`, `us-gov-1` -> `api.laggar.gcw.crowdstrike.com`, `us-gov-2` -> `api.us-gov-2.crowdstrike.mil`; anything else silently falls back to `us-1` (lines 14-24).
   2. `POST https://<host>/oauth2/token` with `grant_type=client_credentials` (lines 57-59).
   3. Detects OS (`linux|darwin|windows`) and arch (`amd64|arm64`), defaulting to linux/amd64 on unknowns (lines 71-105).
   4. `GET https://<host>/csdownloads/combined/files-download/v2?filter=category:'fcs'+os:'<os>'+arch:'<arch>'[+file_version:'<version>']&limit=100&sort=file_version|desc` (lines 120-137) and takes `resources[0]` (latest by version when no version is pinned).
   5. Downloads `resources[0].download_info.download_url` with `curl -L`, computes SHA-256 with `sha256sum`/`shasum -a 256`, and aborts on mismatch with `download_info.file_hash // file_hash` (lines 181-221).
   6. Extracts `.tar.gz` or `.zip`, finds `fcs`/`fcs.exe`, copies it to `bin_path`, `chmod +x`, creates `~/.crowdstrike/log`, appends `bin_path` to `GITHUB_PATH`, outputs `FCS_BIN` (lines 223-292, 401-407).
2. `fcs-scan.sh` (S3): exports `FCS_CLIENT_ID` and `FCS_CLIENT_SECRET`; validates inputs; builds the flag list; `cd $GITHUB_WORKSPACE`; runs `fcs scan iac ...` or `fcs scan image <image> ...` with `2>&1 | tee`; records `exit-code`; converts JSON to SARIF if requested. The composed argument string, including `--client-secret <secret>` when `upload_results` is true, is echoed to the log at line 512 (GitHub masks values registered as secrets, but the secret is also visible on the process command line of the runner).

CLI pinning: not pinned by default; `version` input pins via the `file_version` filter (S4 line 125). Which CLI the action is tested against is implied only by README headings (4.0.x for v5.x; S1).

## 8. Falcon API client requirements

Scopes (S1 "Create a CrowdStrike API Client", v5.0.4):

| Scope | Permission | Needed for |
|-------|------------|-----------|
| Cloud Security Tools Download | READ | "Always" (CLI download via `csdownloads/combined/files-download/v2`; S12/S13 list that operation under this scope) |
| Infrastructure as Code | READ & WRITE | "For IaC scanning only" |
| Falcon Container CLI | READ & WRITE | image scanning |
| Falcon Container Image | READ & WRITE | image scanning |

The IntelliJ README (S11), which only does IaC, lists just Cloud Security Tools Download READ and Infrastructure as Code READ & WRITE. The VS Code README (S10) lists the three READ & WRITE scopes and omits Cloud Security Tools Download, but its download code still calls the deprecated `csdownloads/entities/files/enumerate/v1`, which S12 lists under "Infrastructure as Code (IaC): READ"; S9 #47 is a 403 from exactly that path for an IaC-unlicensed tenant, and the maintainer said engineering was fixing it (resolved by the v2 endpoint in fcs-action v3.0.0, S5). No source separates the scope needed to scan from the scope needed to upload, nor says whether IaC READ alone suffices when `--disable-custom-rules` is set and no upload happens.

Regions: `us-1`, `us-2`, `eu-1`, `us-gov-1`, `us-gov-2` (S2 `falcon_region`; host mapping in S4). The CLI flag is `--falcon-region` (S3). The IntelliJ download script reads `FALCON_CLOUD` for the same purpose, but that is the script's variable, not the CLI's (S11 `fcs_download.sh` line 385).

Credential passing to the CLI (S3): environment variables `FCS_CLIENT_ID` and `FCS_CLIENT_SECRET` are exported before every invocation (lines 532-533); when uploading, `--client-id`, `--client-secret`, `--falcon-region` are also passed as flags; `--falcon-token <bearer>` is an alternative that "skips OAuth2 authentication" (S2) and is passed as a separate quoted argument so it never hits the log (S3 lines 497-510); `--profile` selects stored credentials in `~/.crowdstrike/fcs.json`. The action's own download step uses `FALCON_CLIENT_SECRET` (env) and the `falcon_client_id` input. Whether the CLI itself reads `FALCON_CLIENT_ID`/`FALCON_CLIENT_SECRET` is not shown anywhere; the action deliberately sets the `FCS_` names.

Token lifetime, scope-per-operation tables, and the exact scope string identifiers are only on login-walled pages. The only public hints at the internal names are user-pasted errors: `infrastructure-as-code:read` (S9 #47) and `Scope:falcon-container-cli:read` (S9 #38); neither is a reference.

## 9. Installing and pinning the CLI in GitHub Actions without the action

Where the binary comes from: the CrowdStrike API, not GitHub Releases or a package manager. The operation is `FetchFilesDownloadInfoV2`, `GET /csdownloads/combined/files-download/v2`, "Get cloud security tools info and pre-signed download URLs", scope Cloud Security Tools Download: READ (S12; S13; S14 `downloads_api_client.go`). Parameters (S13): `filter` (FQL; fields `arch`, `category`, `file_name`, `file_version`, `os`), `sort` (same fields), `limit` (default and max 100), `offset` (max `1000 - limit`). The older `files/enumerate/v1`, `files/download/v1` and `files-download/v1` operations are deprecated and need IaC READ (S12).

Response shape (S14 `ModelsCombinedFileDownloadResource`): `arch`, `category` (required), `download_info { download_url, expires_at?, file_hash? }` (field names from S10 `cliManager.ts` type `CrowdStrikeDownloadUrlResponse`), `file_hash`, `file_name` (required), `file_type`, `file_version` (required), `os`, `size`. Errors come back in `errors[]` with `meta` (S14).

Listing versions: query with `filter=category:'fcs'+os:'linux'+arch:'amd64'`, `sort=file_version|desc`, `limit=100` and read `file_version` from each resource (S4 lines 124-137; S11 `fcs_download.sh` lines 135-153). Pinning: add `+file_version:'<X.Y.Z>'` to the filter (S4 line 125). The pre-signed `download_url` is time-limited (`expires_at`) and, per the VS Code client, is served from an `amazonaws.com` host over HTTPS, which that client enforces (S10 `cliManager.ts` lines 155-190).

Checksum: `file_hash` is compared against a locally computed SHA-256 by every CrowdStrike client (S4 lines 195-220; S10 lines 193-207; S11 lines 229-249). The API docs do not name the algorithm (S12), so "SHA-256" is inferred from the clients. Archive is `.tar.gz` or `.zip` containing a single `fcs` (or `fcs.exe`) executable (S4 lines 238-279).

Version numbers that appear in public CrowdStrike sources, for calibrating a pin: 0.47.1 and 1.0.0 (S9 #24, 2025-04), 2.0.2 (S1 example), 2.2.0 and 2.3.0 (S1), 4.0.0 (S5 v5.0.0, 2026-07-28), and 4.2.3 as the newest version the IDE plugins have validated (S10 `constants.ts` `CLI_VERSION.MAXIMUM`; S11 `FCSBinaryService.kt` `MAXIMUM_CLI_VERSION`; both set `MINIMUM` 3.0.0). The pre-v2 action used `falcon-container-sensor-pull.sh -t fcs` (S8 `fcs-pull.sh` v1.1.0), and v2.0.x used FalconPy `downloads.enumerate(platform=..., category="fcs")` then `downloads.download(file_name, file_version)` (S8 `fcs_download.py` v2.0.3); both paths are superseded.

Historical config note: CLI 2.x stored profiles in `~/.crowdstrike/fcs_profiles.json`; 3.x+ uses `~/.crowdstrike/fcs.json`; `fcs migrate-config` converts (S10 helpManager lines 743, 964-970).

## 10. Other constraints on a deploy-gate design

- The action's step exit code is always 0; findings only surface in `outputs.exit-code` (Q3). Any gate must check it or parse the JSON.
- `fail_on` is IaC-only; image gating is console policy (Q3). Mixing the two scan types in one job needs two decision paths.
- Exit codes are not a published table; the only safe contract is zero/non-zero, and "error" vs "findings" cannot be distinguished without parsing output (Q3). The VS Code comment's "201-207: Genuine CLI errors" band is the best public hint.
- Network and credentials are needed even without upload on CLI 4.x because cloud custom rules are fetched by default; `--disable-custom-rules` makes the scan local but changes which rules run (Q6). A gate that must match the console's rule set should not disable them, and should expect results to change when someone edits cloud rules.
- Rule set drift between CLI versions is real: CLI 1.0.0 removed the `low` severity and renamed `info` to `informational`, breaking workflows that did not pin (S9 #24). Pin `version` and bump deliberately.
- The scan timeout defaults to 300 s (`--timeout`), and the CLI resolves Terraform modules (`--module-cache`), so large Terraform trees with many remote modules may need a longer timeout and egress to module registries.
- Scanning only changed files is possible mechanically: the CLI accepts multiple `--path` arguments (S10 `cliManager.ts` passes one `--path` per file with the comment "CLI expects multiple --path arguments or directories"). Whether per-file scanning loses cross-file Terraform context (variables, modules) is not documented.
- Terraform plan JSON: no CrowdStrike source mentions scanning `terraform show -json` output; the only documented Terraform input is source (`.tf`, `.tfvars`).
- `.gitignore`d paths are excluded by default from CLI 4.0.x (Q2); generated files written at build time and ignored by git will not be scanned unless `--exclude-gitignore` is passed.
- Multiple report formats need a directory `--output-path` (CLI >= 2.2.0), and the CLI prints `Results saved to file:` lines you can parse (Q5).
- Rate limits: the Falcon API returned `X-Ratelimit-Limit: 6000` and `X-Ratelimit-Remaining` headers on a `csdownloads` call in a user's log (S9 #47). The limit window and whether it is per client are not stated in any public CrowdStrike doc found. Each run performs at least one OAuth2 token request for the download plus whatever the CLI does.
- The runner needs `bash`, `curl`, `jq`, `tar`, `unzip`, `sha256sum` or `shasum`, and `python3` if SARIF is wanted (S3, S4).
- Supported runner platforms for the binary: linux, darwin, windows on amd64 or arm64 (S4). Minimum OS versions are on a login-walled page (S10 README links `https://docs.crowdstrike.com/access?ft:originId=g9ebb316`).
- Secrets on the command line: with `upload_results: true` the action passes `--client-secret` as an argument and logs the argument string (S3 lines 351, 512). Prefer `--falcon-token`, `--profile`, or the `FCS_CLIENT_SECRET` env var if building a custom workflow, and verify which the CLI honours.
- Floating `@v5` tags are mutable by design (S7 `release.yml`); pin the action by commit SHA (S9 #75).
- The SARIF file the action produces is the action's conversion, not the CLI's, and GitHub-compatibility fixes have shipped in four of the last eight releases (v4.0.1, v5.0.1, v5.0.2, v5.0.3; S5). A custom workflow that asks the CLI for native `sarif` is on a different, untested path.

## Unverified or not found

Login-walled or unreachable primary documentation (attempted 2026-10-19):

- `https://docs.crowdstrike.com/access?ft:originId=g9ebb316` (FCS CLI minimum OS versions, linked from S10) and `...originId=ufcd2496` (API client creation): 303 to a Fluid Topics single-page app that only renders with JavaScript; its REST endpoints (`/api/khub/maps/<map>` and `/toc`) return HTTP 401, and the topic endpoints 404 without a session.
- `https://docs.crowdstrike.com/r/bc45484d` (image scanning docs cited by the maintainer in S9 #58) and `https://docs.crowdstrike.com/r/m0218c93` (image assessment policies): same wall.
- `https://falcon.crowdstrike.com/documentation/page/e08ea90a/infrastructure-as-code-security` (IaC scanning and configuration-file docs linked from S1): redirects to `falcon.crowdstrike.com/login`.
- `https://falcon.crowdstrike.com/support/release-notes/release-notes-manage-infrastructure-as-code-rules-in-falcon-cloud-security` (CLI 1.0.0 severity/rule changes, cited in S9 #24): renders only "Login | Falcon".
- Context7 has no library id for the FCS CLI or fcs-action (only `/crowdstrike/falcon-mcp` and `/crowdstrike/ansible_collection_falcon` matched).

Claims that remain inferred or unconfirmed:

1. Verbatim `fcs --help` / `fcs scan iac --help` for any version, and therefore the complete flag list. Everything above is the subset exercised by CrowdStrike's own clients.
2. The exact non-zero exit-code table for IaC scans (VS Code says 1-2, 10, 20, 30, 40 and 201-207; IntelliJ treats 50 as success) and whether `--fail-on` uses `>=` or `>`.
3. Whether the CLI applies a default `--fail-on` of all-ones when the flag is omitted (README says so; not confirmed from the CLI).
4. Whether secrets findings count toward `--fail-on`, and at what severity.
5. Whether the CLI's native `--report-formats sarif` output is accepted by `github/codeql-action/upload-sarif`; the action avoids it entirely.
6. Whether IaC upload is `--upload-results` (action) or `--upload` (IDE plugins) on CLI 4.x; whether a failed upload changes the exit code; where uploaded results and `project_name` appear in the console; what `--project-owners` notification does.
7. Whether CLI 4.x rejects, ignores, or honours `--policy-rule local` (action says ignored; plugins still send it).
8. Whether the `fcs:ignore` / `_fcs_ignore` markers inserted by the VS Code extension are honoured by the CLI or are plain comments.
9. Whether Bicep and Helm are parsed; Bicep is a plugin file type but not a `--platforms` value, Helm is unmentioned.
10. Terraform plan JSON as an input: no evidence either way.
11. The minimum scope set for "scan without upload, cloud rules disabled", and whether `Infrastructure as Code: READ` alone works.
12. Environment variable names the CLI itself reads for credentials (`FCS_CLIENT_ID`/`FCS_CLIENT_SECRET` are what the action sets; `FALCON_*` unverified).
13. API rate-limit window and scope (only a `6000` header value observed in a user log).
14. Whether `file_hash` is SHA-256 (all clients compare it with SHA-256, the API doc does not say).
15. The current latest CLI version on the download API (newest value seen in public sources is 4.2.3, from the IDE plugins' validated maximum).
