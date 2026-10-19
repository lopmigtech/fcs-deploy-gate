# Falcon API: can it map IaC scan rules to IOM policies?

Research date: 2026-10-19. All URLs were accessed on that date. This is the
third research pass, after `docs/research/fcs-cli.md` (cited as "fcs-cli.md
§N") and `docs/research/fcs-iac-scan-contract.md` ("contract.md §N"). It does
not restate what those files establish. The question is whether the public
Falcon API exposes enough to build, offline, a mapping from the CLI's IaC
scan rules to the console's IOM policies, and what an API client needs.

Primary sources only: the CrowdStrike SDKs (FalconPy, gofalcon, falconjs,
crimson-falcon, rusty-falcon are all generated from the same OpenAPI
specification, so they agree on paths and fields and disagree only in naming),
the FalconPy wiki (the only public per-operation "Required Scope" table), the
CrowdStrike developer center, the CrowdStrike Terraform provider and the
CrowdStrike `falcon-mcp` server. Where a claim rests on a model's field list
rather than on prose, that is said. The Falcon console documentation and the
Swagger file (`assets.falcon.crowdstrike.com/support/api/swagger.html`) are
login-walled and were not read.

## Sources

Ids start at U1 so they do not collide with S1-S16 (fcs-cli.md) and T1-T25
(contract.md).

| Id | Source | Version / date the claim applies to |
|----|--------|-------------------------------------|
| U1 | FalconPy endpoint table `src/falconpy/_endpoint/_cspm_registration.py` (https://raw.githubusercontent.com/CrowdStrike/falconpy/main/src/falconpy/_endpoint/_cspm_registration.py) | `main` 06a5df86 (2026-09-24); release v1.6.6 (2026-09-28) |
| U2 | FalconPy `_endpoint/_cloud_security_detections.py` | same |
| U3 | FalconPy `_endpoint/_cloud_policies.py` | same |
| U4 | FalconPy `_endpoint/_cloud_security_assets.py` | same |
| U5 | FalconPy `_endpoint/_cloud_snapshots.py` | same |
| U6 | FalconPy `_endpoint/_cloud_security_compliance.py`; full listing of `_endpoint/` (143 files) grepped for `iac`, `iom`, `exempt`, `suppress`, `mute` | same |
| U7 | FalconPy `CHANGELOG.md` https://raw.githubusercontent.com/CrowdStrike/falconpy/main/CHANGELOG.md | versions 1.2.16 through 1.6.6 |
| U8 | FalconPy GitHub wiki, per-operation "Required Scope" sections: https://github.com/CrowdStrike/falconpy/wiki/CSPM-Registration (last edited 2026-03-21), `.../wiki/Cloud-Policies`, `.../wiki/Cloud-Security-Detections`, `.../wiki/Cloud-Security-Assets`, `.../wiki/Cloud-Snapshots`, `.../wiki/Cloud-Security-Compliance`. (`falconpy.io/Service-Collections/*` now 301-redirects to U9; the raw wiki URLs `raw.githubusercontent.com/wiki/CrowdStrike/falconpy/*.md` return 404.) | live pages |
| U9 | CrowdStrike developer center collection pages (console-label scope strings per operation): https://developer.crowdstrike.com/api-reference/collections/cspm-registration/, `.../cloud-security-detections/`, `.../cloud-policies/`, `.../cloud-security-assets/`, `.../cloud-snapshots/` | live pages; each renders only its first ~100-128k characters, so some operations' sections were unreadable |
| U10 | gofalcon v0.23.0 (2026-10-02) models under `falcon/models/`: `domain_policy_info.go`, `domain_c_id_policy_assignments.go`, `domain_benchmark.go`, `domain_control.go`, `domain_compliance.go`, `domain_policy_setting_by_account_and_region.go`, `registration_policy_response_v1.go`, `registration_policy_settings_response_v1.go`, `registration_policy_request_ext_v1.go`, `registration_policy_ext_v1.go`, `registration_external_i_o_m_event_response_v2.go`, `registration_i_o_m_event_v2.go`, `registration_i_o_m_event_i_ds_response_v2.go`, `evaluations_get_i_o_ms_response.go`, `evaluations_query_i_o_ms_response.go`, `evaluations_evaluation.go`, `evaluations_evaluation_doc.go`, `evaluations_evaluation_resource.go`, `evaluations_evaluation_cloud.go`, `evaluations_rule.go`, `evaluations_rule_override.go`, `evaluations_i_o_ms_by_rule_response.go`, `evaluations_i_o_ms_by_rule_resource.go`, `evaluations_compliance.go`, `evaluation_finding.go`, `policyframework_control.go`, `policyframework_benchmark.go`, `policyframework_policy_metadata.go`, `common_get_rules_response.go`, `common_query_response.go`, `apimodels_rule.go`, `apimodels_rule_logic.go`, `apimodels_control.go`, `apimodels_resource_type.go`, `apimodels_rule_override.go`, `common_get_rule_override_response.go`, `common_single_create_rule_override_request.go`, `suppressionrules_get_suppression_rules_response.go`, `apimodels_suppression_rule.go`, `apimodels_rule_selection_filter.go`, `apimodels_asset_filter.go`, `models_detections_combined_response.go`, `models_api_detection_response.go`, `models_module_remediation.go`, `remediation.go`, `rule.go` (https://github.com/CrowdStrike/gofalcon/tree/v0.23.0/falcon/models) | v0.23.0 |
| U11 | gofalcon v0.23.0 client packages `falcon/client/cspg_iacapi/` (exactly `combined_detections_*` and `get_credentials_mixin0_*`), `cloud_policies/`, `cloud_security_detections/`, `cspm_registration/`, `cloud_security_assets/`; each `*_responses.go` read for its `OK` payload type | v0.23.0 |
| U12 | falconjs `main` (release v0.7.0, 2026-07-23) `src/models/ModelsAPIDetectionResponse.ts`, `Rule.ts`, `CommonSingleCreateRuleOverrideRequest.ts`, `src/apis/CspgIacapiApi.ts`; crimson-falcon `main` `lib/crimson-falcon/api/cspg_iacapi.rb`, `cspg_iac.rb`, `models/models_api_detection_response.rb`; rusty-falcon `src/apis/cspg_iacapi_api.rs` | as stated |
| U13 | FalconPy service class `src/falconpy/cloud_policies.py` (docstrings with body shapes for `create_rule_override`, `create_suppression_rule`) | `main` |
| U14 | CrowdStrike Terraform provider v1.2.0 (2026-10-08): `docs/data-sources/cloud_security_rules.md`, `docs/resources/cloud_security_iom_custom_rule.md`, `docs/resources/cloud_security_iac_custom_rule.md`, `docs/resources/cloud_security_custom_rule.md` (deprecated), `docs/resources/cloud_security_suppression_rule.md`, `docs/data-sources/cloud_security_suppression_rules.md`; source `internal/cloud_security/custom_iac_rule_resource.go`, `scopes.go`, `rules_data_source.go`, `shared.go`, `rules_data_source_test.go` (https://github.com/CrowdStrike/terraform-provider-crowdstrike) | v1.2.0 |
| U15 | CrowdStrike `falcon-mcp` (release v0.19.0, 2026-09-01; `main`): `falcon_mcp/modules/cloud/cloud_iom.py`, `cloud_base.py`, `cloud_insights.py`, `falcon_mcp/resources/cloud.py`; developer center page https://developer.crowdstrike.com/falcon-mcp/modules/cloud/ and changelog https://developer.crowdstrike.com/falcon-mcp/changelog/ | as stated |
| U16 | Developer center Foundry "API Scopes" page https://developer.crowdstrike.com/foundry/authorization/api-scopes/ | live page |
| U17 | `gh search code --owner CrowdStrike` for `'iac/combined/detections'`, `'iac/entities'`, `'infrastructure-as-code:read'`, `'cloud-security-iac'`, `'iac-scan'`, `'iac/scans'`, `'rule_subdomain'`, `'subdomain IAC'`, `'parent_rule_short_uuid'`; and `gh search code 'override_type' 'rule-overrides'` (GitHub-wide) | run 2026-10-19 |
| U18 | Web searches (standard and extended) for CrowdStrike text joining "IaC" and "IOM" (mapping, "shift left", "IaC to runtime"), for console IOM "exempt"/"exemption", and for `override_type` values; none returned a CrowdStrike document on any of these | run 2026-10-19 |
| U19 | VS Code extension `src/types/index.ts` (`FcsRuleDetection`), cross-reference for the CLI JSON shape already in fcs-cli.md §5 (S10) | `main` |

---

## 1. Operations that list IOM / CSPM policies

There are two generations of policy objects in the public API and they are
not the same table: the legacy integer-keyed "CSPM policy" under the CSPM
Registration collection, and the newer UUID-keyed "rule" under the Cloud
Policies collection (FalconPy 1.5.5 added the collection with 24 operations,
U7). IOM detections reference both (§2).

### 1a. CSPM Registration (legacy policies)

Scope for every operation below: wiki `cspm-registration:read`, or `:write`
for the PATCH (U8); the developer center labels the same scope "CSPM
registration: READ/WRITE" (U9). The console scope list on the Foundry page
spells it "CSPM Registration" (U16).

| Operation | Method, path | Parameters (U1) | Returns (U10, U11) |
|-----------|--------------|-----------------|--------------------|
| `GetCSPMPolicy` | GET `/settings/entities/policy-details/v1` | `ids` (integer, required) "Given a policy ID, returns detailed policy information." | `RegistrationPolicyResponseV1.resources[]` of `DomainPolicyInfo` |
| `GetCSPMPoliciesDetails` | GET `/settings/entities/policy-details/v2` | `ids` (array of string, required) "Given an array of policy IDs, returns detailed policies information." Added in FalconPy 1.2.16 (U7). | same model |
| `GetCSPMPolicySettings` | GET `/settings/entities/policy/v1` | `service` (enum of 55 names: ACM, ACR, Any, App Engine, AppService, BigQuery, ... S3, SES, SNS, SQLDatabase, SQLServer, SQS, SSM, ..., VPC, VirtualMachine, VirtualNetwork), `policy-id` (`^\d+$`), `cloud-platform` (aws, azure, gcp). "Returns information about current policy settings." | `RegistrationPolicySettingsResponseV1.resources[]` of `DomainCIDPolicyAssignments` |
| `UpdateCSPMPolicySettings` | PATCH `/settings/entities/policy/v1` | body "can be used to override policy severity or to disable a policy entirely" | body `resources[] {policy_id, enabled, severity, account_id, account_ids[], regions[], tag_excluded}` (`RegistrationPolicyRequestExtV1` / `RegistrationPolicyExtV1`) |

No query/list operation exists for legacy policies: both `GET` detail
operations require `ids`, and `GetCSPMPolicySettings` without parameters is
the only way to enumerate (it returns one `DomainCIDPolicyAssignments` per
policy; confirmed by the model, the unfiltered call itself is unverified).

`DomainPolicyInfo` fields (U10): `ID` (int64), `account_scope`,
`alert_logic`, `api_command`, `asset_type_id`, `attack_tool`,
`attack_tool_command`, `attack_types[]`, `cis_benchmark_ids[]` (int64),
`cisa_benchmark_ids[]`, `hipaa_benchmark_ids[]`, `hitrust_benchmark_ids[]`,
`iso_benchmark_ids[]`, `nist_benchmark_ids[]`, `pci_benchmark_ids[]`,
`soc2_benchmark_ids[]`, `cli_command`, `cloud_asset_type`, `cloud_document`,
`cloud_platform` (int), `cloud_platform_type`, `cloud_service` (int),
`cloud_service_friendly`, `cloud_service_id`, `cloud_service_subtype`,
`cloud_service_type`, `compliance {benchmarks[], frameworks[], requirements[],
sections[], versions[]}`, `confidence`, `controls[] {framework, name, section,
version, description, benchmarks[] {name, version}}`, `default_severity`,
`deprecated`, `description`, `event_type`, `fql_policy`, `internal_only`,
`is_enabled`, `is_remediable`, `mitre_attack_cloud_matrix`,
`mitre_attack_cloud_subtype`, `policy_confidence_score`,
`policy_fail_query`, `policy_pass_query`, `policy_remediation`,
`policy_severity` (int), `policy_severity_score`, `policy_statement`,
`policy_type`, `remediation_summary`, `resource_type_friendly_name`,
`resource_type_id`, `tactic`, `tactic_id`, `tactic_url`, `technique`,
`technique_id`, `technique_url`, `CreatedAt`, `UpdatedAt`, `DeletedAt`.

`DomainCIDPolicyAssignments` fields (U10): `policy_id` (int32), `name`,
`cloud_provider`, `cloud_service`, `cloud_service_friendly`,
`cloud_service_id`, `cloud_service_subtype`, `cloud_asset_type`,
`cloud_asset_type_id`, `default_severity`, `policy_type`, `fql_policy`,
`is_global`, `is_remediable`, `remediation_summary`, `attack_types[]`,
`account_scope`, `cid`, `cis_benchmark[]`, `cisa_benchmark[]`,
`hipaa_benchmark[]`, `hitrust_benchmark[]`, `iso_benchmark[]`,
`nist_benchmark[]`, `pci_benchmark[]`, `soc2_benchmark[]` (each
`DomainBenchmark {id, benchmark_short, recommendation_number,
applicable_profiles[]}`), `policy_settings[] {account_id, tenant_id, enabled,
regions[], severity, tag_excluded}`, `policy_timestamp`, `created_at`,
`updated_at`.

### 1b. Cloud Policies (rules, UUID-keyed)

Scope: wiki `cloud-security-policies:read` for every `Get*`/`Query*`
operation and `:write` for `Create*`/`Update*`/`Delete*`/`Replace*`/`Clone*`
(U8; the developer center shows "Cloud Security Policies: WRITE" on the
create operations, U9). The Terraform provider declares "Cloud Security
Policies | Read & Write" even for its read-only data sources (U14 `scopes.go`
declares the union for the package).

| Operation | Method, path | Parameters (U3) | Returns (U10, U11) |
|-----------|--------------|-----------------|--------------------|
| `QueryRule` | GET `/cloud-policies/queries/rules/v1` | `filter` FQL over `rule_auto_remediable`, `rule_category`, `rule_cloneable`, `rule_compliance_benchmark`, `rule_compliance_benchmark_uuid`, `rule_compliance_framework`, `rule_control_requirement`, `rule_control_section`, `rule_created_at`, `rule_description`, `rule_domain`, `rule_mitre_tactic`, `rule_mitre_technique`, `rule_name`, `rule_origin`, `rule_parent_uuid`, `rule_provider`, `rule_resource_type`, `rule_resource_type_name`, `rule_risk_factor`, `rule_annotation_status`, `rule_service`, `rule_severity`, `rule_short_code`, `rule_status`, `rule_subdomain`, `rule_updated_at`, `rule_updated_by`; `limit` default 100 max 500; `offset`; `sort` | `CommonQueryResponse.resources[]` of string (rule UUIDs) |
| `GetRule` | GET `/cloud-policies/entities/rules/v1` | `ids` (uuids, required) | `CommonGetRulesResponse.resources[]` of `ApimodelsRule` |
| `GetComplianceControls` / `QueryComplianceControls` | GET `/cloud-policies/entities/compliance/controls/v1`, `/queries/compliance/controls/v1` | query filter: `compliance_control_name`, `_authority`, `_type`, `_section`, `_requirement`, `_benchmark_name`, `_benchmark_version` | controls |
| `GetComplianceFrameworks` / `QueryComplianceFrameworks` | GET `.../compliance/frameworks/v1` | `compliance_framework_name`, `_version`, `_authority` | frameworks |

`ApimodelsRule` fields (U10): `uuid`, `short_code` (int32), `name`,
`description`, `domain`, `subdomain`, `provider`, `platform`, `severity`
(int64; `CreateRuleMixin0` description: "0=Critical, 1=High, 2=Medium and
3=Low", U3), `category`, `origin`, `annotation_status`, `attack_types[]`,
`auto_remediable`, `cloneable`, `controls[] {uuid, authority, code, name,
origin, description, requirement, section_name, control_type,
control_version, applicable_profiles[], security_framework[] {uuid, name,
version, authority, active, description}}`, `resource_types[] {resource_type,
resource_type_name, resource_subtype, resource_version, service,
description}`, `rule_logic_list[] {platform, logic, modules, remediation_info,
remediation_url}`, `logic`, `logic_format`, `custom_configuration`,
`alert_info`, `remediation`, `remediation_url`, `resource_metadata`,
`parent_rule__pk`, `parent_rule_short_code`, `parent_rule_short_uuid`,
`overrides[]` (`ApimodelsRuleOverride`, §5), `scope_asset_filter`,
`scope_type`, `insight_id`, `mitre_tactics_id/_name/_url`,
`mitre_techniques_id/_name/_url`, `mutable`, `deprecated`, `visible`,
`revision`, `cid`, `created_at/by`, `updated_at/by`, `update_reason`,
`deleted_at/by`.

The one model holds three kinds of rule. `CreateRuleMixin0`'s body
description (U3): "For CSPM IOM Custom Rules, logic is mandatory and
parent_rule_id should not be specified. For CSPM IAC Custom Rules, logic is
mandatory and description is optional. For Runtime IOM Custom Rules (KAC),
logic is mandatory. ... For Managed Rule duplication, parent_rule_id is
mandatory and logic should be not specified." The Terraform data source
documents `subdomain` as "'IOM' (Indicators of Misconfiguration) or 'IAC'
(Infrastructure as Code)", `rule_origin` as "'Default' or 'Custom'", and
`domain` default "CSPM" (U14); `falcon-mcp` queries a third subdomain with
`rule_domain:'CSPM'+rule_subdomain:'Insight'` (U15 `cloud_insights.py`).

Two further catalogue-like reads exist:

- `cspm_evaluations_combined_iom_by_rule`, GET
  `/cloud-security-evaluations/combined/ioms-by-rule/v1` ("returns ioms
  grouped by rule"; FalconPy 1.6.1, U7), scope `cloud-security-detections:read`
  (U8). Filter fields are the IOM fields of §2b; sort on `assessed_assets`,
  `cloud_provider`, `misconfigurations`, `rule_id`, `severity`; limit 500/1000.
  Returns `EvaluationsIOMsByRuleResource {rule: EvaluationsRule,
  misconfigurations, assessed_assets, severity, cloud_provider, account_id,
  region, compliance[] {framework, name, type, version, benchmarks[] {name,
  version}}, tags, cloud_groups_v2}` (U10, U2). It lists only rules that
  currently have IOMs.
- `cloud_compliance_rule_posture_summaries`, GET
  `/cloud-security-compliance/entities/rule-posture-summaries/v1`, `ids` = rule
  uuids (max 350), "Get compliance score and counts for rules"; scope
  `cloud-security-assets:read` (U6, U8).

Status: confirmed (paths, parameters, scopes and field lists from the SDK
tables, the wiki and gofalcon). The unfiltered-enumeration behaviour of
`GetCSPMPolicySettings` and whether default (CrowdStrike-managed) rules are
returned by `QueryRule` with `rule_origin:'Default'` are inferred from the
Terraform test that asserts `rule_origin = "Default"` is a valid filter (U14
`rules_data_source_test.go`), not observed.

## 2. Operations that list IOM detections

### 2a. CSPM Registration (legacy IOM, integer policy id)

Scope `cspm-registration:read` (U8; "CSPM registration: READ", U9).

| Operation | Method, path | Parameters (U1) | Returns (U10, U11) |
|-----------|--------------|-----------------|--------------------|
| `GetConfigurationDetectionIDsV2` | GET `/detects/queries/iom/v2` | `filter` fields: `use_current_scan_ids` ("use this to get records for latest scans"), `account_name`, `account_id`, `agent_id`, `attack_types`, `azure_subscription_id`, `cloud_provider`, `cloud_service_keyword`, `custom_policy_id`, `is_managed`, `policy_id`, `policy_type`, `resource_id`, `region`, `status`, `scan_time`, `severity`, `severity_string`; `sort` default `timestamp|desc`; `limit` default 500 max 1000; `offset`; `next_token` ("Cannot be combined with any filter except limit") | `RegistrationIOMEventIDsResponseV2.resources[]` of string |
| `GetConfigurationDetectionEntities` | GET `/detects/entities/iom/v2` | `ids` (required) "including custom policy detections in addition to default policy detections" | `RegistrationExternalIOMEventResponseV2.resources[]` of `RegistrationIOMEventV2` |
| `GetConfigurationDetections` | GET `/detects/entities/iom/v1` | decommissioned: "This endpoint is deprecated, please use GetConfigurationDetectionIDsV2 and GetConfigurationDetectionEntities instead"; FalconPy 1.6.6 tagged it `DECOMMISSIONED` ("calls to this operation will no longer succeed", U7) | n/a |

`RegistrationIOMEventV2` fields (U10): `id`, `policy_id` (int32),
`custom_policy_id` (int32), `policy_type`, `policy_statement`, `resource_id`,
`resource_uuid`, `resource_id_type`, `resource_url`, `resource_attributes`,
`resource_create_time`, `account_id`, `account_name`, `azure_tenant_id`,
`cloud_provider`, `region`, `service`, `severity`, `status`, `scan_id`,
`scan_time`, `report_date_time`, `finding`, `findings[]`, `tags`,
`is_managed`, `agent_id`, `vm_id`, `cloud_groups_v2[]`, `cloud_labels[]`,
`cloud_scopes[]`, `groups[]`, `cid`. The policy link is `policy_id`
(`custom_policy_id` for custom policies), matching `DomainPolicyInfo.ID` /
`DomainCIDPolicyAssignments.policy_id` in §1a.

### 2b. Cloud Security Detections (new IOM, rule UUID)

Scope `cloud-security-detections:read` (U8) = "Cloud Security API Detections:
READ" (U9, U15). FalconPy 1.5.5 added the two base operations, 1.6.5 the
POST variant (U7).

| Operation | Method, path | Parameters (U2) | Returns (U10, U11) |
|-----------|--------------|-----------------|--------------------|
| `cspm_evaluations_iom_queries` | GET `/cloud-security-evaluations/queries/ioms/v1` | `filter` fields: `account_id`, `account_name`, `applicable_profile`, `attack_type`, `benchmark_name`, `benchmark_version`, `business_impact`, `cid`, `cloud_group`, `cloud_label`, `cloud_label_id`, `cloud_provider`, `cloud_scope`, `created_at`, `environment`, `extension_status`, `first_detected`, `framework`, `last_detected`, `policy_id`, `policy_name`, `policy_uuid`, `region`, `requirement`, `requirement_name`, `resource_gcrn`, `resource_id`, `resource_parent`, `resource_status`, `resource_type`, `resource_type_name`, `rule_group`, `rule_id`, `rule_name`, `rule_origin`, `rule_remediation`, `section`, `service`, `service_category`, `severity`, `status`, `suppressed_by`, `suppression_reason`, `tactic_id`, `tactic_name`, `tag_key`, `tag_value`, `tags`, `tags_string`, `technique_id`, `technique_name`, `tenant_id`; `sort` (same fields); `limit` 500/1000; `offset`; `after` (token) | `EvaluationsQueryIOMsResponse.resources[]` of string (IOM ids) |
| `cspm_evaluations_iom_entities` | GET `/cloud-security-evaluations/entities/ioms/v1` | `ids` (max 100) | `EvaluationsGetIOMsResponse.resources[]` of `EvaluationsEvaluation` |
| `cspm_evaluations_iom_entities_post` | POST same path | body `ids` (max 500) | same |

`EvaluationsEvaluation` (U10): `id`, `cid`, `cloud {provider, account_id,
account_name, region}`, `resource {id, resource_id, resource_name,
resource_type, resource_type_name, gcrn, service, service_category, status,
tags, version, captured, creation_time, cloud_groups[], cloud_labels[],
cloud_scopes[]}`, `evaluation {status, severity, first_detected,
last_detected, last_status_change, created, crn, url, error, attack_types[],
findings[] {name, value}, extension {status}, rule}`, `business_impact[]`,
`environment[]`, `groups[]`, `cloud_groups[]`, `cloud_groups_v2[]`,
`cloud_labels[]`. The developer center lists the same top-level names
(`business_impact, cid, cloud, cloud_groups, cloud_groups_v2, cloud_labels,
environment, evaluation, groups, id, resource`, U9).

`evaluation.rule` is `EvaluationsRule` (U10): `id` (uuid), `name`,
`description`, `origin`, `policy_id` (int32), `policy {uuid, name}`,
`controls[] {uuid, code, name, framework, requirement, section_name, type,
version, origin, description, applicableProfiles[], benchmarks[] {id, name,
version}}`, `rule_group[] {uuid, name}`, `remediation`, `alert_logic`,
`ciem_categories[]`, `threat {framework, tactic, technique}`, `override`
(`EvaluationsRuleOverride`, §5). So one IOM carries three policy links: the
rule UUID (`rule.id`, the §1b key), the legacy integer (`rule.policy_id`, the
§1a key) and a policy UUID (`rule.policy.uuid`; also the `policy_uuid` filter
field). `falcon-mcp` documents the FQL semantics in use: `status:'non-compliant'`,
`severity:['critical','high']`, `benchmark_name:*'*CIS*'`,
`suppression_reason:'accept-risk'`, and notes severity sorts by code with
critical lowest (U15 `resources/cloud.py`, `cloud_iom.py`).

### 2c. Cloud Security Assets (per-resource view)

Scope `cloud-security-assets:read` (U8) = "Cloud Security API Assets: READ"
(U9). `cloud_security_assets_queries`, GET
`/cloud-security-assets/queries/resources/v1`: filter fields include
`iom_count`, `ioa_count`, `highest_severity`, `non_compliant.policy_id`,
`non_compliant.rule`, `non_compliant.rule_name`, `non_compliant.benchmark_name`,
`non_compliant.benchmark_version`, `non_compliant.framework`,
`non_compliant.requirement`, `non_compliant.section`,
`non_compliant.severity`, the `compliant.*` twins, `cloud_risks.rule`,
`cloud_risks.severity`, `cloud_risks.status`, `control.*`, `resource_id`,
`resource_gcrn`, `resource_type`, `tags`, ...; `limit` 500/1000, `offset`
(< 10,000), `after`. `cloud_security_assets_entities_get`/`_post`, GET/POST
`/cloud-security-assets/entities/resources/v1`, `ids` (100 / 500) return the
raw resource; the developer center documents `cloud_context`,
`configuration`, `tags`, `supplementary_configuration` and does not document
an `ioms` array on the entity (U4, U9).
`cloud_security_assets_combined_compliance_by_account` (GET
`/cloud-security-assets/combined/compliance-controls/by-account-region-and-resource-type/v1`)
takes `include_failing_iom_severity_counts` (U4).

Status: confirmed from the SDK tables, wiki scopes and gofalcon models; the
FQL value conventions (`non-compliant`, reason strings) are confirmed from
CrowdStrike's own `falcon-mcp` code, not from a reference page.

## 3. IaC rule catalogue and IaC scan results

Across every CrowdStrike SDK there are exactly two operations under `/iac/`,
both in the Cloud Snapshots collection (FalconPy `_cloud_snapshots.py`,
gofalcon `cspg_iacapi` with two parameter/response pairs, falconjs
`CspgIacapiApi.ts`, crimson-falcon `cspg_iacapi.rb` + `cspg_iac.rb`,
rusty-falcon `cspg_iacapi_api.rs`; U5, U11, U12, U17), both with scope
`infrastructure-as-code:read` (U8) = "Infrastructure as Code (IaC): READ"
(U9, which matches contract.md §4):

- `GetCredentialsIAC`, GET `/iac/entities/image-registry-credentials/v1`:
  registry credentials, irrelevant here.
- `CombinedDetections`, GET `/iac/combined/detections/v1`, "Search IaC
  Detections using a query in Falcon Query Language" (FalconPy 1.5.5, U7).
  Filter and sort fields: `detection_uuid`, `file_name`, `is_from_module`,
  `last_detected`, `module_path`, `module_source`, `module_version`,
  `platform`, `project_name`, `project_owner`, `project_ref`, `provider`,
  `resource_name`, `rule_category`, `rule_name`, `rule_type`, `rule_uuid`,
  `service`, `severity`; `limit`, `offset` (U5). Returns
  `ModelsDetectionsCombinedResponse.resources[]` of `ModelsAPIDetectionResponse`
  (U10, U12): `detection_uuid`, `file_name`, `misconfigured_line`,
  `is_from_module`, `module_path`, `module_source`, `module_version`,
  `module_remediation {module_call_file, module_call_line, remediation_1,
  remediation_2}`, `last_detected`, `project_name`, `project_owners[]`,
  `project_ref`, `remediation {actual_value, expected_value}`,
  `resource_name`, `resource_type`, `rule`.

**IaC scan results: yes, readable.** `project_name`, `project_owners` and
`project_ref` are the CLI's `--project-name` / `--project-owners` values
(fcs-cli.md §4), and the per-detection fields (`file_name`,
`misconfigured_line`, module provenance) are the CLI's `rule_detections[].detections[]`
data, so this operation reads what `--upload-results` stored. That reading is
inferred from field names; no CrowdStrike text says "uploaded by the CLI".
The `rule` object's schema cannot be recovered from any SDK: the OpenAPI spec
names it `Rule`, which collides with an unrelated notification-rule model
(`id` int, `alertType`, `buttonText`, `ruleDestinations`, ...) in gofalcon,
falconjs and crimson-falcon alike (U10 `rule.go`, U12). The developer center
example shows `rule` as an empty object (U9). The filter field names
(`rule_uuid`, `rule_name`, `rule_category`, `rule_type`, `platform`,
`provider`, `service`, `severity`) are the keys the CLI writes in
`rule_detections[]` (`rule_uuid`, `rule_name`, `rule_category`, `rule_type`,
`platform`, `cloud_provider`, `service`, `severity`; U19, fcs-cli.md §5), so
the detection store is keyed by the CLI's rule UUID.

**IaC rule catalogue: no direct operation.** Nothing under `/iac/` lists
rules, and a code search over the CrowdStrike organisation for `iac/scans`,
`iac-scan`, `cloud-security-iac` finds only the SARIF converter's
`iac/<rule_uuid>` id prefix (U17). The only indirect route is Cloud Policies
(§1b): the Terraform provider creates IaC custom rules through
`CreateRuleMixin0` with `domain = "CSPM"`, `subdomain = "IAC"`, `platform` =
`iac_framework` ("Currently only Terraform is supported"), `provider`
(`AWS|Azure|GCP|General`), `resource_type` ("Service-level category",
default `Custom`), `category`, `labels` (stored in `custom_configuration`),
reads them back with `GetRule`, and reads `iac_framework` from
`rule_logic_list[0].platform` (U14 `custom_iac_rule_resource.go` lines 40-41,
378-382, 428-480; docs). So `QueryRule` with `rule_domain:'CSPM'+rule_subdomain:'IAC'`
lists at least custom IaC rules. Whether CrowdStrike's shipped IaC rules
(`rule_origin:'Default'`) are in that table, and whether their `uuid` equals
the CLI's `rule_uuid`, is unverified; the CLI-side "cloud custom rules"
fetch (fcs-cli.md §6) uses a non-public endpoint.

**Upload: no public operation.** No SDK has a write operation under `/iac/`
(U11, U17), consistent with contract.md §4.

Status: results read-back confirmed as an operation (field semantics
inferred); rule catalogue absent (confirmed); custom-IaC-rule listing via
Cloud Policies confirmed by provider code; default-rule listing unverified.

## 4. Shared identifiers between IaC rules and IOM policies

Field-by-field comparison of the models in §1-§3:

| Identifier family | Legacy CSPM policy (§1a) | Cloud Policies rule (§1b) | IOM detection (§2) | IaC rule / detection (§3, CLI JSON) |
|-------------------|--------------------------|---------------------------|--------------------|-------------------------------------|
| Integer policy id | `ID` / `policy_id` | none on the rule; `EvaluationsRule.policy_id` on IOMs only | `policy_id`, `custom_policy_id` (2a); `rule.policy_id` (2b) | none |
| Rule / policy UUID | none | `uuid`, `parent_rule_short_uuid`, `short_code` | `rule.id`, `rule.policy.uuid` | `rule_uuid` (CLI), `rule_uuid` filter (API) |
| Benchmark / control | `cis_benchmark_ids[]`, `cis_benchmark[] {benchmark_short, recommendation_number}`, `controls[]`, `compliance{}` | `controls[] {authority, code, security_framework[]}`, filters `rule_compliance_benchmark(_uuid)`, `rule_control_section/requirement` | `rule.controls[] {code, framework, benchmarks[] {id,name,version}}`, filters `benchmark_name`, `framework`, `section`, `requirement` | none (CLI JSON has `rule_category` only; API filters have no benchmark field) |
| Platform / provider / service | `cloud_platform_type`, `cloud_service_type`, `cloud_asset_type`, `resource_type_id` | `provider`, `platform`, `resource_types[] {resource_type, service}`, `category` | `cloud.provider`, `resource.service`, `resource.resource_type` | `cloud_provider`/`provider`, `service`, `platform` (`terraform`, ...), `rule_category`, `resource_type` (Terraform type, e.g. `aws_security_group`) |
| Cross-reference field | none | `domain`/`subdomain` (`IOM` vs `IAC`); `parent_rule_id` (cloning within a subdomain, U14) | none | none |

Findings:

- No model on either side carries the other's key. No IOM policy or rule
  field is named `iac_*`, and no IaC detection or CLI field names a policy id,
  rule UUID, benchmark id or control code (U1-U5, U10, U19). Confirmed.
- No benchmark bridge: IOM rules and legacy policies are richly annotated
  with CIS/NIST/PCI controls, but the IaC side exposes no benchmark or control
  identifier anywhere (CLI JSON shape in fcs-cli.md §5; API filter list in
  U5). Confirmed.
- The one shared namespace is the Cloud Policies rule table, where an IaC
  rule and an IOM rule are rows of the same model distinguished by
  `subdomain` (U3, U14). Nothing in that model links a row in one subdomain
  to a row in the other; the Terraform IaC resource has no `parent_rule_id`
  (U14). So co-location is not a mapping. Confirmed.
- Any mapping would therefore be heuristic: match IaC `cloud_provider` +
  `service` + `rule_name`/`description` tokens against IOM rule `provider` +
  `resource_types[].service` + `name`, and against legacy policy
  `cloud_service_type` + `policy_statement`. The Terraform data source's
  example IOM rule name "NLB/ALB configured publicly with TLS/SSL disabled"
  (U14) and the IaC custom rule example "Check SSH Access from Anywhere" (U14)
  show the two vocabularies are free text. Inferred.
- No CrowdStrike document found joins the terms: searches for IaC-to-IOM
  mapping, "shift left"/"IaC to runtime" with IOM, and the same terms on
  developer.crowdstrike.com return the product page (contract.md T25), the
  MCP module page and the Terraform docs, none of which describe a linkage
  (U18). The login-walled IaC documentation (fcs-cli.md S16) may; unverified.

Status: absence of a shared identifier confirmed from the public field lists;
heuristic name/service matching inferred; login-walled docs unverified.

## 5. Per-resource IOM exemptions through the API

Three mechanisms exist, all under scopes a mapping client would hold anyway;
none is labelled "exemption" in any public CrowdStrike source (the API,
Terraform provider and MCP server all say "suppression"; U13-U15, U18).

### 5a. Suppression rules (Cloud Policies)

| Operation | Method, path | Scope (U8) | Notes (U3, U13) |
|-----------|--------------|-----------|-----------------|
| `QuerySuppressionRules` | GET `/cloud-policies/queries/suppression-rules/v1` | `cloud-security-policies:read` | filter `name`, `description`, `domain`, `subdomain`, `suppression_expiration_date`, `suppression_reason`, `created_by`, `created_at`, `last_modified_at`, `disabled`, `groups`; `limit` default 20 max 50; sort suffix `.asc`/`.desc` |
| `GetSuppressionRules` | GET `/cloud-policies/entities/suppression-rules/v1` | read | `ids` (required) |
| `CreateSuppressionRule` | POST same path | `cloud-security-policies:write` | body below |
| `UpdateSuppressionRule` | PATCH same path | write | |
| `DeleteSuppressionRules` | DELETE same path | write | `ids`, max 10 |

Body and entity (`ApimodelsSuppressionRule`, U10; body shape from U13 and
the exact payload `falcon-mcp` sends, U15 `cloud_iom.py` lines 320-335):
`name`, `description`, `domain` = `"CSPM"`, `subdomain` = `"IOM"`,
`suppression_reason` (Terraform: "One of: accept-risk, compensating-control,
false-positive", U14), `suppression_comment` ("attached to the findings
suppressed by this rule", U14), `suppression_expiration_date` (RFC 3339;
"Omitting this creates a PERMANENT suppression", U15), `rule_selection_type`
= `"rule_selection_filter"`, `rule_selection_filter {rule_ids[],
rule_names[], rule_origins[], rule_providers[], rule_services[],
rule_severities[], rule_resource_type_names[], rule_risk_factors[]}`,
`rule_selection_count`, `scope_type` = `"asset_filter"` or `"all_assets"`,
`scope_asset_filter {account_ids[], cloud_group_ids[], cloud_providers[],
regions[], resource_ids[], resource_names[], resource_types[],
service_categories[], tags[]}`, `disabled`, `id`, `created_*`, `updated_*`.

Per-resource scoping is `scope_asset_filter.resource_ids`: "Set of resource
IDs. An Asset will match if its resource ID is included in this set" (U14);
within an attribute values are OR-ed, across attributes AND-ed (U14).
Semantics: "Suppressed findings are still assessed but not surfaced in
compliance scores" (U15 docstring); deleting a rule "reactivates suppressed
findings" (U15 developer center page); Terraform `type` is "One of: IOM"
(U14), so there is no IaC suppression type. The `rule_ids` here are Cloud
Policies rule UUIDs (§1b), and `ApimodelsRule.overrides[].suppression_rule_id`
plus the Terraform data source's `suppression_rule_ids` (U14
`rules_data_source.go` lines 557-565) expose the reverse link from a rule to
the suppressions touching it.

### 5b. Rule overrides (Cloud Policies)

`GetRuleOverride` GET / `CreateRuleOverride` POST / `UpdateRuleOverride`
PATCH / `DeleteRuleOverride` DELETE `/cloud-policies/entities/rule-overrides/v1`;
read for GET, write for the rest (U8, U9). Create body is `overrides[]` of
`{rule_id, crn, target_region, override_type, overrides_details, reason,
comment, expires_at}`; every field except `expires_at` is "Required: true"
(U10 `common_single_create_rule_override_request.go`; U13). The stored
`ApimodelsRuleOverride` adds `uuid`, `user_id`, `asset_filter`,
`asset_scope_type`, `suppression_rule_id`, `created_*`, `updated_*`,
`deleted_*` (U10). `crn` is a single cloud resource name, so this is the
per-resource primitive, but the allowed `override_type` values are documented
nowhere public (U9, U12, U13, U17: the only GitHub hits for
`override_type` + `rule-overrides` are a third party's code). Whether it
suppresses, re-scores severity, or both is therefore unverified; the IOM-side
`EvaluationsRuleOverride {override_type, severity, suppressed, suppressed_by,
suppression_reason, suppression_comment, suppression_rule_id,
expiration_timestamp, update_reason}` (U10) suggests both kinds exist
(inferred).

### 5c. Policy settings (CSPM Registration)

`UpdateCSPMPolicySettings` (§1a; `cspm-registration:write`) toggles
`enabled`, overrides `severity`, and limits by `account_id(s)`, `regions` and
`tag_excluded` per `policy_id` (U1, U10). Granularity is account/region/tag,
not an individual resource. Confirmed.

### 5d. Reading what was exempted

An IOM that is suppressed still appears in `cspm_evaluations_iom_queries`
with `suppressed_by` and `suppression_reason` set, and its entity carries
`evaluation.rule.override` (U2, U10). The mapping script can therefore list
every suppressed IOM per resource with "Cloud Security API Detections: READ"
alone, and resolve the suppression rule or override behind it with "Cloud
Security Policies: READ". Confirmed from field lists; the `status` value a
suppressed IOM carries (`non-compliant` vs something else) is unverified.

Which of 5a/5b the console's per-asset action writes is not established:
the console documentation is login-walled and no public CrowdStrike text
describes that UI (U18). Inferred: a console "suppress on this asset" is a
suppression rule with `scope_asset_filter.resource_ids` or a rule override
with `crn`; both are readable through the operations above.

Status: operations, scopes and fields confirmed; `override_type` values and
the console action's backing object unverified.

## 6. Scope names the API client needs

Console labels as the developer center prints them per operation (U9) and
as the Terraform provider prints them (U14), with the wiki's internal token
(U8). The Foundry page spells two of them differently ("CSPM Registration",
"Cloud Security Assets", U16), so expect the console's API-client page to be
the final authority on spelling.

| Console label (developer center / Terraform) | Token (wiki) | Needed for | Beyond read? |
|----------------------------------------------|--------------|------------|--------------|
| "CSPM registration: READ" ("CSPM Registration" on U16) | `cspm-registration:read` | §1a policies, §2a legacy IOMs | No. WRITE is only needed for `UpdateCSPMPolicySettings` and account registration; the same scope also governs account create/delete, so do not grant WRITE. |
| "Cloud Security Policies: READ" ("Cloud Security Policies \| Read & Write" in Terraform docs) | `cloud-security-policies:read` | §1b rules and compliance controls, §5 reading suppression rules and overrides | No at READ. WRITE additionally allows creating/deleting custom rules, suppression rules and overrides (U8, U9); grant it only if the script must write exemptions. |
| "Cloud Security API Detections: READ" | `cloud-security-detections:read` | §2b IOMs, §1b `ioms-by-rule` | No; the collection has no write operation (U2). |
| "Cloud Security API Assets: READ" | `cloud-security-assets:read` | §2c assets, compliance posture summaries | No; no write operation (U4, U6). |
| "Infrastructure as Code (IaC): READ" | `infrastructure-as-code:read` | §3 `CombinedDetections` | Already covered by the gate's "Infrastructure as Code: Read & Write" (fcs-cli.md §8), which is more than read. |

Not needed for the mapping but adjacent: "Cloud Security API Risks: READ"
(`combined_cloud_risks`), "Cloud Groups V2: READ" (U15), "Snapshot: READ"
(the non-IaC half of Cloud Snapshots, U8).

So, in addition to "Cloud Security Tools Download: Read" and "Infrastructure
as Code: Read & Write", an offline mapping script needs: **CSPM registration:
READ**, **Cloud Security Policies: READ**, **Cloud Security API Detections:
READ**, **Cloud Security API Assets: READ** (optional, only for the
per-resource asset view). All four are read-only grants.

Status: confirmed (per-operation scope from U8 cross-checked with U9 labels
where the page rendered the operation).

## Gaps still open

1. The shape of `rule` in the IaC detection response (`/iac/combined/detections/v1`):
   the spec's `Rule` name collides with another model in every SDK.
2. Whether CrowdStrike-shipped IaC rules appear in Cloud Policies
   (`QueryRule`, `rule_subdomain:'IAC'`, `rule_origin:'Default'`) and whether
   their `uuid` equals the CLI's `rule_uuid`.
3. Allowed `override_type` values for rule overrides, and whether an
   override suppresses, re-scores, or both.
4. Which object (suppression rule or rule override) the console writes when
   a user suppresses an IOM on one asset; the `status` value a suppressed IOM
   carries.
5. Whether `GetCSPMPolicySettings` with no parameters enumerates every
   policy, and whether legacy `policy_id` is stable across tenants.
6. Any CrowdStrike-maintained IaC-to-IOM correspondence (login-walled IaC
   documentation, fcs-cli.md S16).
7. The exact console spelling of each scope on the API-client page (three
   CrowdStrike pages use three spellings for the CSPM registration scope).

## Implications for the gate

- The API cannot produce the mapping. No IaC rule or detection field
  references an IOM policy id, rule UUID, benchmark or control, and no
  CrowdStrike document claims a link; any IaC-to-IOM table has to be built
  heuristically (provider + service + name) and reviewed by a human.
- The raw material is available read-only: IOM rules with controls and
  resource types (`QueryRule`/`GetRule`), legacy policies with CIS
  recommendation numbers (`GetCSPMPolicySettings`), live IOMs keyed by rule
  UUID and legacy policy id (`cspm_evaluations_iom_*`), and the CLI's own
  rule UUIDs via `CombinedDetections` after a scan with `--upload-results`.
- Grant the mapping client four read scopes (CSPM registration: READ,
  Cloud Security Policies: READ, Cloud Security API Detections: READ, Cloud
  Security API Assets: READ) and keep the write grants off; the gate's
  existing IaC Read & Write already covers the IaC read-back.
- Per-resource exemptions are readable: list IOMs with `suppressed_by` /
  `suppression_reason` set, then `GetSuppressionRules` (`scope_asset_filter.resource_ids`)
  or `GetRuleOverride` (`crn`). The gate can mirror a console suppression as
  an IaC exclusion only by the heuristic rule mapping above, so treat that
  mirror as advisory.
- Suppressions are IOM-only (`type` IOM) and do not touch IaC scans; a
  resource exempted in the console will still fail the gate unless the gate
  carries its own allow-list keyed by the IaC `rule_uuid` and Terraform
  resource address.
- Build the mapping from the new rule UUIDs, not the legacy integer policy
  ids: the v1 IOM endpoint is already decommissioned, and each new IOM
  carries `rule.policy_id` if the legacy id is ever needed.
- Enumerating a tenant's IOMs is bounded by 1,000-item pages with `after`
  tokens, and `QueryRule` by 500 per page with offsets; a nightly offline
  job is realistic, a per-PR call is not necessary.
- Prove the two inferences before relying on them: run `CombinedDetections`
  once after an uploaded scan to see the `rule` object, and `QueryRule` with
  `rule_subdomain:'IAC'+rule_origin:'Default'` to see whether shipped IaC
  rules are listed and keyed by the CLI's `rule_uuid`.
