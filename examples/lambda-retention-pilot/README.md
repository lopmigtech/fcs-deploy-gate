# Lambda log retention pilot

A Consumer repository for a demo of the Gate against one rule: a Lambda function whose
CloudWatch log group has no retention. Copy this directory into an empty GitLab project,
set the variables the pipeline's header names, and push.

The Terraform under `lambda/` is the minimum a function needs plus one deliberate gap,
the log group without `retention_in_days`. The pipeline plans in merge-request and
default-branch pipelines, runs the Gate beside the plan, and applies on the default
branch from the planfile only when the Gate's job succeeds.

## What the scanner reports

The first live scan (CLI 4.2.3) raised these on the module, before tags and X-Ray
tracing were added to it:

| Severity | Rule | Rule id |
|---|---|---|
| medium | CloudWatch Log Group Without KMS | `iac/d6b2ef53-b734-49cf-b736-f71a2dc70e4f` |
| informational | CloudWatch Without Retention Period Specified | `iac/939c056f-d3ba-468f-91c3-9db48c5996f3` |
| informational | IAM Access Analyzer Not Enabled | `iac/d5900282-4330-48df-b93f-1d76f44f33a2` |
| informational | Lambda Functions Without X-Ray Tracing | `iac/96d1d823-88a5-4490-98b1-53304a455686` |
| informational | Resource Not Using Tags (three resources) | `iac/9bf272d6-518a-403d-b9cc-bd2f06d296af` |

The retention Finding is informational, so the pipeline sets the Blocking threshold to
include informational. With literal tags and tracing in the module, a scan raises two
Findings, both on the log group: KMS and retention. The KMS one is for the Exclusions
act, because a customer-managed key is outside what the pilot is about. "IAM Access
Analyzer Not Enabled" appeared on two of four scans of the same module and not on the
others; if it shows in yours, exclude it the same way.

## The four acts

1. **Advisory.** Push as is. The Gate lists every Finding on the function and the apply
   proceeds: the log group now exists in the sandbox with no retention, and the IOM for
   it appears in the Falcon console on its next assessment. This is today's world.
2. **Enforcing.** Set `FCS_GATE_MODE: enforcing` and push any change. The Gate blocks
   and the apply job never runs. The summary is in the job log and under `fcs-gate/`
   in the artifacts.
3. **Exclusions.** Add `.fcs-gate.yml` at the repository root, approved and expiring
   (Gate README, "Exclusions"). The Gate still blocks, now on the retention Finding alone.
   ```yaml
   exclusions:
     - rule: iac/d6b2ef53-b734-49cf-b736-f71a2dc70e4f
       file: main.tf
       reason: Log group encryption with a customer-managed key is outside the retention pilot.
       expires: 2026-11-30
       approved_by: <security reviewer>
   ```
   If the Access Analyzer Finding is in your summary, add a second entry with rule
   `iac/d5900282-4330-48df-b93f-1d76f44f33a2`, file `main.tf`, and the reason that the
   analyzer is enabled per account, not in this module.
4. **The fix.** Add `retention_in_days = 30` to the log group and push. The Verdict is
   clear, the apply runs, and the IOM closes on the next assessment.

## Before the first push

- The Gate project exists on the instance with the checksum pin filled, and its job
  token permissions allow this project.
- `FCS_GATE_IMAGE` names an image the runners can pull that carries `python` and `git`.
- Runners reach the Falcon API host for the region, the pre-signed download host, PyPI
  or an internal index, and the Terraform provider registry or its mirror.
- Apply only in the sandbox account. `terraform destroy` with the same backend
  arguments removes the function, its role and the log group afterwards.
