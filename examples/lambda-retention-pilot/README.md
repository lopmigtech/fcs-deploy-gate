# Lambda log retention pilot

A Consumer repository for a demo of the Gate against one rule: a Lambda function whose
CloudWatch log group has no retention. Copy this directory into an empty GitLab project,
set the variables the pipeline's header names, and push.

The Terraform under `lambda/` is the minimum a function needs plus one deliberate gap,
the log group without `retention_in_days`. The pipeline plans in merge-request and
default-branch pipelines, runs the Gate beside the plan, and applies on the default
branch from the planfile only when the Gate's job succeeds.

## The four acts

1. **Advisory.** Push as is. The Gate lists every Finding on the function and the apply
   proceeds: the log group now exists in the sandbox with no retention, and the IOM for
   it appears in the Falcon console on its next assessment. This is today's world.
2. **Enforcing.** Set `FCS_GATE_MODE: enforcing` and push any change. The Gate blocks
   and the apply job never runs. The summary is in the job log and under `fcs-gate/`
   in the artifacts.
3. **Exclusions.** The function also raises Findings this pilot is not about. Add a
   `.fcs-gate.yml` at the repository root with one approved, expiring entry per such
   Finding, copying the rule id, resource and file from the summary (Gate README,
   "Exclusions"). The Gate still blocks, now on the retention Finding alone.
4. **The fix.** Add `retention_in_days = 30` to the log group and push. The Verdict is
   clear, the apply runs, and the IOM closes on the next assessment.

If the retention Finding's Severity is informational, add
`FCS_GATE_BLOCKING_THRESHOLD: critical,high,medium,informational` to the variables, or
it sits below the default Blocking threshold.

## Before the first push

- The Gate project exists on the instance with the checksum pin filled, and its job
  token permissions allow this project.
- `FCS_GATE_IMAGE` names an image the runners can pull that carries `python` and `git`.
- Runners reach the Falcon API host for the region, the pre-signed download host, PyPI
  or an internal index, and the Terraform provider registry or its mirror.
- Apply only in the sandbox account. `terraform destroy` with the same backend
  arguments removes the function, its role and the log group afterwards.
