# fcs-deploy-gate

A pre-apply check that stops Terraform deployments which would create CrowdStrike IOMs. One context: the gate and the vocabulary its consumers share with it.

## Language

### What is checked

**IOM**:
An Indicator of Misconfiguration: the finding Falcon Cloud Security raises against a cloud resource that already exists. Preventing IOMs is the gate's sole purpose.
_Avoid_: CSPM finding, posture finding, console finding, misconfiguration alert

**Finding**:
A result the CrowdStrike IaC scan reports for a piece of Terraform source, at any severity. It exists to anticipate an IOM, but which Findings correspond to which IOMs is not one-to-one and is measured, never assumed.
_Avoid_: violation, issue, alert, IOM (a Finding is not yet an IOM)

**Severity**:
CrowdStrike's rating of a Finding: critical, high, medium or informational.
_Avoid_: low, info

**Policy**:
The IaC rule set active in the Falcon tenant. The gate evaluates against it and nothing else.
_Avoid_: ruleset, local rules, pinned rules

### Deciding

**Blocking threshold**:
The set of severities at or above which a Finding counts against a Deployment. Critical, high and medium by default.
_Avoid_: fail-on, severity filter

**Exclusion**:
A version-controlled exemption, declared in a Consumer and approved by a named member of the Security team, that stops one specific Finding from counting against a Deployment until a date the Exclusion names. It governs what is about to be deployed; a console exemption governs an IOM that already exists.
_Avoid_: bypass, break-glass, suppression, waiver, allowlist

**Stale exclusion**:
An Exclusion that matches no Finding in the current scan, or whose date has passed. Reported, never silently dropped.
_Avoid_: expired entry, dead exclusion

**Blocking finding**:
A Finding at or above the Blocking threshold, within the call's Scope, that no Exclusion covers.

**Scope**:
Which Findings a call of the gate considers: Whole-tree or Change-aware. Chosen per Consumer.
_Avoid_: mode (that word is for Enforcing/Advisory), filter

**Whole-tree**:
The Scope in which every Finding in the scanned path is considered.
_Avoid_: full scan, strict scope

**Change-aware**:
The Scope in which only Findings absent from the Baseline are considered. A Finding present before and after the change is never a Blocking finding in this Scope.
_Avoid_: diff mode, changed-files, incremental, delta scan

**Baseline**:
The Consumer's Terraform source as it was before the change under deployment. Named by the Consumer; otherwise the target branch's merge base in a merge-request or pull-request pipeline, or the previous commit in a branch pipeline.
_Avoid_: previous scan, last run, reference

**Verdict**:
The gate's conclusion for one Deployment: clear, or blocked by one or more Blocking findings. A run that produces no report has a blocked Verdict.
_Avoid_: result, status, pass/fail, exit code

**Enforcing**:
The gate mode in which a Blocking finding stops the Deployment.
_Avoid_: hard stop, strict, fail mode

**Advisory**:
The gate mode in which Blocking findings are reported and the Deployment proceeds.
_Avoid_: warn-only, soft fail, audit mode, dry run

### Who and what

**Consumer**:
A repository whose Deployments the gate protects, on GitHub or on GitLab.
_Avoid_: client, caller, downstream repo

**Deployment**:
A Terraform apply of a Consumer's infrastructure code, run by a GitHub Actions workflow (new environment) or a GitLab CI pipeline (existing environment). An apply by any other path is outside the gate.
_Avoid_: release, rollout, push

**Security team**:
The group that administers the Falcon tenant and is the final authority on whether an Exclusion is allowed.
_Avoid_: security, SecOps, admins, approvers

**Gate**:
The check that scans a Consumer's Terraform source and decides whether a Deployment proceeds. It runs twice per change: in the merge-request or pull-request pipeline, where an Enforcing block prevents the merge, and again before apply, which is the hard stop.
_Avoid_: preview scan, PR check, scanner, pre-merge gate
