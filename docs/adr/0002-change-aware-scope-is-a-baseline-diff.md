---
status: accepted
---

# Change-aware Scope is a baseline diff, not a changed-files filter

One Consumer environment carries a large backlog of existing findings, so its gate must block only on what a change introduces. We decided that Change-aware Scope scans the Consumer's source twice per run, at the Baseline and at the change, and counts only Findings present after but not before. Two Findings are the same when rule UUID, file path, resource type and resource name all match; line numbers are ignored, so a renamed or moved resource counts as new.

## Considered options

- **Changed-files filter** (one scan, keep only Findings in files the diff touched). Rejected: a change to a variables file that makes a resource in an untouched file insecure is missed, and touching a file with thirty old findings blocks a one-line change until all thirty are fixed, which pushes people toward bypasses we don't offer.
- **Plan-resource filter** (only Findings on resources the Terraform plan will create or update). Rejected for v1: the gate would depend on the plan and on mapping HCL names to plan addresses through modules, `count` and `for_each`.

## Consequences

- Two scans per Change-aware run; only the scan of the change is uploaded to the console.
- No cleanup pressure on pre-existing findings. If the backlog does not shrink, a stricter "touched files must be clean" add-on is the next decision, not a change to this one.
- The Baseline must be resolvable (Consumer-provided ref, defaulting to the commit before the push); an unresolvable Baseline is a blocked Verdict, per ADR 0001.
