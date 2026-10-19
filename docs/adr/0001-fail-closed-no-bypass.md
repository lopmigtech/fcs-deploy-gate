---
status: accepted
---

# Fail closed, with no bypass

The gate's Verdict is computed from the `fcs` JSON report, not from the CLI exit code: CrowdStrike publishes no exit-code table, and a scan error cannot be told from "findings present" without reading the report. We decided that any run which yields no parseable report (binary download failure, Falcon API outage, CLI crash, timeout) is a blocked Verdict in Enforcing mode after a bounded retry, and that the only sanctioned way past a blocked Verdict is a reviewed Exclusion committed in the Consumer repo. A gate that fails open is not a gate, and a break-glass input is the first thing reached for under pressure, with no audit trail beyond a workflow run.

## Consequences

- A Falcon API outage halts Enforcing deployments until it recovers. A Consumer that cannot tolerate that runs in Advisory mode, consciously and visibly.
- Exclusions are the pressure valve, so they must be cheap to add and impossible to add silently: a reviewed file in the Consumer repo, never a workflow input.
- Reintroducing a bypass later is a new ADR, not a quiet input.
