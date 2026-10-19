---
status: accepted
---

# Block on every IaC Finding at threshold until the IOM mapping is measured

The gate exists only to prevent IOMs, but no CrowdStrike source maps IaC scan rules to the IOM policies the console raises, so v1 cannot tell which Findings would become IOMs. We decided that v1 blocks on every Finding at or above the Blocking threshold, a superset of the IOM-relevant ones, rather than blocking on nothing until the mapping exists. Some blocks will be for misconfigurations that would never surface as an IOM; that friction is accepted in exchange for not shipping a gate that prevents nothing.

## Consequences

- Measuring the mapping is an early, tracked ticket, done in the work environment: via the Falcon API if the client can be granted the scopes to list IOM policies and IaC rules, otherwise by applying the insecure fixture to the sandbox and observing which IOMs appear.
- Once measured, narrowing the threshold to IOM-mapped rules is a v1.1 decision and supersedes this ADR.
- Until then, the README must not claim that a clear Verdict means no IOMs will appear.
