---
status: accepted
---

# Invoke the fcs CLI directly rather than through CrowdStrike/fcs-action

CrowdStrike publishes an official GitHub Action for `fcs`, and a reader will reasonably expect this gate to use it. We decided instead to download the pinned CLI binary through the Falcon download API, verify its SHA-256, and invoke it directly with credentials in the environment. The research in `docs/research/fcs-cli.md` found that the action always exits 0 and only exposes the scan result as a step output, floats the CLI version unless told otherwise, force-moves its major tags on every release, and with upload enabled places the client secret on the CLI command line. Each of those is a behaviour a security gate has to own, not inherit.

## Consequences

- The gate carries its own download-and-verify step and a pinned version plus checksum, bumped by pull request here (no automatic bumps in v1).
- Rule and severity drift between CLI versions arrives only when we choose to take it, with a note in the bump.
- If the action's behaviour changes in ways that remove these objections, revisit; until then, do not "simplify" the gate by swapping the action back in.
