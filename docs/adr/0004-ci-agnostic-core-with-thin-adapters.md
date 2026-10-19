---
status: accepted
---

# A CI-agnostic core with thin GitHub and GitLab adapters

The gate must protect two estates that deploy through different CI systems: the new environment through GitHub Actions and the existing environment through GitLab CI (Ansible-driven deployments follow in v2). We decided that the gate is a Python package that does all the work (binary download, scans, Baseline diff, Exclusions, Verdict, summary) behind plain command-line arguments and exit codes 0, 1 and 2, and that each CI system gets a deliberately thin adapter that only checks out code, resolves the Baseline ref from that system's variables, and calls the package. Behaviour therefore cannot drift between platforms, and the core's offline test suite is the gate's test suite.

## Consequences

- No gate logic lives in YAML. An adapter that grows a conditional is a smell; move it into the core.
- The GitHub adapter is a reusable workflow plus a composite action; the GitLab adapter is an included CI template. Both pin the gate at the same semver tag as the core, and a test asserts that.
- The official `CrowdStrike/fcs-action` would have covered only one platform and is rejected for other reasons too (ADR 0003).
