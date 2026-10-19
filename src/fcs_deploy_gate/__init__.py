"""fcs-deploy-gate: a pre-apply Gate that scans Terraform source with the CrowdStrike fcs CLI."""

from fcs_deploy_gate.gate import run

__all__ = ["run"]
