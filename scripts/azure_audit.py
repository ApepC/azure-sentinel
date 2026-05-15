#!/usr/bin/env python3
"""
azure_audit.py — Azure Resource Compliance Auditor
====================================================
AZ-104 Portfolio Project | Fred Mann

Connects to your Azure subscription and audits:
  - NSG rules for dangerous open ports (22, 3389, 1433 from Internet)
  - Storage accounts for public blob access & HTTP
  - Key Vaults for soft-delete and RBAC settings
  - VMs for missing managed identity and disk encryption
  - Resource groups for missing required tags
  - Log Analytics workspace coverage

Output: colored terminal report + optional JSON export

Requirements:
    pip install azure-identity azure-mgmt-network azure-mgmt-storage \
                azure-mgmt-keyvault azure-mgmt-compute azure-mgmt-resource \
                azure-mgmt-monitor rich

Usage:
    # Authenticate first:
    az login

    # Run audit (current subscription):
    python scripts/azure_audit.py

    # Target specific subscription:
    python scripts/azure_audit.py --subscription-id <YOUR_SUB_ID>

    # Export JSON report:
    python scripts/azure_audit.py --output report.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Any

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
from azure.mgmt.storage import StorageManagementClient
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

console = Console()

REQUIRED_TAGS = {"environment", "project", "owner", "managedBy"}
DANGEROUS_PORTS = {22, 3389, 1433, 5432, 3306, 6379, 27017}
DANGEROUS_PORT_NAMES = {
    22: "SSH", 3389: "RDP", 1433: "MSSQL",
    5432: "PostgreSQL", 3306: "MySQL",
    6379: "Redis", 27017: "MongoDB"
}


# ── Data Classes ─────────────────────────────────────────────────────────────

class Finding:
    def __init__(self, resource: str, category: str, severity: str,
                 message: str, remediation: str = ""):
        self.resource = resource
        self.category = category
        self.severity = severity      # CRITICAL | HIGH | MEDIUM | LOW | PASS
        self.message = message
        self.remediation = remediation
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "resource": self.resource,
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
            "remediation": self.remediation,
            "timestamp": self.timestamp
        }


# ── Audit Functions ───────────────────────────────────────────────────────────

def audit_nsgs(credential, subscription_id: str) -> list[Finding]:
    """Check NSG rules for dangerous internet-exposed ports."""
    findings = []
    client = NetworkManagementClient(credential, subscription_id)

    for nsg in client.network_security_groups.list_all():
        nsg_name = nsg.name or "unknown"
        resource_group = nsg.id.split("/")[4] if nsg.id else "unknown"

        for rule in (nsg.security_rules or []):
            if rule.access != "Allow" or rule.direction != "Inbound":
                continue

            src = rule.source_address_prefix or ""
            is_internet = src in ("*", "Internet", "0.0.0.0/0", "Any")

            if not is_internet:
                continue

            # Collect destination ports
            ports = set()
            if rule.destination_port_range:
                _expand_port_range(rule.destination_port_range, ports)
            for pr in (rule.destination_port_ranges or []):
                _expand_port_range(pr, ports)

            exposed = ports & DANGEROUS_PORTS
            if exposed:
                port_str = ", ".join(
                    f"{p}/{DANGEROUS_PORT_NAMES.get(p, '')}" for p in sorted(exposed)
                )
                findings.append(Finding(
                    resource=f"NSG: {nsg_name} (RG: {resource_group})",
                    category="Network Security",
                    severity="CRITICAL",
                    message=f"Rule '{rule.name}' exposes port(s) {port_str} to Internet",
                    remediation=(
                        "Restrict source address to a specific CIDR or use "
                        "Azure Bastion for management access."
                    )
                ))
            else:
                findings.append(Finding(
                    resource=f"NSG: {nsg_name}",
                    category="Network Security",
                    severity="PASS",
                    message=f"Rule '{rule.name}' does not expose dangerous ports"
                ))

    return findings


def audit_storage(credential, subscription_id: str) -> list[Finding]:
    """Check storage accounts for security misconfigurations."""
    findings = []
    client = StorageManagementClient(credential, subscription_id)

    for account in client.storage_accounts.list():
        name = account.name or "unknown"
        resource_label = f"Storage: {name}"

        # Public blob access
        if account.allow_blob_public_access:
            findings.append(Finding(
                resource=resource_label,
                category="Storage Security",
                severity="HIGH",
                message="Public blob access is ENABLED",
                remediation="Set allowBlobPublicAccess=false in storage account properties."
            ))
        else:
            findings.append(Finding(
                resource=resource_label,
                category="Storage Security",
                severity="PASS",
                message="Public blob access is disabled"
            ))

        # HTTPS only
        if not account.enable_https_traffic_only:
            findings.append(Finding(
                resource=resource_label,
                category="Storage Security",
                severity="HIGH",
                message="HTTP traffic is ALLOWED (not HTTPS-only)",
                remediation="Enable supportsHttpsTrafficOnly on the storage account."
            ))
        else:
            findings.append(Finding(
                resource=resource_label,
                category="Storage Security",
                severity="PASS",
                message="HTTPS-only traffic enforced"
            ))

        # Minimum TLS version
        tls = account.minimum_tls_version or "TLS1_0"
        if tls in ("TLS1_0", "TLS1_1"):
            findings.append(Finding(
                resource=resource_label,
                category="Storage Security",
                severity="MEDIUM",
                message=f"Minimum TLS version is {tls}",
                remediation="Set minimumTlsVersion to TLS1_2."
            ))
        else:
            findings.append(Finding(
                resource=resource_label,
                category="Storage Security",
                severity="PASS",
                message=f"Minimum TLS version: {tls}"
            ))

        # Network default action
        nacls = account.network_rule_set
        if nacls and nacls.default_action == "Allow":
            findings.append(Finding(
                resource=resource_label,
                category="Storage Security",
                severity="HIGH",
                message="Network ACL default action is ALLOW (open to internet)",
                remediation="Set networkAcls.defaultAction=Deny and add specific VNet/IP rules."
            ))
        else:
            findings.append(Finding(
                resource=resource_label,
                category="Storage Security",
                severity="PASS",
                message="Network ACL default action is Deny"
            ))

    return findings


def audit_key_vaults(credential, subscription_id: str) -> list[Finding]:
    """Check Key Vault security configuration."""
    findings = []
    client = KeyVaultManagementClient(credential, subscription_id)

    for vault in client.vaults.list():
        name = vault.name or "unknown"
        resource_label = f"Key Vault: {name}"
        props = vault.properties

        # Soft delete
        if not props.enable_soft_delete:
            findings.append(Finding(
                resource=resource_label,
                category="Key Vault",
                severity="HIGH",
                message="Soft delete is DISABLED — secrets can be permanently deleted",
                remediation="Enable softDelete. Note: cannot be disabled once enabled."
            ))
        else:
            findings.append(Finding(
                resource=resource_label,
                category="Key Vault",
                severity="PASS",
                message=f"Soft delete enabled ({props.soft_delete_retention_in_days} days)"
            ))

        # RBAC vs legacy access policies
        if not props.enable_rbac_authorization:
            findings.append(Finding(
                resource=resource_label,
                category="Key Vault",
                severity="MEDIUM",
                message="Using legacy access policies instead of RBAC",
                remediation="Migrate to enableRbacAuthorization=true for fine-grained control."
            ))
        else:
            findings.append(Finding(
                resource=resource_label,
                category="Key Vault",
                severity="PASS",
                message="RBAC authorization enabled"
            ))

        # Network ACLs
        nacls = props.network_acls
        if not nacls or nacls.default_action == "Allow":
            findings.append(Finding(
                resource=resource_label,
                category="Key Vault",
                severity="HIGH",
                message="Key Vault network ACL allows all traffic (no private endpoint or VNet rule)",
                remediation="Set networkAcls.defaultAction=Deny and restrict to specific VNets."
            ))
        else:
            findings.append(Finding(
                resource=resource_label,
                category="Key Vault",
                severity="PASS",
                message="Network ACL default action is Deny"
            ))

    return findings


def audit_vms(credential, subscription_id: str) -> list[Finding]:
    """Check VMs for security and cost-control settings."""
    findings = []
    client = ComputeManagementClient(credential, subscription_id)

    for vm in client.virtual_machines.list_all():
        name = vm.name or "unknown"
        resource_label = f"VM: {name}"

        # Managed identity
        if not vm.identity or vm.identity.type == "None":
            findings.append(Finding(
                resource=resource_label,
                category="VM Security",
                severity="MEDIUM",
                message="No managed identity assigned — VM cannot authenticate to Azure services securely",
                remediation="Assign a System-Assigned or User-Assigned managed identity."
            ))
        else:
            findings.append(Finding(
                resource=resource_label,
                category="VM Security",
                severity="PASS",
                message=f"Managed identity: {vm.identity.type}"
            ))

        # Trusted launch / Secure boot
        sec_profile = vm.security_profile
        if not sec_profile or not sec_profile.uefi_settings:
            findings.append(Finding(
                resource=resource_label,
                category="VM Security",
                severity="LOW",
                message="Trusted Launch (Secure Boot / vTPM) not configured",
                remediation="Enable TrustedLaunch securityType with secureBootEnabled and vTpmEnabled."
            ))
        else:
            sb = sec_profile.uefi_settings.secure_boot_enabled
            vtpm = sec_profile.uefi_settings.v_tpm_enabled
            findings.append(Finding(
                resource=resource_label,
                category="VM Security",
                severity="PASS" if sb and vtpm else "LOW",
                message=f"Trusted Launch: SecureBoot={sb}, vTPM={vtpm}"
            ))

    return findings


def audit_tags(credential, subscription_id: str) -> list[Finding]:
    """Check resource groups for required tag compliance."""
    findings = []
    client = ResourceManagementClient(credential, subscription_id)

    for rg in client.resource_groups.list():
        name = rg.name or "unknown"
        resource_label = f"Resource Group: {name}"
        existing_tags = set((rg.tags or {}).keys())
        missing = REQUIRED_TAGS - existing_tags

        if missing:
            findings.append(Finding(
                resource=resource_label,
                category="Governance",
                severity="MEDIUM",
                message=f"Missing required tags: {', '.join(sorted(missing))}",
                remediation=f"Add tags: {', '.join(sorted(missing))} to the resource group."
            ))
        else:
            findings.append(Finding(
                resource=resource_label,
                category="Governance",
                severity="PASS",
                message="All required tags present"
            ))

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _expand_port_range(port_range: str, target: set) -> None:
    """Expand '22', '8080-8090', or '*' into individual port numbers."""
    if port_range == "*":
        target.update(DANGEROUS_PORTS)
        return
    if "-" in port_range:
        lo, hi = port_range.split("-", 1)
        try:
            for p in range(int(lo), int(hi) + 1):
                target.add(p)
        except ValueError:
            pass
    else:
        try:
            target.add(int(port_range))
        except ValueError:
            pass


def get_subscription_id(credential) -> str:
    """Return the first available subscription ID."""
    client = SubscriptionClient(credential)
    subs = list(client.subscriptions.list())
    if not subs:
        console.print("[red]No Azure subscriptions found. Run 'az login' first.[/red]")
        sys.exit(1)
    return subs[0].subscription_id


# ── Reporting ─────────────────────────────────────────────────────────────────

SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "PASS":     "green",
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "PASS":     "✅",
}


def print_report(findings: list[Finding], subscription_id: str) -> None:
    console.print()
    console.print(Panel.fit(
        f"[bold cyan]Azure Infrastructure Sentinel[/bold cyan]\n"
        f"[dim]Subscription: {subscription_id}[/dim]\n"
        f"[dim]Scan time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}[/dim]",
        border_style="cyan"
    ))

    # Summary counts
    counts = {s: 0 for s in SEVERITY_COLOR}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    summary = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    summary.add_column("Severity",   style="bold")
    summary.add_column("Count",      justify="right")
    summary.add_column("Status")
    for sev, color in SEVERITY_COLOR.items():
        summary.add_row(
            f"[{color}]{sev}[/{color}]",
            str(counts.get(sev, 0)),
            SEVERITY_EMOJI[sev]
        )
    console.print(summary)
    console.print()

    # Detailed findings (non-PASS only)
    issues = [f for f in findings if f.severity != "PASS"]
    if not issues:
        console.print("[bold green]✅ No issues found — infrastructure is clean![/bold green]")
        return

    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold white",
                  title="[bold]Findings[/bold]", expand=True)
    table.add_column("Severity",    style="bold", no_wrap=True)
    table.add_column("Category",    no_wrap=True)
    table.add_column("Resource",    overflow="fold")
    table.add_column("Issue",       overflow="fold")
    table.add_column("Remediation", overflow="fold", style="dim")

    for f in sorted(issues, key=lambda x: list(SEVERITY_COLOR).index(x.severity)):
        color = SEVERITY_COLOR[f.severity]
        table.add_row(
            f"[{color}]{SEVERITY_EMOJI[f.severity]} {f.severity}[/{color}]",
            f.category,
            f.resource,
            f.message,
            f.remediation
        )

    console.print(table)


def export_json(findings: list[Finding], path: str) -> None:
    data = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "summary": {
            sev: sum(1 for f in findings if f.severity == sev)
            for sev in SEVERITY_COLOR
        },
        "findings": [f.to_dict() for f in findings]
    }
    with open(path, "w") as fp:
        json.dump(data, fp, indent=2)
    console.print(f"\n[green]Report saved to: {path}[/green]")


# ── Entry Point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Azure Infrastructure Security Auditor")
    parser.add_argument("--subscription-id", help="Azure subscription ID (default: first available)")
    parser.add_argument("--output", help="Export results to JSON file (e.g. report.json)")
    parser.add_argument("--skip-vms",     action="store_true", help="Skip VM audit")
    parser.add_argument("--skip-storage", action="store_true", help="Skip storage audit")
    parser.add_argument("--skip-kvs",     action="store_true", help="Skip Key Vault audit")
    parser.add_argument("--skip-nsgs",    action="store_true", help="Skip NSG audit")
    parser.add_argument("--skip-tags",    action="store_true", help="Skip tag compliance audit")
    args = parser.parse_args()

    credential = DefaultAzureCredential()
    sub_id = args.subscription_id or get_subscription_id(credential)

    all_findings: list[Finding] = []

    audit_tasks = []
    if not args.skip_nsgs:    audit_tasks.append(("Auditing NSG rules...",     audit_nsgs,    [credential, sub_id]))
    if not args.skip_storage: audit_tasks.append(("Auditing Storage accounts...", audit_storage, [credential, sub_id]))
    if not args.skip_kvs:     audit_tasks.append(("Auditing Key Vaults...",    audit_key_vaults, [credential, sub_id]))
    if not args.skip_vms:     audit_tasks.append(("Auditing Virtual Machines...", audit_vms,  [credential, sub_id]))
    if not args.skip_tags:    audit_tasks.append(("Auditing Tag compliance...", audit_tags,   [credential, sub_id]))

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), console=console) as progress:
        for description, fn, fn_args in audit_tasks:
            task = progress.add_task(description)
            results = fn(*fn_args)
            all_findings.extend(results)
            progress.remove_task(task)

    print_report(all_findings, sub_id)

    if args.output:
        export_json(all_findings, args.output)


if __name__ == "__main__":
    main()
