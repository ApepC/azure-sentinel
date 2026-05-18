# 🛡️ Azure Infrastructure Sentinel

<div align="center">

![Azure](https://img.shields.io/badge/Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)
![Bicep](https://img.shields.io/badge/Bicep-IaC-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-CI%2FCD-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)
![AZ-104](https://img.shields.io/badge/AZ--104-Certified-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)

**Production-grade Azure infrastructure deployment and security auditing toolkit.**  
Built to demonstrate AZ-104 competency across networking, identity, storage, governance, and monitoring.

[Deploy Now](#-quick-start) · [Architecture](#-architecture) · [Audit Tool](#-security-audit-tool) · [CI/CD Pipeline](#-cicd-pipeline)

</div>

---

## 📋 What This Project Demonstrates

| AZ-104 Domain | Coverage |
|---|---|
| **Manage Azure Identities & Governance** | RBAC on Key Vault, Managed Identity on VMs, tag compliance auditing |
| **Implement & Manage Storage** | Secure Storage Account: HTTPS-only, no public blob, TLS 1.2, VNet service endpoints, GRS for prod |
| **Deploy & Manage Azure Compute** | Ubuntu 22.04 LTS VM with Trusted Launch, auto-shutdown, OMS agent, system-managed identity |
| **Configure & Manage Virtual Networking** | Hub VNet, 5 subnets (frontend/backend/data/mgmt/bastion), tiered NSGs, VNet peering-ready |
| **Monitor & Maintain Azure Resources** | Log Analytics Workspace, diagnostic settings on all resources, GitHub Actions audit pipeline |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    Azure Resource Group                          │
│                                                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │              Virtual Network (10.0.0.0/16)              │   │
│   │                                                         │   │
│   │  ┌─────────────┐  ┌─────────────┐  ┌───────────────┐  │   │
│   │  │  snet-front │  │ snet-backend│  │   snet-data   │  │   │
│   │  │ 10.0.1.0/24 │  │ 10.0.2.0/24│  │ 10.0.3.0/24   │  │   │
│   │  │  NSG: 443✅  │  │ NSG: 8080  │  │ NSG: 1433     │  │   │
│   │  │  NSG: 80 ✅  │  │  from front│  │  from backend │  │   │
│   │  │  SvcEndpoint │  │  KeyVault  │  │  SQL+Storage  │  │   │
│   │  │  Storage     │  │  Endpoint  │  │  Endpoints    │  │   │
│   │  └─────────────┘  └─────────────┘  └───────────────┘  │   │
│   │                                                         │   │
│   │  ┌──────────────────┐  ┌──────────────────────────┐   │   │
│   │  │  snet-management │  │   AzureBastionSubnet     │   │   │
│   │  │  10.0.4.0/24     │  │   10.0.5.0/26            │   │   │
│   │  │  NSG: SSH/RDP    │  │   (Bastion host ready)   │   │   │
│   │  │  from Admin IP   │  │                          │   │   │
│   │  │  only            │  │                          │   │   │
│   │  └──────────────────┘  └──────────────────────────┘   │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│   │ Storage Acct │  │  Key Vault   │  │  Log Analytics       │ │
│   │ HTTPS-only   │  │  RBAC auth   │  │  Workspace           │ │
│   │ No pub blob  │  │  Soft delete │  │  30-day retention    │ │
│   │ TLS 1.2+     │  │  VNet locked │  │  All diag settings   │ │
│   │ VNet rules   │  │  Purge prot* │  │  routed here         │ │
│   └──────────────┘  └──────────────┘  └──────────────────────┘ │
│                          *prod only                              │
└──────────────────────────────────────────────────────────────────┘
```

### Design Decisions

- **Tiered NSG model** — each subnet has its own NSG with least-privilege rules. Frontend accepts internet traffic; backend only from frontend CIDR; data only from backend CIDR. No lateral movement possible by default.
- **Service Endpoints** — Storage and Key Vault traffic stays on the Microsoft backbone, never traversing the public internet.
- **Environment-aware SKUs** — Storage uses `Standard_GRS` in prod, `Standard_LRS` in dev. Key Vault purge protection only enabled in prod (allows teardown in dev without 90-day wait).
- **Zero public IPs on VMs** — Management access via Bastion subnet only. No SSH port exposed.
- **RBAC over Access Policies** — Key Vault uses `enableRbacAuthorization=true` for fine-grained role assignments rather than legacy vault access policies.

---

## 🚀 Quick Start

### Prerequisites

```bash
# 1. Install tools
az --version          # Azure CLI 2.50+
az bicep install      # Bicep CLI (auto-installs)
python --version      # Python 3.11+

# 2. Authenticate
az login
az account set --subscription "<YOUR_SUBSCRIPTION_ID>"
```

### Deploy in 3 Commands

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/azure-sentinel.git
cd azure-sentinel

# 2. Create resource group
az group create \
  --name rg-sentinel-dev \
  --location eastus \
  --tags project=az104-portfolio environment=dev managedBy=bicep

# 3. Deploy (dry-run first)
az deployment group what-if \
  --resource-group rg-sentinel-dev \
  --template-file bicep/main.bicep \
  --parameters @bicep/parameters.dev.json \
  --parameters allowedAdminCidr="$(curl -s ifconfig.me)/32"

# 4. Deploy for real
az deployment group create \
  --resource-group rg-sentinel-dev \
  --template-file bicep/main.bicep \
  --parameters @bicep/parameters.dev.json \
  --parameters allowedAdminCidr="$(curl -s ifconfig.me)/32"
```

### Optional: Deploy with VM

```bash
az deployment group create \
  --resource-group rg-sentinel-dev \
  --template-file bicep/main.bicep \
  --parameters @bicep/parameters.dev.json \
  --parameters allowedAdminCidr="$(curl -s ifconfig.me)/32" \
  --parameters deployVM=true \
  --parameters adminPassword="$(openssl rand -base64 20)!"
```

### Tear Down (avoid charges)

```bash
az group delete --name rg-sentinel-dev --yes --no-wait
```

---

## 🔍 Security Audit Tool

`scripts/azure_audit.py` connects to your Azure subscription and audits your infrastructure for misconfigurations across NSGs, Storage, Key Vaults, VMs, and tag governance.

### Install & Run

```bash
cd scripts
pip install -r requirements.txt

# Run full audit
python azure_audit.py

# Target specific subscription
python azure_audit.py --subscription-id <SUB_ID>

# Export JSON report
python azure_audit.py --output report.json

# Skip specific checks
python azure_audit.py --skip-vms --skip-tags
```

### What It Checks

| Category | Checks |
|---|---|
| **NSG Rules** | Dangerous ports (SSH/RDP/SQL/Redis/Mongo) open to Internet |
| **Storage** | Public blob access, HTTP allowed, TLS version < 1.2, open network ACL |
| **Key Vault** | Soft delete disabled, legacy access policies, open network ACL |
| **Virtual Machines** | No managed identity, Trusted Launch not configured |
| **Governance** | Missing required tags (`environment`, `project`, `owner`, `managedBy`) |

### Sample Output

```
╭─────────────────────────────────────────────────╮
│  Azure Infrastructure Sentinel                  │
│  Subscription: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx │
│  Scan time: 2025-03-09 18:42 UTC                │
╰─────────────────────────────────────────────────╯

┌──────────┬───────┬────────┐
│ Severity │ Count │ Status │
├──────────┼───────┼────────┤
│ CRITICAL │     0 │ ✅     │
│ HIGH     │     1 │ 🟠     │
│ MEDIUM   │     2 │ 🟡     │
│ LOW      │     0 │ 🔵     │
│ PASS     │    24 │ ✅     │
└──────────┴───────┴────────┘

 Severity   Category          Resource              Issue
 🟠 HIGH    Storage Security  Storage: stsentinel   Network ACL default action is ALLOW
 🟡 MEDIUM  Governance        Resource Group: rg-x  Missing required tags: owner, managedBy
 🟡 MEDIUM  Key Vault         Key Vault: kv-dev     Using legacy access policies instead of RBAC
```

---

## ⚙️ CI/CD Pipeline

The GitHub Actions workflow (`deploy.yml`) runs four jobs:

```
Push to main / PR
       │
       ▼
 ┌─────────────┐
 │  Validate   │  Bicep lint + what-if dry run
 └──────┬──────┘
        │ (main branch only)
        ▼
 ┌─────────────┐
 │   Deploy    │  az deployment group create
 └──────┬──────┘
        │
        ▼
 ┌─────────────┐
 │    Audit    │  python azure_audit.py → artifact
 └─────────────┘
```

### GitHub Secrets Required

| Secret | Description |
|---|---|
| `AZURE_CREDENTIALS` | Service principal JSON from `az ad sp create-for-rbac` |
| `AZURE_SUBSCRIPTION_ID` | Your subscription ID |
| `ADMIN_CIDR` | Your IP in CIDR notation (e.g. `203.0.113.5/32`) |

### Set Up Service Principal

```bash
# Create SP with Contributor role on your subscription
az ad sp create-for-rbac \
  --name "sp-sentinel-github" \
  --role "Contributor" \
  --scopes "/subscriptions/<YOUR_SUB_ID>" \
  --sdk-auth

# Paste the JSON output into GitHub → Settings → Secrets → AZURE_CREDENTIALS
```

---

## 📁 Project Structure

```
azure-sentinel/
├── .github/
│   └── workflows/
│       └── deploy.yml          # CI/CD: validate → deploy → audit
├── bicep/
│   ├── main.bicep              # Root template: VNet, NSGs, Storage, Key Vault, Log Analytics
│   ├── modules/
│   │   └── linux-vm.bicep      # Modular VM: Ubuntu 22.04, Trusted Launch, OMS agent
│   └── parameters.dev.json     # Dev environment parameters
├── scripts/
│   ├── azure_audit.py          # Security compliance auditor (Python + Azure SDK)
│   └── requirements.txt
└── README.md
```

---

## 🧠 Key Concepts Demonstrated

**Infrastructure as Code (Bicep)**
- Modular template structure with parameter files per environment
- Conditional resource deployment (`deployVM` flag)
- `uniqueString()` for globally unique resource names
- Environment-aware configuration (GRS vs LRS, purge protection, soft-delete days)
- `targetScope`, `@secure()` decorators, `@allowed()` validation

**Networking**
- Hub-spoke-ready VNet with properly segmented subnets
- Tiered NSG rules implementing zero-trust between tiers
- Service Endpoints to keep PaaS traffic off the public internet
- Bastion subnet pre-provisioned for jump-host access

**Security**
- Key Vault with RBAC authorization, soft delete, network ACLs
- Storage with HTTPS-only, no public blob, TLS 1.2, VNet rules
- VM with Trusted Launch (Secure Boot + vTPM), system-managed identity
- NSG audit script that catches dangerous open-port rules before they cause incidents

**Monitoring & Governance**
- Centralized Log Analytics Workspace
- Diagnostic settings routing all resource logs and metrics to workspace
- Tag compliance enforcement across resource groups
- Automated security scanning integrated into CI/CD

---

## 💰 Estimated Cost (Dev Environment, No VM)

| Resource | SKU | Est. Monthly |
|---|---|---|
| VNet + NSGs | Free | $0.00 |
| Storage Account | Standard_LRS | ~$0.02 |
| Key Vault | Standard, <10k ops | ~$0.03 |
| Log Analytics | Pay-per-GB, minimal | ~$0.00 |
| **Total** | | **< $1/month** |

> ⚠️ Adding the VM (`deployVM=true`) adds ~$30–40/month for `Standard_B2s`. Auto-shutdown at 23:00 UTC is configured by default to minimize cost.

---

## 📜 License

MIT — use freely, attribution appreciated.

---

<div align="center">

Built by **C Solo** | AZ-104 Certified Azure Administrator  
[GitHub](https://github.com/ApepC)

</div>
