# ☁️🛡️ Azure CIS Configuration Review – Python GUI (PDF report)

A **read-only** 🔍 configuration review of an Azure tenant and its subscriptions, with a **📄 PDF report** aligned to CIS-style checks. It uses a simple Tkinter 🖥️ desktop GUI.

---

## 📑 Table of contents
- [✨ What this tool does](#-what-this-tool-does)
- [🔐 Authentication modes](#-authentication-modes)
- [🪪 Permissions required](#-permissions-required)
- [📦 Install](#-install)
- [🚀 Usage](#-usage)
- [🚦 Result statuses](#-result-statuses)
- [📄 The PDF report](#-the-pdf-report)
- [🧩 Checks included](#-checks-included)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [📝 Notes](#-notes)
- [📚 References](#-references)

---

## ✨ What this tool does
- 🔑 Authenticates with a **Microsoft Entra service principal** (Tenant ID, Client ID, Client Secret) **or** with your existing **Azure CLI / managed identity** login (no secret needed)
- 📋 Lists the subscriptions in the tenant and runs a curated set of CIS-aligned checks across:
  - 👤 Entra ID / Conditional Access (Microsoft Graph)
  - 🛡️ Defender for Cloud configuration (Azure Security Center APIs)
  - 📜 Subscription diagnostic settings and Log Analytics retention
  - 🗄️ Storage account secure settings (TLS, secure transfer, public access)
  - 🔐 Key Vault protections (soft delete, purge protection)
  - 🌐 Network Security Group exposure (RDP/SSH from the Internet)
  - 🕸️ App Service minimum TLS / HTTPS only / FTPS only
  - 🛢️ SQL Server auditing / public network access
- 📄 Produces a PDF report with a summary, findings, evidence and remediation

The code is structured so you can add checks for more CIS controls (`src/checks/`, `data/cis_controls.json`).

---

## 🔐 Authentication modes

| Mode | Needs | When to use |
|---|---|---|
| 🔑 **Service Principal** | Tenant ID, Client ID, Client Secret | Automation, or when you have an app registration |
| 🙋 **DefaultAzureCredential** | Nothing in the form; log in first with `az login` (or run on a host with a managed identity) | Quick audits from your own machine, no secret to handle |

In DefaultAzureCredential mode the Client ID and Client Secret are ignored. You can still enter a **Tenant ID** (to target a specific tenant) and one or more **Subscription IDs** (comma-separated) on the Authentication tab. The same identity is used for Azure Resource Manager and Microsoft Graph.

---

## 🪪 Permissions required
Use least privilege wherever possible:
- ☁️ Azure RBAC (per subscription): **Reader** + (recommended) **Security Reader**
- 🛡️ Reading Defender for Cloud pricing and security contacts typically needs **Security Reader**
- 👤 Microsoft Graph (Conditional Access): `Policy.Read.All`, and `Directory.Read.All` may be required depending on tenant settings. With a signed-in user, a role such as **Security Reader** or **Global Reader** is enough.

Missing permissions are not fatal: the affected controls are reported as ❓ **UNKNOWN** (see below).

---

## 📦 Install
Python 3.9+ with **Tkinter** is required (on Debian/Ubuntu: `sudo apt install python3-tk`).

```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows
pip install -r requirements.txt
```

---

## 🚀 Usage

### 1️⃣ Sign in (DefaultAzureCredential mode only)
```bash
az login --tenant <tenant-id>
az account set --subscription <subscription-id>
```

### 2️⃣ Start the app
```bash
python main.py
```

### 3️⃣ Use the tabs

| Tab | What to do |
|---|---|
| 🔑 **Authentication** | Pick the auth mode. For Service Principal enter Tenant ID, Client ID and Client Secret. |
| 🎯 **Scope** | Click **Load Subscriptions**, then select one or more subscriptions. Optionally set the minimum Log Analytics retention (default 90 days). |
| ▶️ **Run** | Choose whether to run the Entra ID (Graph) checks and/or Subscription checks, set the output PDF path, then click **Run Audit**. |
| 📊 **Results** | See every finding (ID, name, status, scope, fix type). Use **Open PDF Location** to find the report. |

---

## 🚦 Result statuses

Every check returns one of three statuses.

| Status | Meaning | How it occurs |
|---|---|---|
| ✅ **PASS** | The setting meets the control. | The API call succeeded and no non-compliant setting was found. Example: no storage account returned `allowBlobPublicAccess = true`. |
| ❌ **FAIL** | The setting does **not** meet the control. | The API call succeeded and returned a non-compliant value or a missing required setting. Example: a Key Vault has purge protection disabled, an NSG allows RDP from the Internet, or no Conditional Access policy is enabled. The affected resources are listed in the report. |
| ❓ **UNKNOWN** | The tool could not decide. | The check could not be evaluated. Common causes are listed below. The reason is saved as evidence. |

### ❓ Why a check is UNKNOWN
- 🔒 **Permission denied** (HTTP 401/403): the identity lacks Reader, Security Reader or Graph read access.
- 🔌 **Graph client not initialized:** Entra checks were skipped or no Graph token could be obtained.
- 🕳️ **Nothing to evaluate:** for example no Log Analytics workspaces exist in the subscription, or Defender returned no pricing information.
- 🌍 **API or network error:** timeouts, blocked endpoints or an unavailable resource provider.

> 💡 **UNKNOWN is not a pass.** Fix the permission or error shown in the evidence and run the audit again.

### 🧰 Fix type
Each finding also carries a fix effort estimate:

| Fix type | Meaning |
|---|---|
| ⚡ **QUICK** | A simple setting change |
| 🔧 **INVOLVED** | Needs configuration work or coordination |
| 🗓️ **PLANNED** | Needs a planned change (for example policy design and rollout) |

### ⚠️ Heuristics
Some results are heuristic. For example, legacy-authentication blocking is detected from Conditional Access `clientAppTypes` and `builtInControls`, and NSG exposure is detected from inbound allow rules with Internet/`*` sources. Treat these as strong indicators and confirm manually.

---

## 📄 The PDF report
The report includes:
- 📊 Totals of ✅ PASS / ❌ FAIL / ❓ UNKNOWN
- 📋 A findings table (ID, name, CIS reference, status, scope)
- 🔎 Evidence for each finding, including affected resources
- 🛠️ Remediation guidance and fix type

---

## 🧩 Checks included

| ID | Area | Check |
|---|---|---|
| AZ-CIS-001 | 👤 Entra | Enabled Conditional Access policies exist |
| AZ-CIS-002 | 👤 Entra | A policy blocking legacy authentication exists |
| AZ-CIS-010 | 📜 Logging | Subscription diagnostic settings for Activity Logs |
| AZ-CIS-011 | 📜 Logging | Log Analytics retention meets the minimum |
| AZ-CIS-020 | 🛡️ Defender | Defender plans set to Standard |
| AZ-CIS-021 | 🛡️ Defender | Security contact configured |
| AZ-CIS-030 | 🗄️ Storage | No public blob access |
| AZ-CIS-031 | 🗄️ Storage | Secure transfer (HTTPS) enforced |
| AZ-CIS-032 | 🗄️ Storage | Minimum TLS 1.2 |
| AZ-CIS-040 | 🔐 Key Vault | Soft delete enabled |
| AZ-CIS-041 | 🔐 Key Vault | Purge protection enabled |
| AZ-CIS-050 | 🌐 Network | No RDP (3389) from the Internet |
| AZ-CIS-051 | 🌐 Network | No SSH (22) from the Internet |
| AZ-CIS-060 | 🕸️ App Service | HTTPS only |
| AZ-CIS-061 | 🕸️ App Service | Minimum TLS 1.2 |
| AZ-CIS-062 | 🕸️ App Service | FTPS only |
| AZ-CIS-070 | 🛢️ SQL | Auditing enabled |
| AZ-CIS-071 | 🛢️ SQL | Public network access disabled |

---

## 🛠️ Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'tkinter'` | Install Tkinter (`sudo apt install python3-tk`) and use that Python. |
| `ImportError: cannot import name 'SubscriptionClient'` | Use `azure-mgmt-resource<25` (already pinned in `requirements.txt`). |
| No subscriptions listed in default mode | Run `az login --tenant <tenant-id>` first and confirm with `az account show`. |
| Entra checks are UNKNOWN with a 403 | Grant Graph read access (`Policy.Read.All`, or a Security Reader / Global Reader role). |
| Many subscription checks are UNKNOWN | Assign **Reader** and **Security Reader** on the subscription. |

---

## 📝 Notes
- 🔒 This tool is **non-intrusive**: it performs API reads only (no exploitation, no changes).
- 🔄 CIS benchmarks are updated periodically; treat the included control mapping as a starter pack.
- 🙈 Never commit or share your client secret.

---

## 📚 References
- 📘 CIS Microsoft Azure Benchmarks: https://www.cisecurity.org/benchmark/azure
- 🔑 Azure SDK authentication guidance: https://learn.microsoft.com/en-us/azure/developer/python/sdk/authentication/overview
- 👤 Microsoft Graph Conditional Access policies: https://learn.microsoft.com/en-us/graph/api/conditionalaccesspolicy-get?view=graph-rest-1.0
