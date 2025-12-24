# Azure CIS Configuration Review – Python GUI (PDF report)

This tool performs a **read-only configuration review** of an Azure tenant/subscription set and generates a **PDF report** aligned to CIS-style checks.

## What this tool does
- Authenticates using a **Microsoft Entra application (service principal)**: Tenant ID, Client ID, Client Secret
- Lists subscriptions in the tenant and runs a curated set of CIS-aligned checks across:
  - Entra ID / Conditional Access (via Microsoft Graph)
  - Defender for Cloud configuration (via Azure Security Center APIs)
  - Subscription diagnostic settings and Log Analytics retention
  - Storage account secure settings (TLS, secure transfer, public access)
  - Key Vault protections (soft-delete, purge protection, public access)
  - Network Security Group exposure (RDP/SSH from Internet)
  - App Service minimum TLS / HTTPS only / FTPS only
  - SQL Server auditing / public network access

The codebase is structured so you can easily add checks to cover more CIS controls.

## Permissions required
Use least-privilege wherever possible:
- Azure RBAC (per subscription): **Reader** + (recommended) **Security Reader**
- If you want to read Defender for Cloud pricing/security contacts: **Security Reader** is typically required.
- Microsoft Graph: `Policy.Read.All` (for Conditional Access policies) and `Directory.Read.All` may be required depending on tenant settings.

## Install
```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

## Run
```bash
python main.py
```

## Notes
- This tool is **non-intrusive**: it performs API reads only (no exploitation).
- CIS benchmarks are periodically updated; treat the included control mapping as a starter pack.
- If a control cannot be evaluated due to permissions, the tool will mark it **UNKNOWN** and capture the reason as evidence.

## References (benchmarks & APIs)
- CIS Microsoft Azure Benchmarks (download page): https://www.cisecurity.org/benchmark/azure
- Azure SDK authentication guidance: https://learn.microsoft.com/en-us/azure/developer/python/sdk/authentication/overview
- Microsoft Graph Conditional Access policies: https://learn.microsoft.com/en-us/graph/api/conditionalaccesspolicy-get?view=graph-rest-1.0
