from __future__ import annotations
from typing import Optional, Dict, Any

from azure.identity import ClientSecretCredential, DefaultAzureCredential

def build_credential(auth_mode: str, tenant_id: str, client_id: str, client_secret: str):
    """Create an Azure credential.

    auth_mode:
      - 'service_principal' (Tenant/Client/Secret)
      - 'default' (DefaultAzureCredential; supports Azure CLI, managed identity, etc.)
    """
    if auth_mode == "default":
        return DefaultAzureCredential(exclude_interactive_browser_credential=True)
    return ClientSecretCredential(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)

def token_for_scope(credential, scope: str) -> str:
    """Return an access token string for a resource scope (e.g. 'https://management.azure.com/.default')."""
    return credential.get_token(scope).token
