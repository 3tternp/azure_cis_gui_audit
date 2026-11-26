from __future__ import annotations
from typing import Optional, Dict, Any

from azure.identity import ClientSecretCredential, DefaultAzureCredential

class _TenantScopedCredential:
    """Wraps a credential so every token request targets a chosen tenant (e.g. the Azure CLI's non-default tenant)."""
    def __init__(self, inner, tenant_id: str):
        self._inner = inner
        self._tenant_id = tenant_id

    def get_token(self, *scopes, **kwargs):
        if self._tenant_id and not kwargs.get("tenant_id"):
            kwargs["tenant_id"] = self._tenant_id
        return self._inner.get_token(*scopes, **kwargs)

    def close(self):
        close = getattr(self._inner, "close", None)
        if close:
            close()

def build_credential(auth_mode: str, tenant_id: str, client_id: str, client_secret: str):
    """Create an Azure credential.

    auth_mode:
      - 'service_principal' (Tenant/Client/Secret)
      - 'default' (DefaultAzureCredential; supports Azure CLI, managed identity, etc.)
    """
    if auth_mode == "default":
        cred = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        return _TenantScopedCredential(cred, tenant_id) if tenant_id else cred
    return ClientSecretCredential(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)

def token_for_scope(credential, scope: str) -> str:
    """Return an access token string for a resource scope (e.g. 'https://management.azure.com/.default')."""
    return credential.get_token(scope).token

ARM_SCOPE = "https://management.azure.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

def _jwt_claims(token: str) -> Dict[str, Any]:
    """Decode (without verifying) the payload of a JWT to show who the token is for."""
    import base64, json
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}

def _short_error(e: Exception) -> str:
    msg = " ".join(str(e).split())
    if "DefaultAzureCredential failed to retrieve a token" in msg:
        if "Azure CLI not found on path" in msg:
            return ("Azure CLI ('az') was not found. Install it (winget install -e --id Microsoft.AzureCLI), "
                    "open a NEW terminal, run 'az login', then start this app from that terminal.")
        return "No signed-in identity found. Run 'az login' (Azure CLI), or use a managed identity / service principal."
    return (msg[:300] + "...") if len(msg) > 300 else (msg or type(e).__name__)

def test_connection(auth_mode: str, tenant_id: str, client_id: str, client_secret: str, subscription_ids=None) -> Dict[str, Any]:
    """Check that the credential can get Azure (ARM) and Graph tokens and list subscriptions.

    Returns a dict with: identity, tenant, arm_ok, graph_ok, subscriptions (count or None),
    and an 'errors' dict keyed by step. Never raises.
    """
    from azure.mgmt.resource import SubscriptionClient
    result: Dict[str, Any] = {"identity": "", "tenant": "", "arm_ok": False, "graph_ok": False,
                              "subscriptions": None, "checked_subscriptions": {}, "errors": {}}
    try:
        cred = build_credential(auth_mode, tenant_id, client_id, client_secret)
    except Exception as e:
        result["errors"]["credential"] = f"{type(e).__name__}: {e}"
        return result

    try:
        tok = cred.get_token(ARM_SCOPE).token
        claims = _jwt_claims(tok)
        result["arm_ok"] = True
        result["tenant"] = claims.get("tid", "")
        result["identity"] = (claims.get("upn") or claims.get("unique_name") or claims.get("appid")
                              or claims.get("oid") or "")
    except Exception as e:
        result["errors"]["arm"] = _short_error(e)

    try:
        cred.get_token(GRAPH_SCOPE)
        result["graph_ok"] = True
    except Exception as e:
        result["errors"]["graph"] = _short_error(e)

    if result["arm_ok"]:
        try:
            result["subscriptions"] = len(list(SubscriptionClient(cred).subscriptions.list()))
        except Exception as e:
            result["errors"]["subscriptions"] = _short_error(e)
    if result["arm_ok"] and subscription_ids:
        sc = SubscriptionClient(cred)
        for sid in subscription_ids:
            try:
                sub = sc.subscriptions.get(sid)
                result["checked_subscriptions"][sid] = f"{sub.display_name} ({sub.state})"
            except Exception as e:
                result["checked_subscriptions"][sid] = "ERROR: " + _short_error(e)
    return result
