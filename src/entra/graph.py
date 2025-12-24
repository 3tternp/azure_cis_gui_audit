from __future__ import annotations
import requests
from typing import Any, Dict, Optional

import msal

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

class GraphClient:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.app = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
        )

    def _get_token(self) -> str:
        result = self.app.acquire_token_silent(scopes=["https://graph.microsoft.com/.default"], account=None)
        if not result:
            result = self.app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if "access_token" not in result:
            raise RuntimeError(f"Failed to obtain Graph token: {result.get('error')} - {result.get('error_description')}")
        return result["access_token"]

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        token = self._get_token()
        url = f"{GRAPH_BASE}{path}"
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params=params, timeout=60)
        r.raise_for_status()
        return r.json()
