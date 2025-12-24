from __future__ import annotations
from typing import Any, Dict, List

from .base import Check, Finding, STATUS_FAIL, STATUS_PASS, STATUS_UNKNOWN
from ..utils.controls import load_controls
from ..utils.logging_utils import exc_to_text

class ConditionalAccessEnabledCheck(Check):
    issue_id = "AZ-CIS-001"
    def run(self, ctx: Dict[str, Any]) -> List[Finding]:
        controls = load_controls()[self.issue_id]
        graph = ctx.get("graph")
        if not graph:
            return [Finding(**controls, status=STATUS_UNKNOWN, scope="Tenant", evidence="Graph client not initialized")]
        try:
            data = graph.get("/identity/conditionalAccess/policies", params={"$top": 999})
            policies = data.get("value", [])
            enabled = [p for p in policies if p.get("state") == "enabled"]
            if len(enabled) == 0:
                return [Finding(**controls, status=STATUS_FAIL, scope="Tenant", evidence="No Conditional Access policies in 'enabled' state were returned by Microsoft Graph.")]
            return [Finding(**controls, status=STATUS_PASS, scope="Tenant", evidence=f"Enabled Conditional Access policies: {len(enabled)}")]
        except Exception as e:
            return [Finding(**controls, status=STATUS_UNKNOWN, scope="Tenant", evidence=exc_to_text(e))]

class BlockLegacyAuthPolicyCheck(Check):
    issue_id = "AZ-CIS-002"
    def run(self, ctx: Dict[str, Any]) -> List[Finding]:
        controls = load_controls()[self.issue_id]
        graph = ctx.get("graph")
        if not graph:
            return [Finding(**controls, status=STATUS_UNKNOWN, scope="Tenant", evidence="Graph client not initialized")]
        try:
            data = graph.get("/identity/conditionalAccess/policies", params={"$top": 999})
            policies = data.get("value", [])
            enabled = [p for p in policies if p.get("state") == "enabled"]
            # Heuristic: legacy auth blocks typically include clientAppTypes like 'exchangeActiveSync' and 'other'
            # and grantControls with builtInControls 'block'.
            def looks_like_legacy_block(p: dict) -> bool:
                conditions = p.get("conditions", {})
                client_types = set(conditions.get("clientAppTypes") or [])
                grant = p.get("grantControls", {})
                built_in = set(grant.get("builtInControls") or [])
                return ("block" in built_in) and (("exchangeActiveSync" in client_types) or ("other" in client_types))
            legacy_block = [p for p in enabled if looks_like_legacy_block(p)]
            if len(legacy_block) == 0:
                return [Finding(**controls, status=STATUS_FAIL, scope="Tenant",
                               evidence="No enabled Conditional Access policy was detected that appears to 'block' legacy authentication (heuristic based on clientAppTypes and builtInControls).")]
            names = ", ".join([p.get("displayName","(no name)") for p in legacy_block][:10])
            return [Finding(**controls, status=STATUS_PASS, scope="Tenant", evidence=f"Detected enabled legacy-auth block policy/policies (heuristic): {names}")]
        except Exception as e:
            return [Finding(**controls, status=STATUS_UNKNOWN, scope="Tenant", evidence=exc_to_text(e))]
