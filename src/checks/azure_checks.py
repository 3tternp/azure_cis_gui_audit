from __future__ import annotations
from typing import Any, Dict, List, Tuple
from datetime import datetime

from .base import Check, Finding, STATUS_FAIL, STATUS_PASS, STATUS_UNKNOWN
from ..utils.controls import load_controls
from ..utils.logging_utils import exc_to_text

from azure.mgmt.security import SecurityCenter
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.sql import SqlManagementClient

# ---------- Helper ----------
def _sub_scope(ctx: Dict[str, Any]) -> str:
    sub = ctx.get("subscription_id", "")
    name = ctx.get("subscription_name", "")
    return f"Subscription: {name} ({sub})"

# ---------- Checks ----------
class SubscriptionDiagnosticSettingsCheck(Check):
    issue_id = "AZ-CIS-010"
    def run(self, ctx: Dict[str, Any]) -> List[Finding]:
        c = load_controls()[self.issue_id]
        credential = ctx["credential"]
        sub_id = ctx["subscription_id"]
        try:
            monitor = MonitorManagementClient(credential, sub_id)
            # subscription resource ID:
            resource_id = f"/subscriptions/{sub_id}"
            ds = list(monitor.diagnostic_settings.list(resource_id))
            if not ds:
                return [Finding(**c, status=STATUS_FAIL, scope=_sub_scope(ctx),
                                evidence="No diagnostic settings were found at subscription scope for Activity Logs.")]
            # at least one destination configured
            ok = []
            for d in ds:
                if getattr(d, "workspace_id", None) or getattr(d, "storage_account_id", None) or getattr(d, "event_hub_authorization_rule_id", None):
                    ok.append(d.name)
            if not ok:
                return [Finding(**c, status=STATUS_FAIL, scope=_sub_scope(ctx),
                                evidence=f"Diagnostic settings exist ({len(ds)}) but no destination (Log Analytics/Storage/Event Hub) was detected.")]
            return [Finding(**c, status=STATUS_PASS, scope=_sub_scope(ctx),
                            evidence=f"Subscription diagnostic settings configured: {', '.join(ok[:10])}")]
        except Exception as e:
            return [Finding(**c, status=STATUS_UNKNOWN, scope=_sub_scope(ctx), evidence=exc_to_text(e))]

class LogAnalyticsRetentionCheck(Check):
    issue_id = "AZ-CIS-011"
    def run(self, ctx: Dict[str, Any]) -> List[Finding]:
        c = load_controls()[self.issue_id]
        credential = ctx["credential"]
        sub_id = ctx["subscription_id"]
        min_days = int(ctx.get("min_log_retention_days", 90))
        try:
            la = LogAnalyticsManagementClient(credential, sub_id)
            fails = []
            passes = []
            for ws in la.workspaces.list():
                retention = getattr(ws, "retention_in_days", None)
                rid = getattr(ws, "id", "")
                name = getattr(ws, "name", "")
                if retention is None:
                    fails.append(f"{name}: retention_in_days not returned")
                elif retention < min_days:
                    fails.append(f"{name}: {retention} days (<{min_days})")
                else:
                    passes.append(f"{name}: {retention} days")
            if not passes and not fails:
                return [Finding(**c, status=STATUS_UNKNOWN, scope=_sub_scope(ctx), evidence="No Log Analytics workspaces found in this subscription.")]
            if fails:
                return [Finding(**c, status=STATUS_FAIL, scope=_sub_scope(ctx), affected="; ".join([x.split(':')[0] for x in fails][:20]),
                                evidence="Non-compliant workspaces: " + "; ".join(fails[:30]))]
            return [Finding(**c, status=STATUS_PASS, scope=_sub_scope(ctx), evidence="Workspaces meet retention: " + "; ".join(passes[:30]))]
        except Exception as e:
            return [Finding(**c, status=STATUS_UNKNOWN, scope=_sub_scope(ctx), evidence=exc_to_text(e))]

class DefenderPlansStandardCheck(Check):
    issue_id = "AZ-CIS-020"
    def run(self, ctx: Dict[str, Any]) -> List[Finding]:
        c = load_controls()[self.issue_id]
        credential = ctx["credential"]
        sub_id = ctx["subscription_id"]
        try:
            sec = SecurityCenter(credential, sub_id)
            pricings = list(sec.pricings.list())
            # tier is typically 'Free' or 'Standard'
            non_std = []
            std = []
            for p in pricings:
                tier = getattr(p.pricing_tier, "value", None) if hasattr(p, "pricing_tier") else getattr(p, "pricing_tier", None)
                name = getattr(p, "name", "")
                if str(tier).lower() != "standard":
                    non_std.append(f"{name}:{tier}")
                else:
                    std.append(f"{name}:{tier}")
            if non_std:
                return [Finding(**c, status=STATUS_FAIL, scope=_sub_scope(ctx),
                                evidence="Non-Standard Defender pricing tiers detected: " + ", ".join(non_std[:50]))]
            if not std and not non_std:
                return [Finding(**c, status=STATUS_UNKNOWN, scope=_sub_scope(ctx), evidence="No Defender for Cloud pricing information returned.")]
            return [Finding(**c, status=STATUS_PASS, scope=_sub_scope(ctx), evidence="All Defender plans returned as Standard.")]
        except Exception as e:
            return [Finding(**c, status=STATUS_UNKNOWN, scope=_sub_scope(ctx), evidence=exc_to_text(e))]

class SecurityContactConfiguredCheck(Check):
    issue_id = "AZ-CIS-021"
    def run(self, ctx: Dict[str, Any]) -> List[Finding]:
        c = load_controls()[self.issue_id]
        credential = ctx["credential"]
        sub_id = ctx["subscription_id"]
        try:
            sec = SecurityCenter(credential, sub_id)
            contacts = list(sec.security_contacts.list())
            if not contacts:
                return [Finding(**c, status=STATUS_FAIL, scope=_sub_scope(ctx), evidence="No Security Contact was returned by Defender for Cloud APIs.")]
            # at least one contact with email
            ok = []
            for sc in contacts:
                email = getattr(sc, "email", None)
                name = getattr(sc, "name", "")
                if email:
                    ok.append(f"{name}:{email}")
            if not ok:
                return [Finding(**c, status=STATUS_FAIL, scope=_sub_scope(ctx), evidence=f"Security contacts exist ({len(contacts)}) but no email address was returned.")]
            return [Finding(**c, status=STATUS_PASS, scope=_sub_scope(ctx), evidence="Security contact(s): " + ", ".join(ok[:10]))]
        except Exception as e:
            return [Finding(**c, status=STATUS_UNKNOWN, scope=_sub_scope(ctx), evidence=exc_to_text(e))]

class StoragePublicAccessCheck(Check):
    issue_id = "AZ-CIS-030"
    def run(self, ctx: Dict[str, Any]) -> List[Finding]:
        c = load_controls()[self.issue_id]
        credential = ctx["credential"]
        sub_id = ctx["subscription_id"]
        try:
            st = StorageManagementClient(credential, sub_id)
            non = []
            for acct in st.storage_accounts.list():
                props = st.storage_accounts.get_properties(acct.id.split("/resourceGroups/")[1].split("/")[0], acct.name)
                allow_public = getattr(props, "allow_blob_public_access", None)
                if allow_public is True:
                    non.append(acct.name)
            if non:
                return [Finding(**c, status=STATUS_FAIL, scope=_sub_scope(ctx), affected=", ".join(non[:30]),
                                evidence=f"Storage accounts allowing public blob access: {', '.join(non[:50])}")]
            return [Finding(**c, status=STATUS_PASS, scope=_sub_scope(ctx), evidence="No storage accounts were found with 'allowBlobPublicAccess' enabled.")]
        except Exception as e:
            return [Finding(**c, status=STATUS_UNKNOWN, scope=_sub_scope(ctx), evidence=exc_to_text(e))]

class StorageSecureTransferCheck(Check):
    issue_id = "AZ-CIS-031"
    def run(self, ctx: Dict[str, Any]) -> List[Finding]:
        c = load_controls()[self.issue_id]
        credential = ctx["credential"]
        sub_id = ctx["subscription_id"]
        try:
            st = StorageManagementClient(credential, sub_id)
            non = []
            for acct in st.storage_accounts.list():
                rg = acct.id.split("/resourceGroups/")[1].split("/")[0]
                props = st.storage_accounts.get_properties(rg, acct.name)
                secure = getattr(props, "enable_https_traffic_only", None)
                if secure is False:
                    non.append(acct.name)
            if non:
                return [Finding(**c, status=STATUS_FAIL, scope=_sub_scope(ctx), affected=", ".join(non[:30]),
                                evidence=f"Storage accounts not enforcing HTTPS-only: {', '.join(non[:50])}")]
            return [Finding(**c, status=STATUS_PASS, scope=_sub_scope(ctx), evidence="All storage accounts returned 'enableHttpsTrafficOnly'=True (or not returned as False).")]
        except Exception as e:
            return [Finding(**c, status=STATUS_UNKNOWN, scope=_sub_scope(ctx), evidence=exc_to_text(e))]

class StorageMinTLSCheck(Check):
    issue_id = "AZ-CIS-032"
    def run(self, ctx: Dict[str, Any]) -> List[Finding]:
        c = load_controls()[self.issue_id]
        credential = ctx["credential"]
        sub_id = ctx["subscription_id"]
        try:
            st = StorageManagementClient(credential, sub_id)
            non = []
            for acct in st.storage_accounts.list():
                rg = acct.id.split("/resourceGroups/")[1].split("/")[0]
                props = st.storage_accounts.get_properties(rg, acct.name)
                tls = getattr(props, "minimum_tls_version", None)
                if tls and str(tls).lower() not in ["tls1_2", "tls1_3"]:
                    non.append(f"{acct.name}:{tls}")
                elif tls is None:
                    # treat as unknown rather than fail (API/older accounts may not return it)
                    pass
            if non:
                return [Finding(**c, status=STATUS_FAIL, scope=_sub_scope(ctx),
                                evidence="Storage accounts with minimum TLS below 1.2: " + ", ".join(non[:50]))]
            return [Finding(**c, status=STATUS_PASS, scope=_sub_scope(ctx), evidence="No storage accounts returned a minimum TLS version below 1.2.")]
        except Exception as e:
            return [Finding(**c, status=STATUS_UNKNOWN, scope=_sub_scope(ctx), evidence=exc_to_text(e))]

class KeyVaultSoftDeleteCheck(Check):
    issue_id = "AZ-CIS-040"
    def run(self, ctx: Dict[str, Any]) -> List[Finding]:
        c = load_controls()[self.issue_id]
        credential = ctx["credential"]
        sub_id = ctx["subscription_id"]
        try:
            kv = KeyVaultManagementClient(credential, sub_id)
            non = []
            for vault in kv.vaults.list():
                props = vault.properties
                sd = getattr(props, "enable_soft_delete", None)
                if sd is False:
                    non.append(vault.name)
            if non:
                return [Finding(**c, status=STATUS_FAIL, scope=_sub_scope(ctx), affected=", ".join(non[:30]),
                                evidence=f"Key Vaults without soft delete enabled: {', '.join(non[:50])}")]
            return [Finding(**c, status=STATUS_PASS, scope=_sub_scope(ctx), evidence="No Key Vaults were found with soft delete explicitly disabled.")]
        except Exception as e:
            return [Finding(**c, status=STATUS_UNKNOWN, scope=_sub_scope(ctx), evidence=exc_to_text(e))]

class KeyVaultPurgeProtectionCheck(Check):
    issue_id = "AZ-CIS-041"
    def run(self, ctx: Dict[str, Any]) -> List[Finding]:
        c = load_controls()[self.issue_id]
        credential = ctx["credential"]
        sub_id = ctx["subscription_id"]
        try:
            kv = KeyVaultManagementClient(credential, sub_id)
            non = []
            for vault in kv.vaults.list():
                props = vault.properties
                pp = getattr(props, "enable_purge_protection", None)
                if pp is False:
                    non.append(vault.name)
            if non:
                return [Finding(**c, status=STATUS_FAIL, scope=_sub_scope(ctx), affected=", ".join(non[:30]),
                                evidence=f"Key Vaults without purge protection enabled: {', '.join(non[:50])}")]
            return [Finding(**c, status=STATUS_PASS, scope=_sub_scope(ctx), evidence="No Key Vaults were found with purge protection explicitly disabled.")]
        except Exception as e:
            return [Finding(**c, status=STATUS_UNKNOWN, scope=_sub_scope(ctx), evidence=exc_to_text(e))]

class NSGRDPExposureCheck(Check):
    issue_id = "AZ-CIS-050"
    def run(self, ctx: Dict[str, Any]) -> List[Finding]:
        c = load_controls()[self.issue_id]
        credential = ctx["credential"]
        sub_id = ctx["subscription_id"]
        try:
            net = NetworkManagementClient(credential, sub_id)
            exposed = []
            for nsg in net.network_security_groups.list_all():
                rules = list(nsg.security_rules or [])
                for r in rules:
                    if str(getattr(r, "access", "")).lower() != "allow":
                        continue
                    if str(getattr(r, "direction", "")).lower() != "inbound":
                        continue
                    dst_ports = getattr(r, "destination_port_range", None) or ""
                    dst_ranges = getattr(r, "destination_port_ranges", None) or []
                    ports = set([dst_ports] if dst_ports else []) | set(dst_ranges or [])
                    if "3389" not in ports and "*" not in ports:
                        continue
                    src = getattr(r, "source_address_prefix", None) or ""
                    srcs = getattr(r, "source_address_prefixes", None) or []
                    srcset = set([src] if src else []) | set(srcs or [])
                    if any(x in ["*", "0.0.0.0/0", "Internet"] for x in srcset):
                        exposed.append(f"{nsg.name}:{r.name}")
            if exposed:
                return [Finding(**c, status=STATUS_FAIL, scope=_sub_scope(ctx), evidence="RDP exposure rules: " + ", ".join(exposed[:60]))]
            return [Finding(**c, status=STATUS_PASS, scope=_sub_scope(ctx), evidence="No NSG inbound allow rules found that expose RDP (3389) to Internet/* (heuristic).")]
        except Exception as e:
            return [Finding(**c, status=STATUS_UNKNOWN, scope=_sub_scope(ctx), evidence=exc_to_text(e))]

class NSGSSHExposureCheck(Check):
    issue_id = "AZ-CIS-051"
    def run(self, ctx: Dict[str, Any]) -> List[Finding]:
        c = load_controls()[self.issue_id]
        credential = ctx["credential"]
        sub_id = ctx["subscription_id"]
        try:
            net = NetworkManagementClient(credential, sub_id)
            exposed = []
            for nsg in net.network_security_groups.list_all():
                rules = list(nsg.security_rules or [])
                for r in rules:
                    if str(getattr(r, "access", "")).lower() != "allow":
                        continue
                    if str(getattr(r, "direction", "")).lower() != "inbound":
                        continue
                    dst_ports = getattr(r, "destination_port_range", None) or ""
                    dst_ranges = getattr(r, "destination_port_ranges", None) or []
                    ports = set([dst_ports] if dst_ports else []) | set(dst_ranges or [])
                    if "22" not in ports and "*" not in ports:
                        continue
                    src = getattr(r, "source_address_prefix", None) or ""
                    srcs = getattr(r, "source_address_prefixes", None) or []
                    srcset = set([src] if src else []) | set(srcs or [])
                    if any(x in ["*", "0.0.0.0/0", "Internet"] for x in srcset):
                        exposed.append(f"{nsg.name}:{r.name}")
            if exposed:
                return [Finding(**c, status=STATUS_FAIL, scope=_sub_scope(ctx), evidence="SSH exposure rules: " + ", ".join(exposed[:60]))]
            return [Finding(**c, status=STATUS_PASS, scope=_sub_scope(ctx), evidence="No NSG inbound allow rules found that expose SSH (22) to Internet/* (heuristic).")]
        except Exception as e:
            return [Finding(**c, status=STATUS_UNKNOWN, scope=_sub_scope(ctx), evidence=exc_to_text(e))]

class AppServiceHttpsOnlyCheck(Check):
    issue_id = "AZ-CIS-060"
    def run(self, ctx: Dict[str, Any]) -> List[Finding]:
        c = load_controls()[self.issue_id]
        credential = ctx["credential"]
        sub_id = ctx["subscription_id"]
        try:
            web = WebSiteManagementClient(credential, sub_id)
            non = []
            for app in web.web_apps.list():
                https_only = getattr(app, "https_only", None)
                if https_only is False:
                    non.append(app.name)
            if non:
                return [Finding(**c, status=STATUS_FAIL, scope=_sub_scope(ctx), affected=", ".join(non[:30]),
                                evidence="Web apps not enforcing HTTPS-only: " + ", ".join(non[:50]))]
            return [Finding(**c, status=STATUS_PASS, scope=_sub_scope(ctx), evidence="No web apps returned httpsOnly=False.")]
        except Exception as e:
            return [Finding(**c, status=STATUS_UNKNOWN, scope=_sub_scope(ctx), evidence=exc_to_text(e))]

class AppServiceMinTLSCheck(Check):
    issue_id = "AZ-CIS-061"
    def run(self, ctx: Dict[str, Any]) -> List[Finding]:
        c = load_controls()[self.issue_id]
        credential = ctx["credential"]
        sub_id = ctx["subscription_id"]
        try:
            web = WebSiteManagementClient(credential, sub_id)
            non = []
            for app in web.web_apps.list():
                # need site config for min TLS
                rg = app.id.split("/resourceGroups/")[1].split("/")[0]
                cfg = web.web_apps.get_configuration(rg, app.name)
                tls = getattr(cfg, "min_tls_version", None)
                if tls and str(tls).lower() not in ["1.2", "1.3"]:
                    non.append(f"{app.name}:{tls}")
            if non:
                return [Finding(**c, status=STATUS_FAIL, scope=_sub_scope(ctx), evidence="Web apps with min TLS below 1.2: " + ", ".join(non[:50]))]
            return [Finding(**c, status=STATUS_PASS, scope=_sub_scope(ctx), evidence="No web apps returned minTlsVersion below 1.2.")]
        except Exception as e:
            return [Finding(**c, status=STATUS_UNKNOWN, scope=_sub_scope(ctx), evidence=exc_to_text(e))]

class AppServiceFTPSOnlyCheck(Check):
    issue_id = "AZ-CIS-062"
    def run(self, ctx: Dict[str, Any]) -> List[Finding]:
        c = load_controls()[self.issue_id]
        credential = ctx["credential"]
        sub_id = ctx["subscription_id"]
        try:
            web = WebSiteManagementClient(credential, sub_id)
            non = []
            for app in web.web_apps.list():
                rg = app.id.split("/resourceGroups/")[1].split("/")[0]
                cfg = web.web_apps.get_configuration(rg, app.name)
                ftps = getattr(cfg, "ftps_state", None)
                # Allow: FtpsOnly. Others: AllAllowed, Disabled
                if ftps and str(ftps).lower() != "ftpsonly":
                    non.append(f"{app.name}:{ftps}")
            if non:
                return [Finding(**c, status=STATUS_FAIL, scope=_sub_scope(ctx), evidence="Web apps with FTPS state not FtpsOnly: " + ", ".join(non[:50]))]
            return [Finding(**c, status=STATUS_PASS, scope=_sub_scope(ctx), evidence="No web apps returned FTPS state other than FtpsOnly.")]
        except Exception as e:
            return [Finding(**c, status=STATUS_UNKNOWN, scope=_sub_scope(ctx), evidence=exc_to_text(e))]

class SqlAuditingEnabledCheck(Check):
    issue_id = "AZ-CIS-070"
    def run(self, ctx: Dict[str, Any]) -> List[Finding]:
        c = load_controls()[self.issue_id]
        credential = ctx["credential"]
        sub_id = ctx["subscription_id"]
        try:
            sql = SqlManagementClient(credential, sub_id)
            non = []
            # enumerate SQL servers across RGs
            for srv in sql.servers.list():
                rg = srv.id.split("/resourceGroups/")[1].split("/")[0]
                aud = sql.server_auditing_settings.get(rg, srv.name)
                state = getattr(aud, "state", None)
                if not state or str(state).lower() != "enabled":
                    non.append(f"{srv.name}:{state}")
            if non:
                return [Finding(**c, status=STATUS_FAIL, scope=_sub_scope(ctx), evidence="SQL servers without auditing enabled: " + ", ".join(non[:50]))]
            return [Finding(**c, status=STATUS_PASS, scope=_sub_scope(ctx), evidence="All SQL servers returned auditing state 'Enabled'.")]
        except Exception as e:
            return [Finding(**c, status=STATUS_UNKNOWN, scope=_sub_scope(ctx), evidence=exc_to_text(e))]

class SqlPublicNetworkAccessCheck(Check):
    issue_id = "AZ-CIS-071"
    def run(self, ctx: Dict[str, Any]) -> List[Finding]:
        c = load_controls()[self.issue_id]
        credential = ctx["credential"]
        sub_id = ctx["subscription_id"]
        try:
            sql = SqlManagementClient(credential, sub_id)
            non = []
            for srv in sql.servers.list():
                pna = getattr(srv, "public_network_access", None)
                if pna and str(pna).lower() == "enabled":
                    non.append(srv.name)
            if non:
                return [Finding(**c, status=STATUS_FAIL, scope=_sub_scope(ctx), affected=", ".join(non[:30]),
                                evidence="SQL servers with public network access enabled: " + ", ".join(non[:50]))]
            return [Finding(**c, status=STATUS_PASS, scope=_sub_scope(ctx), evidence="No SQL servers returned publicNetworkAccess='Enabled'.")]
        except Exception as e:
            return [Finding(**c, status=STATUS_UNKNOWN, scope=_sub_scope(ctx), evidence=exc_to_text(e))]
