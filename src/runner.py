from __future__ import annotations
from typing import Any, Dict, List, Optional

from azure.mgmt.resource import SubscriptionClient

from .azure.clients import build_credential
from .entra.graph import GraphClient
from .checks.entra_checks import ConditionalAccessEnabledCheck, BlockLegacyAuthPolicyCheck
from .checks.azure_checks import (
    SubscriptionDiagnosticSettingsCheck, LogAnalyticsRetentionCheck,
    DefenderPlansStandardCheck, SecurityContactConfiguredCheck,
    StoragePublicAccessCheck, StorageSecureTransferCheck, StorageMinTLSCheck,
    KeyVaultSoftDeleteCheck, KeyVaultPurgeProtectionCheck,
    NSGRDPExposureCheck, NSGSSHExposureCheck,
    AppServiceHttpsOnlyCheck, AppServiceMinTLSCheck, AppServiceFTPSOnlyCheck,
    SqlAuditingEnabledCheck, SqlPublicNetworkAccessCheck
)

ENTRA_CHECKS = [
    ConditionalAccessEnabledCheck(),
    BlockLegacyAuthPolicyCheck(),
]

SUBSCRIPTION_CHECKS = [
    SubscriptionDiagnosticSettingsCheck(),
    LogAnalyticsRetentionCheck(),
    DefenderPlansStandardCheck(),
    SecurityContactConfiguredCheck(),
    StoragePublicAccessCheck(),
    StorageSecureTransferCheck(),
    StorageMinTLSCheck(),
    KeyVaultSoftDeleteCheck(),
    KeyVaultPurgeProtectionCheck(),
    NSGRDPExposureCheck(),
    NSGSSHExposureCheck(),
    AppServiceHttpsOnlyCheck(),
    AppServiceMinTLSCheck(),
    AppServiceFTPSOnlyCheck(),
    SqlAuditingEnabledCheck(),
    SqlPublicNetworkAccessCheck(),
]

def list_subscriptions(credential) -> List[Dict[str, str]]:
    sc = SubscriptionClient(credential)
    subs = []
    for s in sc.subscriptions.list():
        subs.append({"subscription_id": s.subscription_id, "display_name": s.display_name})
    return subs

def run_audit(
    *,
    auth_mode: str,
    tenant_id: str,
    client_id: str,
    client_secret: str,
    subscription_ids: List[str],
    min_log_retention_days: int = 90,
    run_entra_checks: bool = True,
    run_subscription_checks: bool = True,
):
    credential = build_credential(auth_mode, tenant_id, client_id, client_secret)
    findings = []

    graph = None
    if run_entra_checks and auth_mode == "service_principal":
        # MSAL client uses client secret mode; for 'default' auth, Graph auth is not handled here.
        graph = GraphClient(tenant_id, client_id, client_secret)

    # Tenant checks
    if run_entra_checks:
        ctx = {"graph": graph}
        for chk in ENTRA_CHECKS:
            findings.extend(chk.run(ctx))

    # Subscription checks
    if run_subscription_checks:
        # map id->name for nicer scope
        subs = []
        try:
            subs = list_subscriptions(credential)
        except Exception:
            subs = []
        id_to_name = {s["subscription_id"]: s["display_name"] for s in subs}

        for sub_id in subscription_ids:
            sub_ctx = {
                "credential": credential,
                "subscription_id": sub_id,
                "subscription_name": id_to_name.get(sub_id, ""),
                "min_log_retention_days": min_log_retention_days,
            }
            for chk in SUBSCRIPTION_CHECKS:
                findings.extend(chk.run(sub_ctx))

    return findings
