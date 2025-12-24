from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_UNKNOWN = "UNKNOWN"

@dataclass
class Finding:
    issue_id: str
    issue_name: str
    cis_ref: str
    status: str
    scope: str  # Tenant / Subscription / Resource
    affected: str = ""  # resource name/id(s)
    evidence: str = ""
    remediation: str = ""
    fix_type: str = ""  # QUICK / INVOLVED / PLANNED
    test_notes: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

class Check:
    """Base class for a CIS-aligned check."""
    issue_id: str = ""
    def run(self, ctx: Dict[str, Any]) -> List[Finding]:
        raise NotImplementedError
