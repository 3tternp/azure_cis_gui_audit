import json
from pathlib import Path

def load_controls() -> dict:
    p = Path(__file__).resolve().parents[2] / "data" / "cis_controls.json"
    controls = json.loads(p.read_text(encoding="utf-8"))
    return {c["issue_id"]: c for c in controls}
