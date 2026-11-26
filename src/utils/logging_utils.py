from __future__ import annotations

_PERMISSION_MARKERS = ("403", "401", "authorizationfailed", "authorization_failed", "forbidden", "unauthorized", "insufficient privileges", "does not have authorization")

def exc_to_text(e: Exception) -> str:
    """Short, human-readable reason for a failed check (no traceback)."""
    msg = " ".join(str(e).split())
    if len(msg) > 300:
        msg = msg[:300] + "..."
    text = f"{type(e).__name__}: {msg}" if msg else type(e).__name__
    if any(m in text.lower() for m in _PERMISSION_MARKERS):
        text = "Permission denied - grant Reader / Security Reader (Azure) or Graph read access. Details: " + text
    return text
