"""Helpers to locate, install and put the Azure CLI ('az') on PATH. Standard library only."""
from __future__ import annotations
import os
import shutil
import subprocess
from typing import List, Optional, Tuple

WINGET_ID = "Microsoft.AzureCLI"
INSTALL_URL = "https://aka.ms/installazurecli"


def candidate_dirs() -> List[str]:
    """Standard Windows install folders that contain az.cmd."""
    dirs = []
    for var in ("ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(var)
        if base:
            dirs.append(os.path.join(base, "Microsoft SDKs", "Azure", "CLI2", "wbin"))
    return dirs


def find_az_dir() -> Optional[str]:
    """Folder containing 'az', whether or not it is on PATH. None if not installed."""
    found = shutil.which("az")
    if found:
        return os.path.dirname(found)
    for d in candidate_dirs():
        if os.path.isfile(os.path.join(d, "az.cmd")):
            return d
    return None


def is_on_path() -> bool:
    return shutil.which("az") is not None


def _norm(p: str) -> str:
    return os.path.normcase(os.path.normpath(os.path.expandvars(p.strip()))).rstrip("\\/")


def merge_path(existing: str, new_dir: str) -> Optional[str]:
    """Return PATH text with new_dir appended, or None if it is already present."""
    parts = [p for p in (existing or "").split(os.pathsep) if p.strip()]
    if any(_norm(p) == _norm(new_dir) for p in parts):
        return None
    return os.pathsep.join(parts + [new_dir])


def add_to_process_path(d: str) -> None:
    new = merge_path(os.environ.get("PATH", ""), d)
    if new:
        os.environ["PATH"] = new


def ensure_az_on_process_path() -> bool:
    """Make 'az' findable by this process (e.g. a terminal opened before the CLI was installed)."""
    if is_on_path():
        return True
    d = find_az_dir()
    if d:
        add_to_process_path(d)
        return True
    return False


def add_to_user_path(d: str) -> bool:
    """Persist d in the *user* PATH (HKCU, no admin needed). Windows only.
    Returns True if it was added, False if it was already there."""
    import winreg  # Windows only
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE)
    try:
        try:
            current, kind = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            current, kind = "", winreg.REG_EXPAND_SZ
        new = merge_path(current, d)
        if new is None:
            return False
        if kind not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
            kind = winreg.REG_EXPAND_SZ
        winreg.SetValueEx(key, "Path", 0, kind, new)
    finally:
        winreg.CloseKey(key)
    try:  # tell running programs (Explorer, new terminals) that the environment changed
        import ctypes
        ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, "Environment", 0x0002, 5000, None)
    except Exception:
        pass
    return True


def install_with_winget() -> Tuple[bool, str]:
    """Install the Azure CLI via winget. Success is judged by whether az can be found afterwards,
    because winget returns non-zero codes for cases such as 'already installed'."""
    if not shutil.which("winget"):
        return False, "winget was not found. Install the Azure CLI from " + INSTALL_URL
    try:
        p = subprocess.run(
            ["winget", "install", "-e", "--id", WINGET_ID, "--silent",
             "--accept-package-agreements", "--accept-source-agreements"],
            capture_output=True, text=True)
        log = (p.stdout + "\n" + p.stderr).strip()
    except Exception as e:
        return False, str(e)
    return find_az_dir() is not None, log
