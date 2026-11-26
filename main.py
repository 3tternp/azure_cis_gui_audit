from __future__ import annotations
import os
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox

import logging
import shutil

# azure-identity logs a long multi-line warning for every failed token request; the app
# reports sign-in problems itself in a short form, so keep the console quiet.
logging.getLogger("azure.identity").setLevel(logging.CRITICAL)


def _ensure_az_on_path():
    """A terminal opened before the Azure CLI was installed has a stale PATH; fix it for this run."""
    try:
        from src.utils.azcli import ensure_az_on_process_path
        ensure_az_on_process_path()
    except Exception:
        pass


_ensure_az_on_path()

HERE = os.path.dirname(os.path.abspath(__file__))
REQUIREMENTS = os.path.join(HERE, "requirements.txt")
# Set after one install attempt so a failed install can never cause a restart loop.
TRIED_ENV = "AZURE_CIS_AUTOINSTALL_TRIED"
# Set to 1 to install without asking (useful for scripts / headless runs).
AUTO_ENV = "AZURE_CIS_AUTO_INSTALL"


def _install_requirements() -> tuple[bool, str]:
    """pip install -r requirements.txt into the Python running this app, with a small progress window."""
    root = tk.Tk()
    root.title("Installing dependencies")
    root.geometry("460x120")
    root.resizable(False, False)
    ttk.Label(root, text="Installing required packages...\nThis can take a minute. Please wait.",
              justify="center").pack(pady=(18, 8))
    bar = ttk.Progressbar(root, mode="indeterminate", length=380)
    bar.pack()
    bar.start(12)
    out: dict = {}

    def work():
        try:
            p = subprocess.run([sys.executable, "-m", "pip", "install", "-r", REQUIREMENTS],
                               capture_output=True, text=True)
            out["ok"], out["log"] = p.returncode == 0, (p.stdout + "\n" + p.stderr).strip()
        except Exception as e:  # pip missing, no permission, etc.
            out["ok"], out["log"] = False, str(e)
        root.after(0, root.destroy)

    threading.Thread(target=work, daemon=True).start()
    root.mainloop()
    return out.get("ok", False), out.get("log", "")


def _handle_missing(e: ModuleNotFoundError):
    cmd = f'"{sys.executable}" -m pip install -r requirements.txt'
    print(f"A required Python package is missing: {e.name}\nInstall with:\n    {cmd}", file=sys.stderr)

    already_tried = os.environ.get(TRIED_ENV) == "1"
    can_install = os.path.exists(REQUIREMENTS) and not already_tried
    ask = tk.Tk()
    ask.withdraw()
    try:
        if can_install:
            go = os.environ.get(AUTO_ENV) == "1" or messagebox.askyesno(
                "Missing dependencies",
                f"A required Python package is missing: {e.name}\n\n"
                f"Install the required packages now into this Python?\n{sys.executable}",
            )
            if go:
                ask.destroy()
                ok, log = _install_requirements()
                if ok:
                    # Restart the app in a fresh interpreter so the new packages are importable.
                    env = dict(os.environ, **{TRIED_ENV: "1"})
                    subprocess.Popen([sys.executable] + sys.argv, env=env)
                    sys.exit(0)
                tail = "\n".join(log.splitlines()[-8:])
                err = tk.Tk()
                err.withdraw()
                messagebox.showerror("Install failed",
                                     f"Could not install the packages automatically.\n\n{tail}\n\n"
                                     f"Try this in a terminal:\n{cmd}")
                err.destroy()
                sys.exit(1)
            sys.exit(1)
        messagebox.showerror("Missing dependencies",
                             f"A required Python package is missing: {e.name}\n\n"
                             f"Install the dependencies with the same Python you use to run this app:\n\n{cmd}")
    finally:
        try:
            ask.destroy()
        except Exception:
            pass
    sys.exit(1)


def _import_app():
    try:
        from src.gui.app import App
        return App
    except ModuleNotFoundError as e:
        _handle_missing(e)


def main():
    App = _import_app()
    root = tk.Tk()
    # Use ttk theme for modern look
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
