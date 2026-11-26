from __future__ import annotations
import sys
import tkinter as tk
from tkinter import ttk

def _import_app():
    """Import the GUI, showing a clear message if dependencies are missing."""
    try:
        from src.gui.app import App
        return App
    except ModuleNotFoundError as e:
        msg = (
            f"A required Python package is missing: {e.name}\n\n"
            "Install the dependencies with the same Python you are using to run this app:\n\n"
            f'    "{sys.executable}" -m pip install -r requirements.txt\n\n'
            "Then start the app again."
        )
        print(msg, file=sys.stderr)
        try:
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Missing dependencies", msg)
            root.destroy()
        except Exception:
            pass
        sys.exit(1)

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
