from __future__ import annotations
import tkinter as tk
from tkinter import ttk

from src.gui.app import App

def main():
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
