"""Wrap the Lead Tracker page (the same lead-tracker.html published as the Claude artifact) into static/index.html,
loading claude-shim.js first so the page runs on this server. Run after copying in a newer lead-tracker.html."""
import sys
from pathlib import Path

base = Path(__file__).resolve().parent
src = Path(sys.argv[1]) if len(sys.argv) > 1 else base / "lead-tracker.html"
page = src.read_text(encoding="utf-8")
head = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<script src="/claude-shim.js"></script></head><body>')
(base / "static" / "index.html").write_text(head + page + "</body></html>", encoding="utf-8")
print("wrote static/index.html from", src.name)
