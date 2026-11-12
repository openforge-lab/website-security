#!/usr/bin/env python3
"""Scan a project folder (and its git history) for secret keys. Prints masked values only.

Usage: python scan_secrets.py <project-folder>
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secret_patterns import find  # noqa: E402

SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", ".turbo", ".cache"}
CLIENT_DIRS = re.compile(r"(^|/)(src|app|pages|components|public|dist|build|\.next/static|client|lib|hooks)(/|$)")
CLIENT_ENV = re.compile(r"^\s*(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_)\w*(KEY|SECRET|TOKEN|PASSWORD|SERVICE)\w*\s*=", re.M)
CLIENT_CODE = [
    (re.compile(r"process\.env\.(NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_)\w*(KEY|SECRET|TOKEN|PASSWORD)\w*"), "Code reads a secret-looking browser-exposed env var"),
    (re.compile(r"import\.meta\.env\.(VITE_|PUBLIC_)\w*(KEY|SECRET|TOKEN|PASSWORD)\w*"), "Code reads a secret-looking browser-exposed env var"),
    (re.compile(r"dangerouslyAllowBrowser\s*:\s*true"), "AI SDK configured to run in the browser (key is exposed)"),
]
CODE_EXT = (".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".astro", ".mjs")
SERVER_HINT = re.compile(r"(^|/)(api|server|functions|supabase/functions|edge|actions)(/|$)|\.server\.|route\.(t|j)s$")


def scan_tree(root):
    hits = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, root)
            try:
                if os.path.getsize(p) > 5_000_000:
                    continue
                text = open(p, encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            for name, val, sev, off in find(text):
                line = text.count("\n", 0, off) + 1
                where = "server" if SERVER_HINT.search(rel) else ("CLIENT?" if CLIENT_DIRS.search(rel) else "")
                if fn.startswith(".env"):
                    ln = text.splitlines()[line - 1] if line <= len(text.splitlines()) else ""
                    where = "CLIENT (browser-exposed prefix)" if re.match(r"\s*(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_)", ln) else "env file"
                hits.append((sev, name, val, f"{rel}:{line}", where))
            if fn.endswith(CODE_EXT) and not SERVER_HINT.search(rel):
                for rx, label in CLIENT_CODE:
                    for m in rx.finditer(text):
                        if re.search(r"ANON_KEY|PUBLISHABLE_KEY|PUBLIC_KEY", m.group(0)):
                            continue
                        line = text.count("\n", 0, m.start()) + 1
                        client = "'use client'" in text[:200] or '"use client"' in text[:200] or CLIENT_DIRS.search(rel)
                        hits.append(("secret?", label, m.group(0), f"{rel}:{line}", "CLIENT" if client else "check"))
            if fn.startswith(".env") or fn.endswith(".env"):
                for m in CLIENT_ENV.finditer(text):
                    if re.search(r"ANON|PUBLISHABLE|PUBLIC_KEY", m.group(0)):
                        continue
                    line = text.count("\n", 0, m.start()) + 1
                    hits.append(("secret?", "Secret-looking var with a browser-exposed prefix", m.group(0).split("=")[0].strip(), f"{rel}:{line}", "CLIENT"))
    return hits


def scan_git(root):
    if not os.path.isdir(os.path.join(root, ".git")):
        return [], []
    tracked_env = subprocess.run(["git", "-C", root, "ls-files", "*.env*", ".env*"], capture_output=True, text=True).stdout.split()
    log = subprocess.run(["git", "-C", root, "log", "--all", "-p", "--no-color", "-U0"], capture_output=True, text=True, errors="ignore").stdout
    hist = sorted({(sev, name, val) for name, val, sev, _ in find(log) if sev != "public"})
    return tracked_env, hist


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    hits = scan_tree(root)
    print(f"== Secret scan: {os.path.abspath(root)}")
    order = {"secret": 0, "secret?": 1, "check": 2, "public": 3}
    for sev, name, val, loc, where in sorted(hits, key=lambda h: order.get(h[0], 9)):
        print(f"[{sev.upper():7}] {name}: {val}  @ {loc}  {where}")
    if not hits:
        print("No key patterns found in files.")
    tracked_env, hist = scan_git(root)
    if tracked_env:
        print("\n[SECRET?] .env files committed to git:", ", ".join(tracked_env))
    if hist:
        print("\n== Keys found in git history (rotate these even if deleted now):")
        for sev, name, val in hist:
            print(f"[{sev.upper():7}] {name}: {val}")
    print("\nNote: 'public' keys are fine only if RLS / security rules protect the data behind them. 'CLIENT?' means the file likely ships to the browser.")


if __name__ == "__main__":
    main()
