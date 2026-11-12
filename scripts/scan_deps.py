#!/usr/bin/env python3
"""Check a project's dependencies for:
  C23 packages that don't exist on the registry, are brand new, or barely used
      (possible AI-hallucinated / slopsquatted names)
  C22 known vulnerabilities (npm audit / pip-audit when available)

Usage: python scan_deps.py <project-folder>
"""
import datetime as dt
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request

UA = {"User-Agent": "app-security-audit/1.0"}
# Names publicly documented as AI-hallucinated packages that were later registered.
KNOWN_HALLUCINATED = {"react-codeshift", "huggingface-cli", "arangodb", "starlette-reverse-proxy"}
DL_FAILED = []


def get_json(url):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=15) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return None, None


def npm_info(name):
    st, data = get_json("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"))
    if st == 404:
        return "MISSING", None, None
    if not data:
        return "UNKNOWN", None, None
    created = data.get("time", {}).get("created")
    st2, dl = get_json("https://api.npmjs.org/downloads/point/last-week/" + urllib.parse.quote(name, safe="@"))
    if st2 != 200:
        DL_FAILED.append(name)
    return "OK", created, (dl or {}).get("downloads")


def pypi_info(name):
    st, data = get_json(f"https://pypi.org/pypi/{name}/json")
    if st == 404:
        return "MISSING", None, None
    if not data:
        return "UNKNOWN", None, None
    times = [f[0]["upload_time"] for f in data.get("releases", {}).values() if f]
    return "OK", min(times) if times else None, None


def age_days(iso):
    try:
        t = dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (dt.datetime.now(dt.timezone.utc) - t.replace(tzinfo=t.tzinfo or dt.timezone.utc)).days
    except Exception:
        return None


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    deps = []
    pj = os.path.join(root, "package.json")
    if os.path.exists(pj):
        d = json.load(open(pj))
        for sec in ("dependencies", "devDependencies"):
            for n, v in (d.get(sec) or {}).items():
                if not str(v).startswith(("file:", "link:", "workspace:", "git", "http")):
                    deps.append(("npm", n, ""))
    for req in ("requirements.txt", "requirements-dev.txt"):
        p = os.path.join(root, req)
        if os.path.exists(p):
            for line in open(p):
                m = re.match(r"\s*([A-Za-z0-9_.\-]+)", line)
                if m and not line.strip().startswith(("#", "-")):
                    deps.append(("pypi", m.group(1), ""))
    # MCP servers launched via npx/uvx are dependencies too (C28)
    for mcp in (".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", "mcp.json"):
        mp = os.path.join(root, mcp)
        if os.path.exists(mp):
            txt = open(mp, encoding="utf-8", errors="ignore").read()
            for m in re.finditer(r"\"(npx|bunx|uvx)\"[^\]]*\[([^\]]*)\]", txt):
                args = [a for a in re.findall(r"\"([^\"]+)\"", m.group(2)) if not a.startswith("-")]
                if args:
                    name = re.sub(r"(?<=.)@[^/]*$", "", args[0])
                    deps.append(("npm" if m.group(1) != "uvx" else "pypi", name, f"MCP server in {mcp} (C28)"))
    deps = [d if len(d) == 3 else (*d, "") for d in deps]
    print(f"== Dependency check: {len(deps)} packages")
    flagged = 0
    for eco, n, origin in deps:
        status, created, dls = npm_info(n) if eco == "npm" else pypi_info(n)
        age = age_days(created) if created else None
        notes = []
        if status == "MISSING":
            notes.append("DOES NOT EXIST on the registry — likely hallucinated; installing it later could pull an attacker's package")
        if age is not None and age < 90:
            notes.append(f"published only {age} days ago")
        if dls is not None and dls < 200:
            notes.append(f"only {dls} downloads last week")
        if n in KNOWN_HALLUCINATED:
            notes.append("publicly documented AI-hallucinated package name (slopsquatting target) — confirm it's really the package you want")
        if status == "UNKNOWN":
            notes.append("could not reach registry")
        if notes:
            flagged += 1
            print(f"[{'C28' if origin else 'C23'}] {eco}:{n}{' — ' + origin if origin else ''} — " + "; ".join(notes))
    if not flagged:
        print("[C23] All packages exist and look established.")
    if DL_FAILED:
        print(f"[C23] WARNING: download counts could not be fetched for {len(DL_FAILED)} package(s) — the 'barely used' check did not run; look at them manually: {', '.join(DL_FAILED[:15])}")

    print("\n== Known vulnerabilities (C22)")
    if os.path.exists(os.path.join(root, "package-lock.json")):
        r = subprocess.run(["npm", "audit", "--json", "--omit=dev"], cwd=root, capture_output=True, text=True)
        try:
            meta = json.loads(r.stdout).get("metadata", {}).get("vulnerabilities", {})
            print("npm audit:", ", ".join(f"{k}={v}" for k, v in meta.items()))
            vulns = json.loads(r.stdout).get("vulnerabilities", {})
            for name, v in list(vulns.items())[:25]:
                if v.get("severity") in ("high", "critical"):
                    print(f"  [{v['severity'].upper()}] {name} {v.get('range','')}  fix available: {bool(v.get('fixAvailable'))}")
        except Exception:
            print("npm audit failed:", (r.stderr or r.stdout)[:300])
    elif os.path.exists(pj):
        import shutil, tempfile
        tmp = tempfile.mkdtemp(prefix="audit-deps-")
        d = json.load(open(pj))
        missing = {n for e, n, o in deps if e == "npm" and not o and npm_info(n)[0] == "MISSING"}
        for sec in ("dependencies", "devDependencies"):
            for n in list((d.get(sec) or {})):
                if n in missing:
                    del d[sec][n]
        json.dump(d, open(os.path.join(tmp, "package.json"), "w"))
        r0 = subprocess.run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=tmp, capture_output=True, text=True)
        if r0.returncode == 0:
            r = subprocess.run(["npm", "audit", "--json", "--omit=dev"], cwd=tmp, capture_output=True, text=True)
            try:
                out = json.loads(r.stdout)
                print("npm audit (lockfile generated in a temp folder; project untouched):", ", ".join(f"{k}={v}" for k, v in out.get("metadata", {}).get("vulnerabilities", {}).items()))
                for name, v in list(out.get("vulnerabilities", {}).items())[:25]:
                    if v.get("severity") in ("high", "critical"):
                        print(f"  [{v['severity'].upper()}] {name} {v.get('range','')}  fix available: {bool(v.get('fixAvailable'))}")
            except Exception:
                print("npm audit failed:", (r.stderr or r.stdout)[:300])
        else:
            print("Could not resolve dependencies for audit:", r0.stderr[-300:])
        shutil.rmtree(tmp, ignore_errors=True)
    if any(e == "pypi" and not o for e, _, o in deps):
        r = subprocess.run(["pip-audit", "-r", os.path.join(root, "requirements.txt"), "-f", "json"], capture_output=True, text=True)
        print("pip-audit:", (r.stdout[:800] or r.stderr[:300] or "not installed (pip install pip-audit)"))


if __name__ == "__main__":
    main()
