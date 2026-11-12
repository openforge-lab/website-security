#!/usr/bin/env python3
"""Check of a live site the user owns: what the browser can see.

Optional flags (only on a site the user confirmed is theirs):
  --burst PATH|URL [--post] [--apikey KEY]   send 30 quick requests to see if rate limiting kicks in (C17).
     For Supabase auth: --burst https://<ref>.supabase.co/auth/v1/token?grant_type=password --post --apikey <anon key>

Downloads the page and its same-origin JS, looks for secret keys, source maps,
Supabase/Firebase config, admin-looking routes, and probes a few sensitive paths.
Sends only a small number of GET requests. Prints masked values only.

Usage: python scan_live.py https://myapp.com
"""
import os
import re
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secret_patterns import find  # noqa: E402

UA = {"User-Agent": "app-security-audit/1.0 (owner self-check)"}
PROBE_PATHS = ["/.env", "/.env.local", "/.env.production", "/.git/config", "/config.json",
               "/backup.sql", "/database.sql", "/admin", "/api/admin", "/dashboard/admin", "/.DS_Store"]
ADMIN_RE = re.compile(r"""["'`](/(?:api/)?(?:admin|internal|backoffice|manage)[A-Za-z0-9_\-/]*)["'`]""")
SUPA_URL_RE = re.compile(r"https://([a-z0-9]{20})\.supabase\.co")
FIREBASE_RE = re.compile(r"([a-z0-9\-]+)\.firebaseio\.com|projectId[\"']?\s*:\s*[\"']([a-z0-9\-]+)")
WEBHOOK_RE = re.compile(r"""["'`](/api/[A-Za-z0-9_\-/]*(?:webhook|stripe)[A-Za-z0-9_\-/]*)["'`]""", re.I)


def get(url, limit=8_000_000):
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.headers.get("content-type", ""), r.read(limit).decode("utf-8", "ignore"), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("content-type", ""), "", url
    except Exception as e:
        return None, "", str(e), url


SEC_HEADERS = {
    "strict-transport-security": "HSTS (forces HTTPS)",
    "content-security-policy": "CSP (limits XSS damage)",
    "x-content-type-options": "nosniff",
    "referrer-policy": "Referrer-Policy",
}
WAF_SIGNS = [
    ("cf-ray", "Cloudflare"), ("x-sucuri-id", "Sucuri"), ("x-akamai", "Akamai"), ("x-amz-cf-id", "AWS CloudFront"),
    ("x-vercel-id", "Vercel edge"), ("x-nf-request-id", "Netlify edge"), ("x-iinfo", "Imperva"), ("x-cdn", "CDN"),
    ("x-fastly", "Fastly"), ("server: imunify", "Imunify360"), ("x-litespeed", "LiteSpeed"), ("bunny", "BunnyCDN"),
]


def head(url, extra=None):
    h = dict(UA)
    h.update(extra or {})
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(3000).decode("utf-8", "ignore"), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(3000).decode("utf-8", "ignore"), url
    except Exception as e:
        return None, {}, str(e), url


def infra_checks(origin, base):
    print("\n== Infrastructure (C30-C33)")
    st, h, body, _ = head(base)
    # C30 HTTPS + headers
    if origin.startswith("https://"):
        st2, _, _, fin = head("http://" + origin[len("https://"):])
        hsts = "strict-transport-security" in h
        if st2 is None:
            print(f"[C30] HTTP->HTTPS redirect: could not test plain http from here{'; HSTS is set, so browsers always use HTTPS (good)' if hsts else ''}")
        else:
            print(f"[C30] HTTP->HTTPS redirect: {'yes' if fin.startswith('https://') else 'NO (plain http still served)'}")
    else:
        print("[C30] Site is served over plain HTTP — no encryption")
    missing = [v for k, v in SEC_HEADERS.items() if k not in h]
    framing = "x-frame-options" in h or "frame-ancestors" in h.get("content-security-policy", "")
    if not framing:
        missing.append("clickjacking protection (X-Frame-Options / frame-ancestors)")
    print(f"[C30] Security headers missing: {', '.join(missing) if missing else 'none'}")
    # C33 software disclosure
    disc = [f"{k}: {h[k]}" for k in ("server", "x-powered-by", "x-aspnet-version", "x-generator") if k in h and re.search(r"\d", h[k])]
    print(f"[C33] Server software versions shown to visitors: {', '.join(disc) if disc else 'none (good)'}")
    # C31 WAF / CDN presence
    blob = " ".join(f"{k}: {v}" for k, v in h.items()).lower()
    seen = sorted({name for sign, name in WAF_SIGNS if sign in blob})
    print(f"[C31] Edge protection / WAF signs: {', '.join(seen) if seen else 'none detected from headers (a WAF may still exist; confirm with the host)'}")
    # C17 rate-limit headers
    rl = [k for k in h if "ratelimit" in k or k == "retry-after"]
    print(f"[C17] Rate-limit headers on the homepage: {', '.join(rl) if rl else 'none seen'}")
    # CORS
    st3, h3, _, _ = head(origin + "/api/", {"Origin": "https://example-attacker.test"})
    acao = h3.get("access-control-allow-origin")
    if acao in ("*", "https://example-attacker.test"):
        cred = h3.get("access-control-allow-credentials")
        print(f"[C29] CORS lets any website call /api/ (Allow-Origin: {acao}{', with credentials!' if cred == 'true' else ''})")
    else:
        print("[C29] CORS on /api/: not open to foreign origins")
    # C03 error leak
    st4, _, b4, _ = head(origin + "/api/__audit_nonexistent__?x=%7B")
    leak = re.search(r"(Traceback|at [\w$.<>]+ \(/|node_modules/|Exception in|SQLSTATE|stack\s*[\"']?:|Warning: .* on line \d+|/var/www/|/home/\w+/)", b4)
    print(f"[C03] Error page for a bad API request (HTTP {st4}): {'LEAKS internal details: ' + leak.group(0) if leak else 'no internal details seen'}")


APIKEY = None
WAF_BLOCK_SIGNS = re.compile(r"(access denied|request blocked|forbidden|not acceptable|mod_security|modsecurity|web application firewall|cloudflare|attention required|sucuri|imunify|incapsula|security policy|blocked by)", re.I)


def waf_probe(origin):
    """C31: harmless requests that look like attacks. A WAF blocks them; an unprotected site serves them."""
    base_st, _, base_body, _ = head(origin + "/?audit_q=hello")
    base_sign = WAF_BLOCK_SIGNS.search(base_body or "")
    probes = [
        "/?audit_q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "/?id=1%27%20OR%20%271%27%3D%271",
        "/?file=..%2F..%2F..%2Fetc%2Fpasswd",
    ]
    results = []
    for pr in probes:
        st, _, body, _ = head(origin + pr)
        sign = WAF_BLOCK_SIGNS.search(body or "")
        blocked = (st != base_st and st in (400, 403, 406, 418, 429, 501, 503)) or (st is not None and st == base_st and sign and not base_sign)
        results.append((pr, st, blocked, sign.group(0) if sign else ""))
    n = sum(1 for r in results if r[2])
    detail = "; ".join(f"HTTP {st}{' (' + sg + ')' if sg else ''}" for _, st, _, sg in results)
    if base_st is None:
        print("[C31] WAF probe: site unreachable — not checked")
    elif n == len(results):
        print(f"[C31] WAF probe: all {n} attack-looking requests BLOCKED ({detail}) — a firewall is active")
    elif n:
        print(f"[C31] WAF probe: {n} of {len(results)} attack-looking requests blocked ({detail}) — partial firewall rules")
    else:
        hdr = head(origin)[1]
        blob = " ".join(f"{k}: {v}" for k, v in hdr.items()).lower()
        edge = sorted({name for sign, name in WAF_SIGNS if sign in blob})
        if edge:
            print(f"[C31] WAF probe: {', '.join(edge)} is in front of the site, but all {len(results)} attack-looking requests were served like a normal page — its firewall rules aren't blocking common attacks (DDoS protection may still be active)")
            return
        print(f"[C31] WAF probe: all {len(results)} attack-looking requests served like a normal page (normal HTTP {base_st}; probes {detail}) — no firewall blocking common attacks")


def burst_test(origin, path, post):
    """C17: 30 quick requests to one endpoint; does the site ever slow us down?"""
    import json as _json
    url = path if path.startswith("http") else origin + (path if path.startswith("/") else "/" + path)
    _, _, home_body, _ = head(origin + "/")
    codes, bodies = [], []
    for i in range(30):
        data = _json.dumps({"email": "ratelimit-audit@example.com", "password": "audit-test-wrong"}).encode() if post else None
        hdrs = dict(UA, **({"Content-Type": "application/json"} if post else {}))
        if APIKEY:
            hdrs.update({"apikey": APIKEY, "Authorization": "Bearer " + APIKEY})
        req = urllib.request.Request(url, data=data, headers=hdrs, method="POST" if post else "GET")
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                codes.append(r.status)
                bodies.append(r.read(3000).decode("utf-8", "ignore"))
        except urllib.error.HTTPError as e:
            codes.append(e.code)
        except Exception:
            codes.append(None)
        if codes[-1] == 429 or (len(codes) > 1 and codes[-1] in (403, 406, 503) and codes[0] not in (403, 406, 503)):
            break
    first = codes[0] if codes else None
    limited = [c for c in codes if c in (429, 503) or (c in (403, 406) and first not in (403, 406))]
    summary = ", ".join(f"{c}x{codes.count(c)}" for c in sorted(set(codes), key=str))
    if bodies and home_body and all(b[:500] == home_body[:500] for b in bodies[:3]):
        print(f"[C17] Burst test on {path}: this path just returns the site's main page (single-page app) — it isn't the real login/API endpoint. For Supabase apps test https://<project>.supabase.co/auth/v1/token?grant_type=password with --post --apikey <anon key>")
        return
    if codes and all(c in (404, 405, 501, None) for c in codes):
        print(f"[C17] Burst test on {path}: endpoint not found / method not allowed ({summary}) — pick the real login or API path and run again")
    elif limited:
        print(f"[C17] Burst test on {path}: rate limiting kicked in after {codes.index(limited[0]) + 1} requests (HTTP {limited[0]}) — protected")
    else:
        print(f"[C17] Burst test on {path}: {len(codes)} quick {'POST' if post else 'GET'} requests, none slowed down or blocked ({summary}) — no rate limiting within 30 quick requests on this endpoint")


def main():
    global APIKEY
    burst_path = None
    if "--apikey" in sys.argv:
        i = sys.argv.index("--apikey")
        APIKEY = sys.argv[i + 1]
        del sys.argv[i:i + 2]
    post = "--post" in sys.argv
    if "--burst" in sys.argv:
        i = sys.argv.index("--burst")
        burst_path = sys.argv[i + 1] if i + 1 < len(sys.argv) else "/"
        del sys.argv[i:i + 2]
    if post:
        sys.argv.remove("--post")
    if len(sys.argv) < 2:
        sys.exit("usage: scan_live.py <url>")
    base = sys.argv[1].rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base
    origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlparse(base))
    status, _, html, final = get(base)
    print(f"== Live scan: {base} (HTTP {status})")
    if not html or status is None:
        print("Could not load the page:", html[:200])
        return
    scripts = set(re.findall(r"""<script[^>]+src=["']([^"']+)["']""", html))
    scripts |= set(re.findall(r"""["'](/(?:_next|assets|static)/[^"']+\.js)["']""", html))
    urls = []
    for s in scripts:
        u = urllib.parse.urljoin(final, s)
        if urllib.parse.urlparse(u).netloc == urllib.parse.urlparse(origin).netloc:
            urls.append(u)
    urls = sorted(set(urls))[:60]
    texts = {"(page HTML)": html}
    maps = []
    for u in urls:
        st, _, body, _ = get(u)
        if st == 200:
            texts[u] = body
            # follow chunk references one level for SPA bundles
            if "sourceMappingURL=" in body[-500:]:
                maps.append(u)
    # extra lazily-loaded chunks referenced inside main bundles (one level, capped)
    extra = set()
    for body in list(texts.values()):
        for m in re.findall(r"""["'](/?(?:_next/static|assets|static)/[^"'\s]+\.js)["']""", body):
            u = urllib.parse.urljoin(origin + "/", m)
            if u not in texts:
                extra.add(u)
    for u in sorted(extra)[:80]:
        st, _, body, _ = get(u)
        if st == 200:
            texts[u] = body

    print(f"Downloaded {len(texts) - 1} JavaScript files.")
    findings = []
    admin_routes, webhooks, supa, fb = set(), set(), set(), set()
    for u, t in texts.items():
        for name, val, sev, _ in find(t):
            findings.append((sev, name, val, u))
        admin_routes |= set(ADMIN_RE.findall(t))
        webhooks |= set(WEBHOOK_RE.findall(t))
        supa |= set(SUPA_URL_RE.findall(t))
        for a, b in FIREBASE_RE.findall(t):
            fb.add(a or b)

    print("\n== Keys visible to any visitor")
    order = {"secret": 0, "check": 1, "public": 2}
    for sev, name, val, u in sorted(set(findings), key=lambda f: order.get(f[0], 9)):
        print(f"[{sev.upper():6}] {name}: {val}  in {u}")
    if not findings:
        print("None found.")

    if maps:
        print("\n== Source maps referenced (may expose full source code):")
        for u in maps:
            st, _, _, _ = get(u + ".map", limit=1000)
            print(f"  {u}.map -> HTTP {st}")
    if supa:
        print("\n== Supabase project(s):", ", ".join(sorted(supa)), "-> check RLS (door 3)")
    if fb:
        print("== Firebase project(s):", ", ".join(sorted(fb)), "-> check security rules (door 3)")
    if admin_routes:
        print("\n== Admin-looking routes in the code:", ", ".join(sorted(admin_routes)[:30]))
    if webhooks:
        print("== Webhook/payment routes in the code:", ", ".join(sorted(webhooks)[:20]))

    print("\n== Sensitive path probes (logged out)")
    for p in PROBE_PATHS + sorted(r for r in admin_routes if r not in PROBE_PATHS)[:10]:
        st, ctype, body, fin = get(origin + p, limit=4000)
        note = ""
        if st == 200:
            if p.startswith("/.env") and "=" in body and "<html" not in body.lower():
                note = "  <-- EXPOSED env file!"
            elif p == "/.git/config" and "[core]" in body:
                note = "  <-- EXPOSED git repo!"
            elif "admin" in p:
                note = "  (loads logged out — check whether it shows data or calls APIs that answer without login)"
            elif "<html" in body.lower()[:500]:
                note = "  (SPA fallback page, probably fine)"
        if fin != origin + p:
            note += f"  redirected to {fin}"
        print(f"  {p:22} HTTP {st}{note}")
    infra_checks(origin, base)
    waf_probe(origin)
    if burst_path:
        burst_test(origin, burst_path, post)
    print("\nThis is a passive outside view. Doors 3-7 still need the code, database settings or test accounts to confirm.")


if __name__ == "__main__":
    main()
