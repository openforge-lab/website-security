#!/usr/bin/env python3
"""Static scan of a project folder for the code-level checks of the audit.

Prints findings grouped by check ID (see references/checks.md). Each line is a
lead to verify by reading the code, not a verdict. Also prints which checks had
no hits so the auditor knows where it still needs to look manually.

Usage: python scan_code.py <project-folder>
"""
import os
import re
import subprocess
import sys
from collections import defaultdict

SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", ".next", "dist", "build", ".turbo", ".cache", "coverage", ".vercel"}
CODE_EXT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro", ".py", ".php", ".rb", ".go")
SQL_EXT = (".sql",)
SERVER_HINT = re.compile(r"(^|/)(api|server|functions|supabase/functions|edge|actions|backend|routes|controllers)(/|$)|\.server\.|route\.(t|j)s$|\.py$|\.php$")
RULE_FILES = re.compile(r"(^|/)(\.cursorrules|\.windsurfrules|CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.clinerules|copilot-instructions\.md|\.cursor/rules.*|\.github/instructions/.*|\.kiro/.*\.md)$")
MCP_FILES = re.compile(r"(^|/)(\.mcp\.json|\.cursor/mcp\.json|\.vscode/mcp\.json|mcp\.json|claude_desktop_config\.json|\.gemini/settings\.json)$")
HIDDEN_CHARS = re.compile("[​‌‍⁠﻿‪-‮⁦-⁩\U000e0000-\U000e007f]")

# (check_id, label, regex, scope) scope: "any" | "client" | "server"
RULES = [
    ("C03", "Error details sent to the user", r"((res\.(status\(\d+\)\.)?(json|send)|Response\.json|NextResponse\.json|jsonify)\(\s*(err|error|e)\s*\)|error\.stack|err\.stack|message:\s*(err|error|e)\.message|traceback\.format_exc|DEBUG\s*=\s*True|display_errors)", "server"),
    ("C04", "Users' own API keys stored (check encryption)", r"\b(openai_key|api_key|apikey|anthropic_key|user_api_key|secret_key)\b\s*(text|varchar|:\s*(str|string))", "any"),
    ("C08", "Admin/service client in browser code", r"(service_role|SERVICE_ROLE|serviceRoleKey|sb_secret_)", "client"),
    ("C09", "Role/plan/credits written from request body", r"(\.update\(\s*(req\.body|body|data|input)\s*\)|\.\.\.(req\.body|body)\b|update\(\s*\{[^}]*(is_admin|role|plan|credits|subscription|tier)\s*:)", "any"),
    ("C12", "Login/role decided in the browser", r"(localStorage\.(getItem|setItem)\(\s*['\"`](isAdmin|is_admin|role|admin|isPro|plan|user|token|auth)['\"`]|sessionStorage\.getItem\(\s*['\"`](isAdmin|role|admin)|(isAdmin|is_admin|role\s*===?\s*['\"`]admin['\"`]))", "client"),
    ("C14", "Math.random used for a token/code/password", r"Math\.random\(\)[^\n]{0,80}(token|code|otp|reset|password|secret|key|invite|id)|(token|code|otp|reset|password|secret|invite)[^\n]{0,80}Math\.random\(\)|random\.randint\([^\n]{0,40}(otp|code|token)", "any"),
    ("C16", "Price/amount taken from the request", r"(unit_amount|amount|price)\s*:\s*(req\.body|body|params|input|data)\.\w+|(unit_amount|amount|price)\s*:\s*Number\((req\.body|body)|price_data", "server"),
    ("C17", "Rate limiting / captcha present", r"(ratelimit|rateLimit|rate-limit|express-rate-limit|@upstash/ratelimit|slowapi|throttle|captcha|turnstile|hcaptcha|recaptcha)", "any"),
    ("C18", "File upload handler (check type/size limits)", r"(multer\(|formidable|busboy|\.upload\(|storage\.from\([^)]*\)\.upload|request\.files|UploadFile|move_uploaded_file|createSignedUploadUrl)", "any"),
    ("C19", "Server fetches a URL that comes from the user", r"(fetch|axios\.get|axios|got|requests\.get|httpx\.get|urlopen|file_get_contents|curl_init)\(\s*(req\.(body|query|params)\.\w+|body\.\w+|url\b|params\.url|searchParams\.get\(['\"]url)", "server"),
    ("C20", "Raw HTML rendering (XSS risk)", r"(dangerouslySetInnerHTML|\.innerHTML\s*=|v-html=|\{@html|document\.write\(|insertAdjacentHTML|\|\s*safe\b|mark_safe\()", "any"),
    ("C21", "SQL built from strings (injection risk)", r"((query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe|sql)\s*\(\s*[`'\"][^`'\"]*(SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{|f[\"'](SELECT|INSERT|UPDATE|DELETE)[^\"']*\{|[\"'](SELECT|INSERT|UPDATE|DELETE)[^\"']*[\"']\s*\+\s*\w|\$queryRawUnsafe|\$executeRawUnsafe|\.rpc\([^)]*\$\{|mysqli_query\([^,]+,\s*[\"'][^\"']*\$)", "any"),
    ("C21", "eval / new Function on dynamic input", r"(\beval\(|new Function\()", "any"),
    ("C24", "User text sent to an AI model (prompt injection surface)", r"(chat\.completions\.create|messages\.create|responses\.create|generateText|streamText|generateObject|ChatOpenAI|ChatAnthropic|genai\.|GenerativeModel|invoke\()", "any"),
    ("C24", "AI given tools / function calling", r"(tools\s*:\s*\[|tool_choice|function_call|functions\s*:\s*\[|bind_tools|tool\(\{|createTool|mcpServers)", "any"),
    ("C25", "AI output rendered as HTML/markdown", r"(dangerouslySetInnerHTML[^\n]{0,80}(completion|response|answer|message|content|output)|marked\(|markdown-it|react-markdown[^\n]*rehype-raw)", "any"),
    ("C26", "AI/agent code with destructive DB or shell power", r"(child_process|exec\(|execSync|subprocess\.(run|Popen|call)|os\.system|DROP TABLE|TRUNCATE|\.delete\(\)\s*$|deleteMany\(\s*\)|service_role)", "server"),
    ("C29", "Security turned off in code", r"(rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED|disable row level security|@ts-ignore[^\n]*(auth|session|user)|eslint-disable[^\n]*security|csrf_exempt|origin\s*:\s*['\"]\*['\"]|Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*)", "any"),
    ("C30", "Security headers configured", r"(Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|helmet\(|frame-ancestors)", "any"),
]
COMPILED = [(c, l, re.compile(r, re.I if c not in ("C12",) else 0), s) for c, l, r, s in RULES]

SQL_RULES = [
    ("C05", "Table created; RLS enabled?", re.compile(r"create\s+table\s+(if\s+not\s+exists\s+)?([\w\.\"]+)", re.I)),
    ("C05", "RLS enabled", re.compile(r"alter\s+table\s+([\w\.\"]+)\s+enable\s+row\s+level\s+security", re.I)),
    ("C10", "Policy that allows everyone (using true)", re.compile(r"create\s+policy[^;]*using\s*\(\s*true\s*\)", re.I | re.S)),
    ("C10", "Update/insert policy without WITH CHECK", re.compile(r"create\s+policy[^;]*for\s+(update|insert|all)[^;]*;", re.I | re.S)),
    ("C07", "Public storage bucket", re.compile(r"(insert\s+into\s+storage\.buckets[^;]*true|public\s*=\s*true|public:\s*true)", re.I | re.S)),
    ("C29", "RLS disabled", re.compile(r"disable\s+row\s+level\s+security", re.I)),
    ("C05", "SECURITY DEFINER function (bypasses RLS)", re.compile(r"security\s+definer", re.I)),
]


def is_client(rel, text):
    if SERVER_HINT.search(rel):
        return False
    head = text[:300]
    if "'use client'" in head or '"use client"' in head:
        return True
    return bool(re.search(r"(^|/)(src|app|pages|components|hooks|lib|client|public|views|composables)(/|$)", rel)) and rel.endswith((".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".astro"))


def walk(root):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, root)
            try:
                if os.path.getsize(p) > 2_000_000:
                    continue
                yield rel, open(p, encoding="utf-8", errors="ignore").read()
            except Exception:
                continue


def line_of(text, off):
    return text.count("\n", 0, off) + 1


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    hits = defaultdict(list)
    tables, rls_on = {}, set()
    admin_paths, has_middleware, routes, called = [], False, [], []
    for rel, text in walk(root):
        low = rel.lower()
        if re.search(r"(^|/)middleware\.(t|j)s$", rel):
            has_middleware = True
        if re.search(r"(^|/)(admin|backoffice|internal|dashboard/admin)(/|\.|$)", low):
            admin_paths.append(rel)
        if re.search(r"(^|/)api/.*(route|index)\.(t|j)s$|(^|/)pages/api/|supabase/functions/[^/]+/index\.ts$", rel):
            routes.append(rel)
        if RULE_FILES.search(rel):
            for m in HIDDEN_CHARS.finditer(text):
                hits["C27"].append(f"Hidden/invisible character U+{ord(m.group(0)):04X} @ {rel}:{line_of(text, m.start())}")
                break
            for m in re.finditer(r"(curl[^\n|]*\|\s*(ba)?sh|wget [^\n]*\|\s*sh|base64\s+-d|<script|http[s]?://(?!localhost)[^\s)\"']+|ignore (all|previous) instructions|do not (tell|mention|show) the user)", text, re.I):
                hits["C27"].append(f"Suspicious instruction '{m.group(0)[:60]}' @ {rel}:{line_of(text, m.start())}")
        if MCP_FILES.search(rel):
            servers = re.findall(r"\"([\w\-@/\.]+)\"\s*:\s*\{[^{}]*\"(command|url)\"", text)
            hits["C28"].append(f"MCP config {rel}: servers = {', '.join(s for s, _ in servers) or '(could not parse)'}")
            for m in re.finditer(r"\"(npx|uvx|bunx)\"[^\]]*\[[^\]]*\"(-y\"\s*,\s*)?\"([^\"@][^\"]*?)\"", text):
                if "@" not in m.group(3)[1:]:
                    hits["C28"].append(f"Unpinned MCP package '{m.group(3)}' (runs latest version every time) @ {rel}")
        if rel.endswith(".vsix") or re.search(r"(^|/)\.vscode/extensions\.json$", rel):
            hits["C28"].append(f"Editor extension list: {rel}")
        if rel.endswith(SQL_EXT):
            for cid, label, rx in SQL_RULES:
                for m in rx.finditer(text):
                    if label.startswith("Table created"):
                        name = m.group(2).strip('"').split(".")[-1]
                        tables[name] = f"{rel}:{line_of(text, m.start())}"
                    elif label == "RLS enabled":
                        rls_on.add(m.group(1).strip('"').split(".")[-1])
                    elif label.startswith("Update/insert"):
                        if not re.search(r"with\s+check", m.group(0), re.I):
                            hits[cid].append(f"{label}: {' '.join(m.group(0).split())[:110]} @ {rel}:{line_of(text, m.start())}")
                    else:
                        hits[cid].append(f"{label} @ {rel}:{line_of(text, m.start())}")
            priv_tables = {m.group(1).split(".")[-1] for m in re.finditer(r"create\s+table\s+(?:if\s+not\s+exists\s+)?([\w\.\"]+)\s*\(([^;]*?)\);", text, re.I | re.S) if re.search(r"\b(is_admin|role|plan|credits|subscription_status|tier)\b", m.group(2))}
            for m in re.finditer(r"create\s+policy[^;]*\bon\s+([\w\.\"]+)\s+for\s+(update|all)[^;]*;", text, re.I | re.S):
                t = m.group(1).strip('"').split(".")[-1]
                if t in priv_tables:
                    hits["C09"].append(f"Users can update their own `{t}` row, which has role/plan/credits columns — no column protection seen @ {rel}:{line_of(text, m.start())}")
        if rel.endswith(("firestore.rules", "storage.rules", "database.rules.json")):
            for m in re.finditer(r"(allow\s+read\s*,\s*write\s*:\s*if\s+true|allow\s+(read|write)\s*:\s*if\s+true|\"\.(read|write)\"\s*:\s*true|request\.time\s*<\s*timestamp)", text):
                hits["C05"].append(f"Firebase rule open to everyone '{m.group(0)}' @ {rel}:{line_of(text, m.start())}")
            for m in re.finditer(r"allow\s+[\w, ]+:\s*if\s+request\.auth\s*!=\s*null\s*;", text):
                hits["C06"].append(f"Firebase rule: any logged-in user (not owner) @ {rel}:{line_of(text, m.start())}")
        if not rel.endswith(CODE_EXT):
            continue
        client = is_client(rel, text)
        for cid, label, rx, scope in COMPILED:
            if scope == "client" and not client:
                continue
            if scope == "server" and client:
                continue
            for m in rx.finditer(text):
                hits[cid].append(f"{label}: `{m.group(0)[:70].strip()}` @ {rel}:{line_of(text, m.start())}" + ("  [browser]" if client else ""))
                if len(hits[cid]) > 40:
                    break
        # IDOR lead: query by id from params with no user filter nearby
        for m in re.finditer(r"\.eq\(\s*['\"]id['\"]\s*,\s*(params|req\.(params|query)|searchParams|query)[^)]*\)|findUnique\(\s*\{\s*where\s*:\s*\{\s*id\s*:\s*(params|req)|findById\((req\.)?params", text):
            window = text[max(0, m.start() - 300): m.end() + 300]
            if not re.search(r"user_id|userId|owner|auth\.uid|session\.user|getUser\(", window):
                hits["C06"].append(f"Loads a record by ID from the URL with no owner check nearby @ {rel}:{line_of(text, m.start())}")
        # webhooks
        if re.search(r"webhook", rel, re.I) or re.search(r"checkout\.session\.completed|payment_intent\.succeeded|order_created|subscription_created", text):
            if not re.search(r"constructEvent|constructEventAsync|verifyWebhook|validateEvent|X-Signature|x-signature|createHmac|hmac\.|Webhook\.verify|svix", text):
                hits["C15"].append(f"Payment webhook with no signature verification @ {rel}")
            if re.search(r"req\.json\(\)|request\.json\(\)|JSON\.parse\(", text) and re.search(r"constructEvent", text):
                hits["C15"].append(f"Body parsed as JSON before signature check (breaks verification) — confirm order @ {rel}")
        for m in re.finditer(r"success(_url)?[^\n]{0,60}[?&](plan|paid|tier|pro|upgrade)=", text):
            hits["C15"].append(f"Success URL carries the plan (`{m.group(0)[-40:]}`) — make sure access isn't granted from it @ {rel}:{line_of(text, m.start())}")
        for m in re.finditer(r"role['\"]?\s*:\s*['\"]system['\"][^\n]{0,40}content['\"]?\s*:\s*[`'\"][^`'\"]*(code|key|password|secret|token|discount|coupon|internal|api)[^`'\"]*", text, re.I):
            hits["C24"].append(f"System prompt contains something sensitive (`{m.group(0)[-60:]}`) — users can extract it @ {rel}:{line_of(text, m.start())}")
        if not client and re.search(r"(NEXT_PUBLIC_SUPABASE_ANON_KEY|SUPABASE_ANON_KEY|from ['\"]@/lib/supabase['\"])", text) and re.search(r"\.(update|insert|delete|upsert)\(", text):
            hits["C15" if re.search("webhook", rel, re.I) else "C08"].append(f"Server code writes with the anon (browser) Supabase client — under RLS it acts as an anonymous visitor @ {rel}")
        for m in re.finditer(r"fetch\(\s*['\"`](/api/[\w\-/]+)", text):
            called.append((m.group(1), f"{rel}:{line_of(text, m.start())}"))
        # client-side env reading of server secrets / service role
        for m in re.finditer(r"process\.env\.(\w*(SERVICE_ROLE|SECRET|PRIVATE)\w*)", text):
            if client:
                hits["C02"].append(f"Browser code reads server secret env `{m.group(1)}` @ {rel}:{line_of(text, m.start())}")

    for name, loc in tables.items():
        if name not in rls_on:
            hits["C05"].append(f"Table `{name}` created without ENABLE ROW LEVEL SECURITY @ {loc}")
    if admin_paths:
        hits["C11"].append(f"Admin areas: {', '.join(admin_paths[:15])}" + ("" if has_middleware else "  — no middleware.ts found; check each page/route checks login + admin role on the server"))
    route_urls = {"/" + re.sub(r"(^|.*/)(app|pages)/", "", r).rsplit("/", 1)[0] for r in routes}
    for url, loc in called:
        if url.rstrip("/") not in route_urls and not any(u.startswith(url.rstrip("/")) or url.startswith(u + "/") for u in route_urls):
            hits["C11" if "admin" in url else "C08"].append(f"Calls {url} but no such route in this repo — it lives elsewhere; check it separately @ {loc}")
    if routes:
        hits["C08"].append(f"API routes/functions to check for login ({len(routes)}): {', '.join(routes[:25])}")
    if not any("Rate limiting" in h for h in hits.get("C17", [])):
        hits.setdefault("C17", [])

    # git history: security switched off by an AI "fix"
    if os.path.isdir(os.path.join(root, ".git")):
        log = subprocess.run(["git", "-C", root, "log", "--all", "-p", "--no-color", "-U0", "--max-count=500"], capture_output=True, text=True, errors="ignore").stdout
        for m in re.finditer(r"^\+.*(disable row level security|rejectUnauthorized:\s*false|verify=False|origin:\s*['\"]\*|allow read, write: if true)", log, re.I | re.M):
            hits["C29"].append(f"Added in git history: `{m.group(0)[1:90].strip()}`")
        for m in re.finditer(r"^-.*(constructEvent|enable row level security|auth\.uid\(\)|requireAuth|getUser\(|ratelimit)", log, re.I | re.M):
            hits["C29"].append(f"Removed in git history (security check deleted?): `{m.group(0)[1:90].strip()}`")

    names = {
        "C02": "Secret keys (full key scan is scan_secrets.py)", "C03": "Error details exposed", "C04": "Users' API keys stored", "C05": "Database / RLS",
        "C06": "Other people's records (IDOR)", "C07": "Public file storage", "C08": "API routes without login",
        "C09": "Users editing their own role/plan", "C10": "Weak RLS policies", "C11": "Admin protection",
        "C12": "Login decided in the browser", "C14": "Predictable tokens", "C15": "Payment verification",
        "C16": "Price from the browser", "C17": "Rate limit / bot protection", "C18": "File uploads", "C19": "SSRF",
        "C20": "XSS", "C21": "Injection (SQL / eval)", "C24": "AI prompt injection surface", "C25": "AI output / data leaks",
        "C26": "AI/agent with too much power", "C27": "Hidden instructions in AI rules files", "C28": "MCP servers / extensions",
        "C29": "Security switched off", "C30": "Security headers in code",
    }
    print(f"== Code scan: {os.path.abspath(root)}")
    for cid in sorted(names):
        items = hits.get(cid, [])
        print(f"\n[{cid}] {names[cid]} — {len(items)} lead(s)")
        for h in items[:30]:
            print("   -", h)
        if cid == "C17" and not items:
            print("   - No rate limiting / captcha code found anywhere (check platform settings too)")
    print("\nLeads are starting points: open each file and confirm before marking a check red.")


if __name__ == "__main__":
    main()
