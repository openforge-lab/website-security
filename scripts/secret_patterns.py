"""Shared secret patterns for scan_secrets.py and scan_live.py."""
import base64
import json
import re

# (name, regex, severity) — severity: "secret" must never be public; "public" is fine if protected.
PATTERNS = [
    ("OpenAI key", r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}", "secret"),
    ("Anthropic key", r"sk-ant-[A-Za-z0-9_\-]{20,}", "secret"),
    ("Stripe secret key", r"(?:sk|rk)_live_[A-Za-z0-9]{20,}", "secret"),
    ("Stripe test secret key", r"(?:sk|rk)_test_[A-Za-z0-9]{20,}", "secret"),
    ("Stripe webhook secret", r"whsec_[A-Za-z0-9]{20,}", "secret"),
    ("Resend key", r"\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}", "secret"),
    ("AWS access key", r"\bAKIA[0-9A-Z]{16}\b", "secret"),
    ("GitHub token", r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})", "secret"),
    ("Slack token", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}", "secret"),
    ("SendGrid key", r"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}", "secret"),
    ("Twilio auth/API key", r"\bSK[0-9a-f]{32}\b", "secret"),
    ("Groq key", r"\bgsk_[A-Za-z0-9]{40,}", "secret"),
    ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "check"),
    ("Private key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "secret"),
    ("Stripe publishable key", r"pk_(?:live|test)_[A-Za-z0-9]{20,}", "public"),
    ("Supabase publishable key", r"sb_publishable_[A-Za-z0-9_\-]{20,}", "public"),
    ("Supabase secret key", r"sb_secret_[A-Za-z0-9_\-]{20,}", "secret"),
]
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")
COMPILED = [(n, re.compile(r), s) for n, r, s in PATTERNS]


PREFIX_RE = re.compile(r"^(sk-ant-|sk-proj-|sk-svcacct-|sk-admin-|sk_live_|sk_test_|rk_live_|rk_test_|pk_live_|pk_test_|whsec_|sb_secret_|sb_publishable_|github_pat_|ghp_|gsk_|re_|SG\.|xox[baprs]-|sk-|eyJ)")


def mask(s):
    """Prefix + 4 characters of the key itself, so the owner can tell which key it is."""
    m = PREFIX_RE.match(s)
    keep = (len(m.group(0)) if m else 0) + 4
    if s.startswith("eyJ"):
        keep = 12
    return s[:keep] + "…" if len(s) > keep + 6 else s[:3] + "…"


def jwt_role(token):
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part)).get("role")
    except Exception:
        return None


def find(text):
    """Yield (name, masked_value, severity, offset)."""
    seen = set()
    for name, rx, sev in COMPILED:
        for m in rx.finditer(text):
            v = m.group(0)
            if name == "OpenAI key" and v.startswith("sk-ant-"):
                continue
            if (name, v) in seen:
                continue
            seen.add((name, v))
            yield name, mask(v), sev, m.start()
    for m in JWT_RE.finditer(text):
        v = m.group(0)
        role = jwt_role(v)
        if role == "service_role":
            yield "Supabase SERVICE_ROLE key (bypasses all security!)", mask(v), "secret", m.start()
        elif role == "anon":
            yield "Supabase anon key", mask(v), "public", m.start()
