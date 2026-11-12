# The 34 checks

Each check: what it is (plain Hebrew name for the report), how to check it, what decides the color. 🔴 = open hole, 🟠 = risk / partly protected / couldn't fully confirm, 🟢 = protection seen with evidence.

Deep dives for checks C01, C02, C05, C06, C11, C17, C15 (the original "7 doors") — per-stack SQL, Supabase/Firebase/Stripe details and fixes — are in `doors.md`. Read the matching section when a check there is red or orange.

`[scan]` = which script output to look at. `[hosting]` = a check where the hosting layer genuinely helps (see `hosting.md`).

Contents: A. Secrets · B. Data access · C. Login · D. Money · E. Abuse · F. Injection · G. Packages · H. AI features · I. AI dev tools · J. Infrastructure

---

## A. Secrets & what the browser sees

**C01 · קוד ומידע גלוי בדפדפן** `[scan_live, scan_secrets]` `[hosting]`
Secrets, internal URLs, admin logic, source maps, reachable `.env` / `.git` files. 🔴 secret or env/git file reachable; 🟠 source maps public or business logic only in the browser; 🟢 none of these.

**C02 · מפתחות סודיים חשופים** `[scan_secrets, scan_live]`
Secret keys in browser code, in committed `.env`, or in git history (OpenAI, Anthropic, Stripe secret, Supabase service_role, Resend…). Public-by-design keys (Supabase anon, Stripe pk_, Firebase web config) are not leaks. 🔴 any secret exposed now or in history (needs rotation); 🟠 secret in a committed file that never shipped to the browser and repo is private; 🟢 secrets only in server env.

**C03 · הודעות שגיאה שחושפות מידע** `[scan_code, scan_live]`
Stack traces, SQL errors, file paths, raw error objects returned to the client (`Response.json(err)`, `DEBUG=True`). 🔴 live error shows internals; 🟠 code returns raw errors but not confirmed live; 🟢 generic messages.

**C04 · מפתחות AI של המשתמשים שלך** `[scan_code]`
Apps that let users paste their own API keys/tokens (OpenAI, agents, integrations) — real case: Moltbook (2026) exposed ~1.5M agent API keys. Are they encrypted at rest, never returned to the browser after saving, protected by RLS? 🔴 stored plain and readable via API/DB; 🟠 stored plain but access-controlled; 🟢 encrypted / vault, write-only. N/A → 🟢 with note "לא רלוונטי".

## B. Data access

**C05 · מסד נתונים בלי הגנת שורות** `[scan_code SQL, Supabase connector]` — see doors.md door 3.
🔴 a table with user data has RLS off (or Firebase rules `if true`) — including when the migration files show it off (note that the live DB still needs confirming); 🟠 migrations look fine but the live DB couldn't be checked; 🟢 confirmed on the live DB.

**C06 · צפייה ברשומות של אחרים (IDOR)** `[scan_code]` — doors.md door 4.
Real case: Tea app (2025) — 1.1M private messages via an endpoint with no access check. 🔴 loads by ID without owner check; 🟢 owner enforced by query/RLS and tested with two accounts.

**C07 · קבצים פרטיים בתיקייה ציבורית** `[scan_code SQL, connector]`
Storage buckets (Supabase storage, Firebase Storage, S3) that are public but hold private files — real case: Tea app, ~72,000 images incl. ID documents. 🔴 private files in a public bucket / listable; 🟠 public bucket with unclear contents; 🟢 private buckets with per-user policies or signed URLs.

**C08 · ממשק פנימי (API) בלי התחברות** `[scan_code route list]`
Every API route / edge function / server action: does it check who is calling? Pages being locked doesn't protect the API they call. 🔴 a route returning private data or doing writes with no auth; 🟢 all routes check the session (public routes are intentional).

**C09 · משתמש משנה לעצמו הרשאות** `[scan_code, SQL]`
Users able to set their own `role`, `is_admin`, `plan`, `credits` — via an update policy without column protection, or by spreading `req.body` into an update (mass assignment). 🔴 possible; 🟢 those columns writable only by the server.

**C10 · הגנה שקיימת אבל לא עובדת** `[scan_code SQL]`
RLS exists but is meaningless: `using (true)` on private data, update/insert without `with check`, `security definer` functions or views that bypass RLS. Platform scanners often only check that *a* policy exists (Lovable CVE-2025-48757 discussion). 🔴 such a policy on private data; 🟢 policies actually restrict to the owner.

## C. Login & admin

**C11 · עמוד ניהול בלי התחברות** `[scan_code, scan_live]` — doors.md door 5.

**C12 · התחברות שנבדקת רק בדפדפן** `[scan_code]`
Role/login decided in React (`localStorage.isAdmin`, `{isAdmin && …}`, hard-coded admin email in frontend) with no server check — one of Wiz's recurring findings in vibe-coded apps. 🔴 server trusts it; 🟠 UI-only check but server also checks (fine) → 🟢 if server check confirmed.

**C13 · הרשמה פתוחה לאפליקציה פרטית** `[code, live signup page]`
Internal/invite-only apps where anyone can still register (signup endpoint open, SSO not enforced) — real case: Base44 (Wiz, July 2025). 🔴 open signup on an app meant to be private; 🟢 signup closed/domain-restricted/invite-only, or app is meant to be public (then 🟢 N/A).

**C14 · קודים וקישורים שאפשר לנחש** `[scan_code]` `[hosting: endpoint rate limit]`
Reset links, OTPs, invite codes, session tokens from `Math.random`, sequential IDs, short codes without attempt limits, reset tokens that never expire. 🔴 predictable or unlimited guessing; 🟢 crypto-random, expiring, rate-limited (or handled by the auth provider).

## D. Money

**C15 · תשלומים שאפשר לזייף** `[scan_code]` — doors.md door 7.
Webhook signature check, paid access only from verified events, not from `/success?plan=pro`.

**C16 · מחיר שנקבע בדפדפן** `[scan_code]`
Price/amount/discount/quantity rules sent from the browser and trusted (`unit_amount: body.price`). 🔴 yes; 🟢 server uses fixed price IDs.

## E. Abuse

**C17 · הרשמות וקריאות בלי הגבלה** `[scan_code, scan_live]` `[hosting]` — doors.md door 6.
Evidence: the `--burst` test is the strongest — rate limiting kicked in → 🟢 for that endpoint; 30 requests with no slowdown → 🔴/🟠 (real failure). Without a live test, judge from code (rate-limit libraries, captcha, per-user quotas) and say it's from code only. Rate limits set at the host or platform don't show in the code.
Rate limits, captcha, email verification, AI quotas, provider spending caps. A WAF/edge rate limit at the host helps here but doesn't replace per-user quotas in the app.

**C18 · העלאת קבצים בלי בדיקה** `[scan_code]` `[hosting]`
File type/size limits enforced on the server, files stored outside the web root / in a private bucket, no executing uploads, image re-encoding, malware scanning. 🔴 any type/size accepted and publicly served; 🟠 partial; 🟢 limits + private storage. No uploads → 🟢 N/A.

**C19 · השרת נכנס לכל כתובת (SSRF)** `[scan_code]`
"Paste a link and we'll summarize/preview/import it" features that fetch user URLs from the server without blocking internal addresses (169.254.169.254, localhost, 10.x, 192.168.x). 🔴 unrestricted; 🟢 allowlist / blocks private ranges. None → 🟢 N/A.

## F. Injection

**C20 · הזרקת קוד לדף (XSS)** `[scan_code, scan_live CSP]` `[hosting: CSP header / WAF as extra layer]`
`dangerouslySetInnerHTML`, `innerHTML`, `v-html`, markdown with raw HTML, rendering user or AI text as HTML. XSS was the weakness AI models failed most in Veracode's 2025 tests. 🔴 user-controlled text rendered as HTML unsanitized; 🟠 sanitized but no CSP; 🟢 no raw HTML or DOMPurify + CSP.

**C21 · הזרקת פקודות למסד הנתונים (SQL Injection)** `[scan_code]` `[hosting: WAF as extra layer]`
String-built SQL, `$queryRawUnsafe`, `eval`/`new Function` on input, shell commands with input. 🔴 input reaches a query/eval unparameterized; 🟢 parameterized / ORM / no raw queries.

## G. Packages

**C22 · ספריות ישנות עם פרצות ידועות** `[scan_deps]`
`npm audit` / `pip-audit` high or critical with a fix available. 🔴 critical/high in a package used at runtime; 🟠 moderate or dev-only; 🟢 clean.

**C23 · חבילות שה-AI המציא (Slopsquatting)** `[scan_deps]`
Packages that don't exist, were published days ago, or have almost no downloads — AI models invent ~20% of package names in studies and repeat the same fake names, so attackers register them. 🔴 a dependency that doesn't exist or is a fresh lookalike; 🟠 obscure/new package worth a manual look; 🟢 all established.

## H. AI features inside the app

**C24 · השתלטות על הצ'טבוט (Prompt Injection)** `[scan_code]`
Any place user text, uploaded files, emails or fetched web pages go into an LLM. Ask: if that text says "ignore your instructions and…", what's the worst the model can do? Risk grows with tools (DB access, sending email, payments) and with secrets in the system prompt. 🔴 model has write/send/DB tools and processes untrusted text without confirmation or limits, or secrets (keys, discount codes, internal data) are in the system prompt; 🟠 untrusted text reaches a model with no tools — leak/abuse limited; 🟢 no LLM, or tools are read-only + scoped to the user + destructive actions need human confirmation.

**C25 · הצ'טבוט מגלה מידע של אחרים** `[scan_code]`
Chat history, vector search (RAG) or "memory" not filtered by user/tenant; AI answers rendered as HTML; system prompt with private data. 🔴 retrieval/history not scoped per user; 🟢 scoped + output treated as untrusted text.

**C26 · AI או סוכן עם יותר מדי כוח** `[scan_code, ask]` `[hosting: backups]`
AI agents (in the app or the coding agent used to build it) with production DB credentials, delete/shell powers, no backups — real case: Replit agent deleted a production database during a code freeze (July 2025). 🔴 agent/AI holds prod admin credentials and there are no tested backups; 🟠 one of the two, or no backups and you can't tell from the code what credentials the agent has; 🟢 least privilege + separate dev DB + backups with a tested restore.

## I. AI development tools

**C27 · הוראות נסתרות בקבצי ה-AI** `[scan_code]`
`.cursorrules`, `.cursor/rules`, `CLAUDE.md`, `AGENTS.md`, `copilot-instructions.md` with invisible Unicode characters, "don't tell the user", unknown URLs, `curl | sh` — the "Rules File Backdoor" technique (Pillar Security, 2025). 🔴 hidden characters or exfiltration instructions; 🟠 rules copied from unknown sources; 🟢 clean.

**C28 · תוספים ושרתי MCP לא מוכרים** `[scan_code]`
MCP servers and editor extensions run with your permissions. Unpinned `npx -y <pkg>`, unknown publishers, servers with prod credentials. Real cases: a malicious wipe prompt shipped in the Amazon Q VS Code extension (July 2025); the Nx "s1ngularity" supply-chain attack used developers' AI CLIs to hunt for secrets (Aug 2025). 🔴 an MCP package name that doesn't exist on the registry (anyone can register it and it runs on the next start — `scan_deps` checks this), or an unknown/unpinned server with prod secrets; 🟠 unpinned but reputable; 🟢 pinned, known, least-privilege. None → 🟢 N/A.

**C29 · ה-AI כיבה אבטחה כדי "לתקן" שגיאה** `[scan_code git history, scan_live CORS]`
RLS disabled, `using (true)` added, signature checks removed, `rejectUnauthorized:false`, CORS `*`, auth checks commented out — often right after an error message. Only count it here when there's evidence something was *turned off or removed* (a diff that deletes a check, disables RLS, adds `verify=False`/CORS `*`); a weak policy that was weak from the first commit belongs to C10. 🔴 found and still active; 🟠 found in history but later reverted; 🟢 nothing.

## J. Infrastructure & hosting

These are the checks where the hosting provider does real work. They are genuine checks — mark them from evidence like any other.

**C30 · הצפנה (HTTPS) וכותרות אבטחה** `[scan_live]` `[hosting]`
HTTP→HTTPS redirect, valid certificate, HSTS, CSP, X-Content-Type-Options, frame protection, Referrer-Policy. 🔴 no HTTPS; 🟠 HTTPS but key headers missing; 🟢 all present.

**C31 · חומת אש ליישומים (WAF) והגנה מהתקפות עומס (DDoS)** `[scan_live]` `[hosting]`
Is there an edge layer (WAF / CDN / bot management / DDoS mitigation) in front of the app? The WAF probe in `scan_live` is the main evidence: BLOCKED → 🟢; served normally → 🟠 "no firewall blocking common attacks" (counts as a real failure); no live URL → 🟠 לא נבדק. Header signs alone are supporting evidence only. A WAF blocks common SQLi/XSS payloads, bad bots and floods before they reach the app — an extra layer, not a fix for code holes. 🟠 none detected (or can't confirm); 🟢 detected or confirmed by the host. Never 🔴 on its own unless the app is under active abuse.

**C32 · גיבויים ושחזור** `[ask / connector]` `[hosting]`
Automatic, off-site, versioned backups of DB and files, and a restore that was actually tested. Supabase free tier has no point-in-time recovery. 🔴 no backups; 🟠 backups exist, restore never tested; 🟢 automatic + tested.

**C33 · תוכנת שרת ישנה או חשופה** `[scan_live]` `[hosting]`
Server/X-Powered-By headers revealing versions, outdated PHP/Node/OS, open admin panels (phpMyAdmin, cPanel on default ports). 🟠 versions disclosed; 🔴 a known-vulnerable version; 🟢 hidden and current. Managed platforms (Vercel/Netlify) → 🟢 N/A for OS patching.

**C34 · איפה המידע נשמר ומי אחראי עליו** `[ask / config]` `[hosting]`
Where the DB, files and logs physically live (region), which processors receive personal data, and whether that matches the privacy page. Relevant to Israel's Privacy Protection Law / Amendment 13 duties (security, documentation, breach reporting). Israeli law does not generally forbid storing data abroad — don't claim it does. 🟠 unknown or not documented; 🟢 documented and matches the privacy page.
