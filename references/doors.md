# The 7 doors — deep dives

Mapping to checks.md: Door 1 = C01 · Door 2 = C02 · Door 3 = C05/C07/C10 · Door 4 = C06 · Door 5 = C11 · Door 6 = C17 · Door 7 = C15

Contents: 1 Code visible · 2 Secret keys · 3 Database RLS · 4 Other people's records · 5 Admin · 6 Signup abuse · 7 Payment webhooks

---

## Door 1 — Code visible in the browser

**Why it matters:** everything sent to the browser is public. Right-click → Inspect shows it. Anything private there is already leaked.

**Look for**
- Built JS bundles (`dist/`, `.next/static`, `build/`) and source maps (`*.js.map`) served in production — source maps reveal the full original code.
- Env vars exposed to the client: `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `EXPO_PUBLIC_*`, `PUBLIC_*`. Any secret behind these prefixes is public.
- Files reachable over HTTP: `/.env`, `/.env.local`, `/.git/config`, `/config.json`, `/backup.sql`, `/firebase.json`. `scripts/scan_live.py` probes these.
- Business logic only in the frontend: price calculation, "is this user pro?", "is this user admin?" decided in the browser.
- Hard-coded test credentials, internal API URLs, debug endpoints.

**Confirm:** fetch the live JS and search it; check what the server returns for the probe paths (200 with content = exposed).

**Fix:** move secrets and decisions to the server (API route, server action, edge function). Disable production source maps (`productionBrowserSourceMaps: false` in Next.js; `build.sourcemap: false` in Vite) unless uploaded privately to an error tracker. Block dotfiles at the host.

---

## Door 2 — Exposed secret / AI keys

**Why it matters:** a stolen key means someone uses your paid account — AI calls, emails, SMS — and you get the bill. Bots scrape GitHub for keys within minutes.

**Secret (must never be in frontend or git):**
| Prefix / pattern | Service |
|---|---|
| `sk-`, `sk-proj-` | OpenAI |
| `sk-ant-` | Anthropic |
| `sk_live_`, `rk_live_` | Stripe secret / restricted |
| `whsec_` | Stripe webhook secret |
| JWT with `"role":"service_role"` | Supabase service role (bypasses RLS!) |
| `re_` | Resend |
| `AC…` + auth token, `SK…` | Twilio |
| `AIza…` used for Gemini/Maps server APIs | Google (check key restrictions) |
| `xoxb-`, `ghp_`, `github_pat_`, `AKIA` | Slack, GitHub, AWS |
| `-----BEGIN PRIVATE KEY-----` | any private key |

**Public by design (not a leak — but check the protection behind it):** Supabase anon/publishable key (needs RLS, door 3), Stripe `pk_live_` publishable key, Firebase web config `apiKey` (needs security rules), Google Maps browser key (needs HTTP referrer restriction).

**Look for:** frontend files, client env prefixes (door 1), `.env` committed to git (`git log --all -p -- .env* | head`), keys in git history even if deleted (`git log -p -S 'sk-'`).

**Fix:** call the provider from server code only; put the key in server env / edge-function secrets. **Rotate every key that was ever exposed** (in code or in git history) — deleting it from code doesn't un-leak it. Set spending limits / usage alerts at the provider.

---

## Door 3 — Database without row-level security

**Why it matters:** with Supabase/Firebase the browser talks to the database directly using a public key. The only thing stopping a visitor from downloading every table is RLS / security rules.

**Supabase — check (SQL, read-only):**
```sql
-- tables in exposed schemas and whether RLS is on
select schemaname, tablename, rowsecurity from pg_tables where schemaname in ('public','storage') order by 1,2;
-- the policies themselves
select schemaname, tablename, policyname, roles, cmd, qual, with_check from pg_policies order by 1,2;
-- storage buckets
select id, public from storage.buckets;
```
Red flags: `rowsecurity = false` on any table with user data; policies whose `qual` is `true` for `anon`/`authenticated` on private data; `insert/update` without `with_check`; users able to update their own `role`/`is_admin`/`plan`/`credits` column; public buckets holding private files; views or `security definer` functions that bypass RLS; the Supabase advisors (if a connector exists, run `get_advisors` for security).

Live confirmation (own project only): with the anon key from the site, `GET https://<ref>.supabase.co/rest/v1/<table>?select=*&limit=1` with headers `apikey` and `Authorization: Bearer <anon>`. Rows from a private table = open door. Report row count, not the data.

**Firebase:** read `firestore.rules` / `database.rules.json` / `storage.rules`. Red flags: `allow read, write: if true;`, `if request.auth != null` alone on shared collections (any logged-in user reads everyone's data), test-mode rules with an expiry date.

**Own backend (Postgres/Prisma/Mongo via API):** the door is the API — check each query filters by the authenticated user (see door 4).

**Watch for the anon client on the server:** server code (pages, API routes, webhooks) that imports the same browser Supabase client (`createClient(url, ANON_KEY)` with no user session) runs as an anonymous visitor. Once RLS is on, those queries return nothing or silently fail — e.g. a webhook that "upgrades" a user updates zero rows. The fix is RLS **plus** the right client on the server: a session-aware client (`@supabase/ssr` `createServerClient` with cookies) for user requests, and the service-role key — server-only — for trusted jobs like verified webhooks.

**Fix:** enable RLS on every table; policies like `using (auth.uid() = user_id)` and `with check (auth.uid() = user_id)`; protect privileged columns (separate table or trigger/column privileges); make private buckets private with per-user path policies. Never use the service_role key in the browser.

---

## Door 4 — Other people's records (IDOR)

**Why it matters:** being logged in isn't enough. If `/invoice/1042` shows invoice 1042 to whoever asks, any customer can read every other customer's data by counting.

**Look for:** every route, API endpoint, server action or query that takes an ID from the URL/body (`params.id`, `req.query.id`, `.eq('id', id)`, `findUnique({ where: { id } })`) — does it also check ownership (`user_id = current user`, org membership) on the server or via RLS? Sequential numeric IDs make it worse but UUIDs alone are not protection. Also check update and delete, not just read; file downloads; signed URLs; exports.

**Confirm (live):** with test account A, open one of A's records; copy the URL/request; log in as test account B and replay it. Should get 403/404/empty. Also try logged out.

**Note:** if the page loads data with the anon Supabase client and no session (see door 3), RLS alone will just make the page empty for everyone — switch to a session-aware server client so RLS knows who's asking.

**Fix:** enforce ownership in the query itself (`where id = $1 and user_id = $currentUser`) or by RLS; return 404 for not-yours.

---

## Door 5 — Admin without login

**Why it matters:** an admin page that only "hides" behind its URL lets anyone delete users, refund orders or export data.

**Look for:** routes/folders named `admin`, `dashboard`, `internal`, `manage`, `backoffice`, `/api/admin/*`; middleware that protects pages but not the API routes they call; role checks done only in React (`{isAdmin && <AdminPanel/>}`); role read from localStorage or from a user-editable profile column; admin determined by a hard-coded email compared in the frontend.

**Confirm (live):** open `/admin` (and found admin API routes) logged out and as a normal test user → must redirect / 401 / 403, and the API must refuse even if the page shell loads.

**Fix:** server-side check on every admin page *and* admin API: logged in + role from a trusted source (DB table only admins can write, or auth custom claims). Deny by default.

---

## Door 6 — Unlimited signups / abuse

**Why it matters:** a script can open thousands of accounts; each gets free credits; your AI/email bill explodes overnight and your dashboard looks like you "went viral".

**Look for:** rate limiting on signup, login, password reset, and on expensive endpoints (AI calls, email/SMS sending, file uploads); email verification before free credits; CAPTCHA / bot protection (Turnstile, hCaptcha, reCAPTCHA, Supabase Auth captcha); per-user and global caps on AI usage; whether AI calls go through your server (so you can limit them) or straight from the browser; provider spending limits; disposable-email blocking (nice to have).

Supabase: Auth → rate limits and "Confirm email" setting; check edge functions enforce per-user quotas.

**Don't** hammer the live site to "prove" it. Reading the code/settings is enough; at most a handful of requests.

**Fix:** turn on email confirmation and captcha; add rate limits (e.g. Upstash ratelimit, Vercel/Cloudflare WAF rules, middleware); grant free credits only after verification; server-side per-user daily quota; hard spending cap at the AI provider.

---

## Door 7 — Payment webhooks not verified

**Why it matters:** the payment provider tells your app "this person paid" through a webhook. If the app doesn't verify the signature, anyone can send a fake "payment succeeded" and get the paid plan forever.

**Look for (Stripe):** the webhook handler uses `stripe.webhooks.constructEvent(rawBody, sig, STRIPE_WEBHOOK_SECRET)` (or `constructEventAsync` in edge runtimes) with the **raw** body — `JSON.parse` / `req.json()` before verifying breaks it, and code that skips verification when it fails is still open. Lemon Squeezy / Paddle / PayPal: their HMAC signature check. Also:
- Paid access granted from a success-page URL (`/success?plan=pro`, `session_id` trusted without fetching it from Stripe server-side).
- Plan/credits column the user can update themselves (ties to door 3).
- Price or amount sent from the browser and trusted by the server — prices should come from server-side price IDs.
- Duplicate events not handled (idempotency) — minor.
- The handler updates the database with the anon Supabase client — under RLS this usually matches zero rows, so real customers may not get upgraded. After verifying the signature, use a server-only service-role client.

**Confirm (live, own app):** sending an unsigned test POST to the webhook URL should return 400. Never send a fake event that would actually grant access on production; read the code instead if unsure.

**Fix:** verify the signature with the webhook secret on the raw body; reject on failure; grant access only from verified events; keep prices on the server.
