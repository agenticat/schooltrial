# Security assessment — 2026-10-07

Scope: `admin.html`, `master_panel.html`, `xyz_school.html`, `supabase/schema.sql` at commit
`480d374` plus the changes made during this assessment. Method: 346 adversarial test cases
across 9 suites, plus mutation testing (10 injected vulnerabilities, 10 detected).

## 1. Short answers to the four questions

| Question | Answer |
|---|---|
| **Are they completely secure?** | **No.** Nothing is. Every code-level attack class we tested is now closed (346/346 cases), but four risks remain that are *not* code bugs — the database policies and hosting headers live outside this repo and were not verifiable from here. |
| **Are they using current tech and ideas?** | **Partly.** The security *patterns* are current (context escaping, protocol allow-lists, delegated event handling, fail-closed authorization, `security definer` RPC instead of wide table reads). The *architecture* is dated: a browser holding a database session, secrets inlined in static files, Tailwind's dev CDN in production, no CSP/SRI, no captcha, no build step. See §7. |
| **Are they 99.99% hack proof?** | **No — and that claim is not meaningful for any software.** A number like that implies someone enumerated the attack space; nobody can. What can be said is precisely what §3 and §4 say: these specific classes are closed with evidence, these are open, this is unknown. |
| **Chrome inspection / copying files?** | **Partly tested.** I could not run a real Chrome (no network/browser in this environment), so I executed the real HTML files in a spec-compliant DOM (jsdom) with a mocked Supabase API, and separately reviewed what "copying the files" actually grants (§6). |

## 2. How the testing was done

* The **real files** are loaded unmodified; only `window.fetch` is stubbed, so every request the
  page makes can be inspected and every response controlled (hostile database content included).
* Payload corpora: 82 HTML-injection payloads (OWASP filter-evasion families, mutation-XSS edge
  cases, attribute breakouts, token-exfiltration attempts), 36 URL-scheme payloads
  (`javascript:`, `data:text/html`, control characters, CSS breakouts), 18 PostgREST
  filter-injection values, 10 attribute-breakout payloads.
* Coverage: every text sink (11 admin tables × all fields, 9 public tables, 22 school-column
  fields), every URL sink (logo, banner, photos, gallery, downloads, socials, map iframe),
  every write path, the full auth failure matrix (401/403/404/500, network failure, malformed
  bodies, missing/forged/expired sessions), tenant scoping, and static source rules.
* **Mutation testing** proves the suites can fail: ten real vulnerabilities (escaping removed,
  protocol checks removed, filters unencoded, tenant filter dropped, authorization probe
  bypassed, session re-auth disabled, …) were injected into copies of the pages. All ten were
  caught, and the process found a genuine blind spot in the suite (see §5).

```
cd security-tests && npm install
npm test                  # 346 cases, 9 suites
node mutation-test.js     # 10 injected vulnerabilities → 10 detected
```

## 3. What is verified, with evidence

| Suite | Cases | Result | Proves |
|---|---:|---|---|
| 1. XSS — public website | 47 | ✅ | 82 payloads × every public sink stay inert; payload text is preserved (no silent data loss); nothing executes |
| 2. XSS — admin portal | 126 | ✅ | 82 payloads × all 11 tables (incl. anonymous `inquiries`) render inert; edit forms round-trip exactly, modulo documented HTML value sanitisation; access token never reaches the DOM |
| 3. XSS — super-admin console | 8 | ✅ | hostile tenant names/keys/ids stay inert; `data-*` attributes survive quote, backtick and entity breakouts byte-for-byte |
| 4. URL scheme smuggling | 18 | ✅ | 36 payloads × 12 sinks cannot produce `javascript:`, `data:text/html`, `blob:`, `vbscript:` or CSS breakout; legit URLs still render |
| 5. Query-filter injection | 9 | ✅ | 18 hostile values cannot add/alter a single PostgREST parameter on any read, write, delete, admin lookup or public key lookup |
| 6. Auth & session | 51 | ✅ | fail-closed login matrix; 401/403 → re-login and token wiped; 500 → honest error, session kept; no path claims success without a 2xx; login scoped to `owner_id=eq.<uid>` |
| 7. Authorization — console | 33 | ✅ | no session / non-admin / missing table / probe failure → **zero** tenant queries; admin ops require confirmation |
| 8. Tenant isolation | 10 | ✅ | every read/write carries the session school; a tampered stored id cannot widen a query; inquiry `school_id`/`status` come from the server |
| 9. Static analysis | 44 | ✅ | no inline handlers, no `javascript:` URIs, no `eval`/`Function`/`document.write`, `_blank` links opener-safe, no privileged keys, no plaintext endpoints, no URL-derived data |

## 4. Open findings

### Blocking — depends on configuration outside this repo

**B1. The live database may still have wide-open policies.** Before this work the pages assumed
the anon key could read `schools` (every column, every row) and write the content tables — the
easy way to make that work is `using (true)`. If those policies are still live, then today,
right now, *anyone* holding the anon key (it is inside the published HTML) can read every
school's `api_key` and `owner_id` and can create/edit/delete content rows for any school.
`supabase/schema.sql` fixes this (Step 2 removes the open policies, Steps 3–6 install
owner-scoped ones), **but it has not been applied — I have no network access to your project.**
Check with:

```sql
select tablename, policyname, roles, cmd, qual from pg_policies
where schemaname = 'public' order by tablename, policyname;
```

Any policy with `qual = true` on `schools`, or `cmd = ALL` for role `anon`, is a blocker.

**B2. `master_panel.html` will not open until `platform_admins` exists.** This is deliberate
(fail closed), and the page hands you the exact SQL. Until then the console shows the setup
screen instead of the tenant list.

### Medium — architecture, not a bug

| # | Finding | Why it matters | Fix |
|---|---|---|---|
| M1 | Session token in `localStorage` | any future XSS, or a malicious browser extension, can read it and impersonate the school | Supabase's server-side auth (`@supabase/ssr`, httpOnly cookie) + a thin backend |
| M2 | No captcha on the public inquiry form | honeypot + cooldown reduce spam; a determined script still inserts rows (bounded by the DB check constraint) | Turnstile/hCaptcha or a rate-limited edge function |
| M3 | Three CDN scripts without SRI; Tailwind **Play** CDN | a CDN compromise runs code inside all three pages; the Play CDN is explicitly not for production | self-host/pin bundles with `integrity`, or compile Tailwind at build time |
| M4 | No CSP / `X-Frame-Options` / `Referrer-Policy` | XSS impact and clickjacking are not constrained by policy | set response headers on the host |
| M5 | Public `api_key` and anon key are both inside the published file | by design (the key selects the tenant), but it means the public page *is* a public credential | acceptable **only** with the RLS in `supabase/schema.sql` applied; never let a `service_role` key near these files |
| M6 | No audit trail for destructive admin actions | a school can be deleted with one click and no record | log to a `platform_audit` table |

### Low / hygiene

`limit=8` silently truncates galleries and mis-orders fees/notices; `secondary_color` is
collected but unused; the master panel's stats grid is `grid-cols-3` holding two cards;
no rate limiting on any endpoint; JWT lifetime and email-confirmation settings are Supabase
project settings that were not inspected.

## 5. Regressions and mistakes found *by* this process (disclosed)

* Testing found three real code gaps that were then fixed: the profile form reported
  "Profile Saved!" on a failed PATCH; query-filter values were not percent-encoded; and
  `admin.html` had 11 inline `onclick` tab handlers (now `data-tab` + one delegated listener).
* Testing found a **bug I had introduced myself**: a scripted edit wrote literal `onclick=\"…\"`
  into the markup, which silently broke every tab button. Suite 9 flagged it; it is fixed and
  now covered by real-click tests (suite 6).
* Mutation testing found a **blind spot in the test suite**: nothing asserted that the login
  lookup is scoped to `owner_id`. Four cases were added; the mutation is now caught.

## 6. What "copying the files" gives an attacker

| They get | They do not get | Bounded by |
|---|---|---|
| Supabase project URL, publishable/anon key, the school `api_key`, all business logic | any password, the `service_role` key, other schools' private data | the RLS policies in `supabase/schema.sql`. **This is the whole boundary.** |

## 7. Is this current practice? (architecture vs patterns)

**Current:** context-aware escaping at every sink, URL protocol allow-listing, delegated event
handlers (no inline JS), fail-closed authorization with an explicit admin registry,
`security definer` functions with `search_path` pinned, insert-only policy for public writes,
CHECK constraints shaping anonymous input, and a test suite with mutation verification.

**Dated:** direct browser→Postgres data access; secrets and keys inside static files; no
build step or dependency pinning; Tailwind's dev CDN in production; no captcha, CSP, SRI or
audit log; tenant isolation delegated entirely to the database with no server-side enforcement
layer. The 2026-standard shape is a thin server (or Supabase Edge Functions) that owns the
session cookie, validates input, applies rate limits and captcha, and is the only thing holding
a database key — with these pages reduced to presentation.

## 8. Honest limitations of this assessment

* No live Supabase access: **RLS behaviour, table grants, storage-bucket policies, auth
  settings and JWT lifetime were not executed or verified.** Everything about the database in
  this report is derived from `supabase/schema.sql` and the client code.
* No real browser engine: execution used jsdom. Browser-version-specific parser bugs (mXSS),
  CSP enforcement, extension-based token theft and TLS/host behaviour are outside this harness.
* No hosting/header review (the repo contains no server config), no load/DoS testing, no
  dependency-vulnerability scan of the CDN bundles, no mobile/native clients.
* Payload corpora are large but finite. Passing 346 cases shows these classes are closed; it
  does not prove the absence of unknown classes.
* Until `supabase/schema.sql` is applied and the policies are confirmed live, **B1 remains the
  single highest risk in this system, and it is not something this repository can fix by itself.**
