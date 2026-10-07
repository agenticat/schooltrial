# Schooltrial — multi-tenant school website platform

Three static pages that read and write a Supabase (Postgres + PostgREST + GoTrue) backend
directly from the browser. No build step, no server of your own.

| File | Who uses it | Auth |
|---|---|---|
| `master_panel.html` | Platform operator (super admin) | Supabase Auth + membership of `platform_admins` |
| `admin.html` | School owner / staff | Supabase Auth (email + password), scoped to their own school |
| `xyz_school.html` | The public | none — reads one school's public data, submits admission inquiries |

```
master_panel.html ──┐
                    │   https://xlmsgtxyrlovjobwvdom.supabase.co
admin.html ─────────┼──▶  PostgREST  ──▶  Postgres (RLS enforced)
                    │         │
xyz_school.html ────┘         └── GoTrue (auth)
```

## Data model

`schools` is the tenant root (one row per school, `owner_id` → `auth.users.id`, plus profile,
branding, contact and social columns). Ten child tables hang off it by `school_id`:

`notices`, `toppers`, `galleries`, `facilities`, `downloads`, `fee_structures`,
`staff_members`, `achievements`, `testimonials`, `inquiries`

`inquiries` is the only table the public may write to (admission form). Every child table is
read by the public website and managed by that school's admin portal.

## Setup

1. **Apply the database schema and policies** — open the Supabase SQL editor and run
   [`supabase/schema.sql`](supabase/schema.sql) in one go. It creates `platform_admins`,
   the `is_platform_admin()` / `owns_school()` helpers, owner-scoped policies for the nine
   content tables, an insert-only policy for `inquiries`, the public lookup RPC, and it
   **removes the wide-open prototype policies** that let anyone with the anon key read every
   tenant row.
2. **Promote your operator account.** Sign in at `master_panel.html`; if you are not yet an
   admin it shows a setup screen with the exact SQL (your `auth.uid`) to run.
3. **Onboard a school** from the master panel: institution name + the owner's Supabase Auth
   UID. The generated `api_key` identifies that school's public website.
4. **Publish the website** by copying `xyz_school.html` and setting `SCHOOL_API_KEY` (top of
   the file) to that school's key.

## Security model

* The **public site** never reads `schools` directly when the RPC exists — it calls
  `public_school_by_key(key)`, a `security definer` function that returns only public columns.
  Anonymous writes are limited to the inquiry insert policy, with shape/length constraints.
* The **admin portal** authenticates with Supabase Auth, keeps the session token in
  `localStorage`, validates it on boot, and bounces to the login screen on any 401/403.
  Every read, update and delete is filtered by `school_id`.
* The **master panel** verifies the signed-in user against `platform_admins` *before*
  requesting tenant data, and fails closed (no session, unknown admin, missing table,
  network error → no data, no console).
* All database values are HTML-escaped before they reach `innerHTML`, and every URL from the
  database is protocol-checked (`http:`/`https:`/relative only). Row actions use `data-*`
  attributes with delegated listeners — there are no inline event handlers anywhere.

See [`SECURITY-REPORT.md`](SECURITY-REPORT.md) for the full assessment, what is verified by
tests, and the remaining (mostly architectural) risks.

## Security test suite

```bash
cd security-tests
npm install
npm test                 # all suites
npm test -- --only 04    # a single suite
node mutation-test.js    # prove the suites catch injected vulnerabilities
```

Nine suites (346 cases) boot the real HTML files in a DOM with a mocked Supabase API and
fire generated attack payloads through every sink: XSS across all 11 content tables and 22
school fields, URL-scheme smuggling, PostgREST filter injection, the auth/session failure
matrix, tenant scoping, and static source rules. `mutation-test.js` re-introduces real
vulnerabilities into copies of the pages and fails if a suite does not notice.

`node_modules` and `sec-results.json` are gitignored.

## Known limitations

These are properties of the architecture, not bugs — they are listed with fixes in the report:

* The browser holds the database session; a `localStorage` token is reachable by any future
  XSS. Server-side sessions (httpOnly cookie) remove that class entirely.
* Tenant isolation is enforced by Postgres RLS. If the policies in `supabase/schema.sql` are
  not applied, the client cannot compensate for them.
* The public inquiry form has a honeypot and a client-side cooldown, but no captcha —
  an attacker can still insert spam rows (bounded in shape by the DB constraint).
* Third-party CDN scripts (Tailwind Play CDN, Font Awesome) load without SRI; the Tailwind
  Play CDN is explicitly not for production. Self-host the bundles for anything real.
* No CSP / `X-Frame-Options` / `Referrer-Policy` response headers are configured here; they
  belong on the host.

## License

MIT — see [LICENSE](LICENSE).
