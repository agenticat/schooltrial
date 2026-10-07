# Code review — findings before the hardening work

Record of the review that produced the fixes in commit `480d374`, kept so the reasoning and
the original risk list stay with the repository. Severity is as assessed at the time.

## Critical

1. **`master_panel.html` had no authentication at all.** Anyone who opened it could enumerate
   every tenant, copy each school's `api_key`, and delete any school (cascading to its data).
   → Fixed: Supabase sign-in + `platform_admins` membership check, fail-closed, before any
   tenant data is requested; RLS for the console is in `supabase/schema.sql`.
2. **Stored XSS → school-account takeover.** `admin.html` rendered every database value with
   unescaped `innerHTML` template literals, including `inquiries`, which anonymous visitors can
   write. A payload in a submitted inquiry executed in the owner's session and could read the
   Supabase access token from `localStorage`.
   → Fixed: escape every dynamic value, protocol-check every URL, move row actions to
   `data-*` attributes with delegated handlers. Verified by payload sweeps (suites 1–3).
3. **No visible RLS.** The repository contained no SQL, so tenant separation depended entirely
   on invisible dashboard state. `xyz_school.html` requires anonymous reads of `schools` and
   anonymous inserts to `inquiries`; the easy way to enable that is `using (true)`, which also
   exposes every tenant's `api_key` and `owner_id`.
   → Fixed/addressed: `supabase/schema.sql` (owner-scoped policies, `security definer` helpers,
   a public RPC returning only public columns, insert-only inquiry policy with CHECK
   constraints). **Must be applied to the live project.** See SECURITY-REPORT.md finding B1.
4. **No abuse controls on the public inquiry endpoint** (no captcha, rate limit or honeypot).
   → Partly fixed: honeypot, client-side cooldown, length caps, DB shape constraints. A captcha
   or edge-function rate limit is still recommended.

## Bugs

5. **`master_panel.html` table was a column out of alignment** — four `<th>` but three `<td>`
   per row, so the date rendered under "Credentials", the buttons under "Registration Date",
   and `username` was never displayed. → Fixed.
6. **Login could not work as labelled** — the field said "School Username (e.g. Admin000)" but
   the value was sent as `email` to GoTrue; `schools.username` was never used. → Fixed: the
   form asks for the admin email; the lookup is scoped by `owner_id`.
7. **Silent failures everywhere** — `loadList()` never checked `response.ok`, so an expired
   token or a policy denial rendered "No records yet."; `boot()` in the public page swallowed
   all errors; the inquiry form always claimed success. → Fixed with explicit status handling
   and an error banner; verified in suite 6.
8. **Edits and deletes were scoped by `id` alone** (no `school_id` guard). → Fixed.
9. **Edit state leaked across tabs**; button labels degraded to a bare "Add". → Fixed.
10. **Ordering/limits wrong for some tables** — every list was fetched `created_at.desc&limit=8`,
    which mis-orders fee structures and notices and truncates galleries. → Not fixed (functional,
    not security).
11. **`'★'.repeat(t.rating || 5)`** — a rating of 0 showed five stars and a rating above 5 threw
    `RangeError`, killing the whole testimonials grid. → Fixed with a clamped helper.
12. **Stale session** — `sid`/`sname` were never cleared on failed login and `showDash()` ran
    without validating the token. → Fixed: token validated on boot, session cleared on failure.
13. **`via.placeholder.com` fallbacks** (service retired) → replaced with an inline SVG data URI.
14. Invalid `id2="…"` attributes; `sw()` depended on the implicit global `event`. → Fixed.
15. `secondary_color` collected but unused; "100% Uptime" hardcoded; mobile admin layout
    unusable at small widths. → Not fixed (cosmetic).

## Repository hygiene

16. No README, no schema, no RLS, no seed data, no `.gitignore`, no LICENSE, no deploy config —
    the database could not be recreated from the repository. → Addressed: `README.md`,
    `supabase/schema.sql`, `.gitignore`, `LICENSE`, and the `security-tests/` harness.
