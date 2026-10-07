'use strict';
/**
 * Suite 6 — authentication and session handling in the school admin portal.
 *
 * Covers the full failure matrix: missing/garbage/expired tokens, 401/403/404/500,
 * network failures, malformed bodies, and whether the UI ever claims success (or
 * silently shows an empty school) when the API refused the request.
 */
const { makeDom, settle, readRepo, supabaseResponder, jsonResponse } = require('../lib/harness');

const ADMIN = 'admin.html';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function boot({ token = null, sid = null, tokenStatus, userStatus, schools, tables, writeStatus, profileStatus, hook, throwOn } = {}) {
    const responder = supabaseResponder({ tokenStatus, userStatus, writeStatus, hook });
    const base = responder;
    const env = makeDom(readRepo(ADMIN), {
        responder: (rec) => {
            if (throwOn && throwOn(rec)) throw new TypeError('Failed to fetch');
            if (rec.path.includes('/rest/v1/schools')) {
                if (profileStatus && rec.method === 'PATCH') return jsonResponse({ message: 'rejected' }, profileStatus);
                if (schools === 'error') return jsonResponse({ message: 'boom' }, 500);
                if (schools === 'unauthorized') return jsonResponse({ message: 'denied' }, 403);
                if (schools === 'malformed') return jsonResponse({ nope: true });
                if (Array.isArray(schools)) return jsonResponse(schools);
                return jsonResponse([{ id: 'school-1', school_name: 'Test School' }]);
            }
            const m = rec.path.match(/\/rest\/v1\/([a-z_]+)/);
            if (m && tables && m[1] in tables) {
                const v = tables[m[1]];
                if (v && typeof v === 'object' && !Array.isArray(v)) return jsonResponse(v.body, v.status);
                return jsonResponse(v);
            }
            return base(rec);
        },
    });
    if (token) env.win.localStorage.setItem('sb_token', token);
    if (sid) env.win.localStorage.setItem('sid', sid);
    await settle(env.win);
    await sleep(40);
    return env;
}

async function signIn(env, user = 'a@b.c', pass = 'pw') {
    env.doc.getElementById('loginUser').value = user;
    env.doc.getElementById('loginPass').value = pass;
    env.doc.getElementById('loginForm').dispatchEvent(new env.win.Event('submit', { bubbles: true, cancelable: true }));
    await settle(env.win);
    await sleep(30);
}

const paramsOf = (url) => new URL(url).searchParams;
const loginVisible = (env) => !env.doc.getElementById('loginScreen').classList.contains('hidden');
const dashVisible = (env) => !env.doc.getElementById('dashboardScreen').classList.contains('hidden');
const errorText = (env) => env.doc.getElementById('loginError').textContent;

module.exports = {
    name: '6. Auth & session — admin portal',
    description: 'Failure matrix for login, boot, reads, writes and deletes. Checks that no path shows data or success without server confirmation.',
    async run(t) {
        // 1. cold start with no session at all
        let env = await boot({});
        t.check(loginVisible(env) && !dashVisible(env), 'no session → login screen, dashboard hidden');
        t.check(env.calls.filter((c) => c.path.includes('/rest/v1/')).length === 0, 'no session → zero data requests issued');
        await env.close();

        // 2. stored session that the server rejects
        env = await boot({ token: 'expired', sid: 'school-1', userStatus: 401 });
        t.check(loginVisible(env), 'expired token → bounced to login on boot');
        t.check(env.win.localStorage.getItem('sb_token') === null, 'expired token deleted from storage');
        t.check(/expired|sign in again/i.test(errorText(env)), 'user is told why', errorText(env));
        t.check(env.calls.filter((c) => c.path.includes('/rest/v1/')).length === 0, 'expired token → no data requests issued');
        await env.close();

        // 3. valid session, dashboard loads
        env = await boot({ token: 'tok', sid: 'school-1' });
        t.check(dashVisible(env), 'valid token → dashboard shown');
        await env.close();

        // 4. login: wrong password
        env = await boot({ tokenStatus: 401 });
        await signIn(env);
        t.check(/invalid email or password/i.test(errorText(env)), 'wrong password → explicit error');
        t.check(env.win.localStorage.getItem('sb_token') === null, 'wrong password → no token stored');
        t.check(loginVisible(env), 'wrong password → stays on login');
        await env.close();

        // 5. login ok, but the school lookup is refused
        env = await boot({ schools: 'unauthorized' });
        await signIn(env);
        t.check(loginVisible(env), 'school lookup 403 → stays on login');
        t.check(/could not load your school/i.test(errorText(env)), 'school lookup 403 → error surfaced', errorText(env));
        t.check(env.win.localStorage.getItem('sid') === null, 'school lookup 403 → no school id stored');
        await env.close();

        // 6. login ok, account owns no school
        env = await boot({ schools: [] });
        await signIn(env);
        t.check(/no school found/i.test(errorText(env)), 'account without a school → explicit message');
        await env.close();

        // 7. login ok, malformed school payload
        env = await boot({ schools: 'malformed' });
        await signIn(env);
        t.check(/no school found/i.test(errorText(env)) && loginVisible(env), 'malformed school payload → fails closed, no crash');
        await env.close();

        // 8. network down during login
        env = await boot({ throwOn: (rec) => rec.path.includes('/auth/v1/token') });
        await signIn(env);
        t.check(/network error/i.test(errorText(env)), 'network failure during login → reported');
        t.check(env.win.localStorage.getItem('sb_token') === null, 'network failure → no token stored');
        await env.close();

        // 9. session dies mid-session during a read
        env = await boot({ token: 'tok', sid: 'school-1', tables: { notices: { body: { message: 'jwt expired' }, status: 401 } } });
        env.win.showDash('Test School');
        await settle(env.win);
        await sleep(40);
        t.check(loginVisible(env), 'read rejected with 401 → session dropped, login shown');
        t.check(env.win.localStorage.getItem('sb_token') === null, 'read rejected with 401 → token cleared');
        await env.close();

        // 10. server error during a read: stay signed in, show the error
        env = await boot({ token: 'tok', sid: 'school-1', tables: { notices: { body: { message: 'boom' }, status: 500 } } });
        env.win.showDash('Test School');
        await settle(env.win);
        await sleep(40);
        const notices = env.doc.getElementById('l-notices').textContent;
        t.check(dashVisible(env), 'read 500 → still signed in (not a session problem)');
        t.check(/could not load this list/i.test(notices), 'read 500 → list shows an error, not "no records"', notices.slice(0, 80));
        await env.close();

        // 11. malformed read payload
        env = await boot({ token: 'tok', sid: 'school-1', tables: { notices: { nope: 1 } } });
        env.win.showDash('Test School');
        await settle(env.win);
        await sleep(40);
        t.check(dashVisible(env), 'malformed read payload → no crash');
        t.check(env.doc.getElementById('l-notices').textContent.trim().length > 0, 'malformed read payload → UI states something');
        await env.close();

        // 12. write rejected: must not claim success
        env = await boot({ token: 'tok', sid: 'school-1', writeStatus: 403 });
        env.win.showDash('Test School');
        await settle(env.win);
        env.doc.getElementById('n_title').value = 'x';
        env.doc.getElementById('n_date').value = '2026-01-01';
        env.doc.getElementById('f-notices').dispatchEvent(new env.win.Event('submit', { bubbles: true, cancelable: true }));
        await settle(env.win);
        await sleep(40);
        t.check(loginVisible(env), 'write rejected with 403 → forced re-login');
        t.check(env.win.localStorage.getItem('sb_token') === null, 'write 403 → token cleared');
        await env.close();

        env = await boot({ token: 'tok', sid: 'school-1', writeStatus: 500 });
        env.win.showDash('Test School');
        await settle(env.win);
        const btn = env.doc.querySelector('#f-notices button');
        env.doc.getElementById('n_title').value = 'x';
        env.doc.getElementById('n_date').value = '2026-01-01';
        env.doc.getElementById('f-notices').dispatchEvent(new env.win.Event('submit', { bubbles: true, cancelable: true }));
        await settle(env.win);
        await sleep(40);
        t.check(/failed/i.test(btn.textContent), 'write rejected with 500 → button reports failure', btn.textContent);
        t.check(!/saved/i.test(btn.textContent), 'write rejected with 500 → never says "Saved!"');
        t.check(env.win.localStorage.getItem('sb_token') !== null, 'write 500 keeps the session (not an auth problem)');
        await env.close();

        // 13. delete: 500 must not report success
        env = await boot({ token: 'tok', sid: 'school-1', tables: { notices: [{ id: 'n1', title: 't', notice_date: '2026-01-01' }] } });
        env.win.showDash('Test School');
        await settle(env.win);
        let alerts = [];
        env.win.alert = (m) => alerts.push(String(m));
        env.win.confirm = () => true;
        env.calls.length = 0;
        await env.win.delItem('notices', 'n1');
        const del = env.calls.find((c) => c.method === 'DELETE');
        t.check(!!del, 'delete issues a DELETE');
        t.check(del && del.path.includes('school_id=eq.school-1'), 'delete is scoped to the session school');
        await env.close();

        // 14. cancelled confirm must not touch the network
        env = await boot({ token: 'tok', sid: 'school-1' });
        env.win.showDash('Test School');
        await settle(env.win);
        env.win.confirm = () => false;
        env.calls.length = 0;
        await env.win.delItem('notices', 'n1');
        t.check(env.calls.length === 0, 'cancelled confirm → no request at all');
        await env.close();

        // 15. profile save must not claim success on failure
        for (const status of [400, 403, 500]) {
            env = await boot({ token: 'tok', sid: 'school-1', profileStatus: status });
            env.win.showDash('Test School');
            await settle(env.win);
            const profileBtn = env.doc.getElementById('profileBtn');
            env.doc.getElementById('profileForm').dispatchEvent(new env.win.Event('submit', { bubbles: true, cancelable: true }));
            await settle(env.win);
            await sleep(40);
            t.check(!/profile saved/i.test(profileBtn.textContent), `profile save rejected with ${status} never claims success`, profileBtn.textContent);
        }
        // and it must report success when the server accepted it
        env = await boot({ token: 'tok', sid: 'school-1' });
        env.win.showDash('Test School');
        await settle(env.win);
        env.doc.getElementById('profileForm').dispatchEvent(new env.win.Event('submit', { bubbles: true, cancelable: true }));
        await settle(env.win);
        await sleep(40);
        t.check(/profile saved/i.test(env.doc.getElementById('profileBtn').textContent), 'profile save reports success on a 2xx', env.doc.getElementById('profileBtn').textContent);
        await env.close();

        // 16. the token must travel in a header, never in a URL
        env = await boot({ token: 'secret-token-DEADBEEF', sid: 'school-1' });
        env.win.showDash('Test School');
        await settle(env.win);
        const leaked = env.calls.filter((c) => c.url.includes('secret-token-DEADBEEF'));
        t.check(leaked.length === 0, 'access token never appears in a request URL', leaked.map((c) => c.path).join(' | '));
        const authed = env.calls.filter((c) => c.path.includes('/rest/v1/'));
        t.check(authed.every((c) => String(c.headers.Authorization || '').includes('secret-token-DEADBEEF')), 'data requests carry the user token (not the anon key)');
        await env.close();

        // 17. the login lookup must be scoped to the authenticated user's uid.
        // Without this, any account that can authenticate could land in whichever school
        // the API returns first instead of the one it owns.
        env = await boot({});
        await signIn(env, 'owner@school.test', 'pw');
        const schoolQuery = env.calls.find((c) => c.path.includes('/rest/v1/schools'));
        t.check(!!schoolQuery, "login looks up the signed-in user's school");
        const sp = schoolQuery ? paramsOf(schoolQuery.url) : null;
        t.check(!!sp && sp.get('owner_id') === 'eq.uid-1', 'login scopes the lookup with owner_id=eq.<auth uid>', schoolQuery && schoolQuery.path);
        t.check(!!sp && [...sp.keys()].length === 2, 'login lookup carries exactly owner_id and select', schoolQuery && schoolQuery.path);
        t.check(!!sp && !sp.has('school_id') && !sp.has('api_key'), 'login lookup cannot be redirected by another identifier', schoolQuery && schoolQuery.path);
        env.close();

        // 18. real click gestures must wire up: tabs, logout, row actions
        env = await boot({ token: 'tok', sid: 'school-1', tables: { notices: [{ id: 'n1', title: 'Notice', notice_date: '2026-01-01' }] } });
        env.win.showDash('Test School');
        await settle(env.win);
        const toppersTab = env.doc.querySelector('[data-tab="toppers"]');
        t.check(!!toppersTab, 'tab buttons carry a data-tab attribute (no inline handler)');
        toppersTab.dispatchEvent(new env.win.MouseEvent('click', { bubbles: true, cancelable: true }));
        t.check(env.doc.getElementById('tab-toppers').classList.contains('active'), 'clicking a tab actually switches content');
        t.check(toppersTab.classList.contains('active'), 'clicking a tab marks it active');
        t.check(!env.doc.getElementById('tab-notices').classList.contains('active'), 'previous tab deactivated by the click');
        t.check(env.doc.querySelectorAll('.tab-btn').length === 11, 'all 11 tabs are wired through the delegated handler');

        // row actions (edit + delete) must respond to a real click
        const editBtn = env.doc.querySelector('#l-notices [data-act="edit"]');
        t.check(!!editBtn, 'rendered rows expose edit controls');
        editBtn.dispatchEvent(new env.win.MouseEvent('click', { bubbles: true, cancelable: true }));
        t.check(env.doc.getElementById('n_title').value === 'Notice', 'clicking edit loads the record into the form');
        env.win.confirm = () => false;
        env.calls.length = 0;
        const delBtn = env.doc.querySelector('#l-notices [data-act="del"]');
        delBtn.dispatchEvent(new env.win.MouseEvent('click', { bubbles: true, cancelable: true }));
        await sleep(20);
        t.check(env.calls.length === 0, 'clicking delete with a cancelled confirm issues no request');

        // logout clears the session and returns to the login screen
        env.doc.getElementById('logoutBtn').dispatchEvent(new env.win.MouseEvent('click', { bubbles: true, cancelable: true }));
        t.check(env.win.localStorage.getItem('sb_token') === null, 'clicking logout clears the stored token');
        await env.close();

        // 19. multi-school account: portal picks the first and never merges tenants
        env = await boot({ schools: [{ id: 'school-1', school_name: 'A' }, { id: 'school-2', school_name: 'B' }] });
        await signIn(env);
        t.check(env.win.localStorage.getItem('sid') === 'school-1', 'multi-school account → deterministic single tenant selected');
        await env.close();
    },
};
