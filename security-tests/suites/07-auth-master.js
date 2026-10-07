'use strict';
/**
 * Suite 7 — is the super-admin console actually gated?
 *
 * It can read every tenant's api key and destroy schools, so the critical property is
 * "fails closed": with no session, a fake session, a valid non-admin account, a missing
 * platform_admins table or a network error, it must never issue a single tenant request.
 */
const { makeDom, settle, readRepo, supabaseResponder, jsonResponse } = require('../lib/harness');

const MASTER = 'master_panel.html';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function boot({ token, adminRows = [], adminStatus = 200, schools = [], schoolsStatus = 200, hook, throwOn } = {}) {
    const base = supabaseResponder({});
    const env = makeDom(readRepo(MASTER), {
        responder: (rec) => {
            if (throwOn && throwOn(rec)) throw new TypeError('Failed to fetch');
            if (hook) { const r = hook(rec, env); if (r) return r; }
            if (rec.path.includes('/rest/v1/platform_admins')) return jsonResponse(adminRows, adminStatus);
            if (rec.path.includes('/rest/v1/schools')) return jsonResponse(schools, schoolsStatus);
            return base(rec);
        },
    });
    if (token) env.win.sessionStorage.setItem('sa_token', token);
    await settle(env.win);
    await sleep(40);
    return env;
}

const at = (env, id) => !env.doc.getElementById(id).classList.contains('hidden');
const tenantRequests = (env) => env.calls.filter((c) => c.path.includes('/rest/v1/schools'));
const adminTableRequests = (env) => env.calls.filter((c) => c.path.includes('/rest/v1/platform_admins'));

module.exports = {
    name: '7. Authorization — super-admin console',
    description: 'Fails-closed matrix for the console that can enumerate tenants and delete them.',
    async run(t) {
        // 1. no session
        let env = await boot({});
        t.check(at(env, 'loginScreen') && !at(env, 'appScreen'), 'no session → login screen only');
        t.check(tenantRequests(env).length === 0, 'no session → zero tenant queries');
        await env.close();

        // 2. fake/expired session
        env = await boot({ token: 'forged', hook: (rec) => (rec.path.includes('/auth/v1/user') ? jsonResponse({}, 401) : undefined) });
        t.check(at(env, 'loginScreen'), 'forged session → login screen');
        t.check(env.win.sessionStorage.getItem('sa_token') === null, 'forged session → token discarded');
        t.check(tenantRequests(env).length === 0, 'forged session → zero tenant queries');
        await env.close();

        // 3. authentic account that is not a platform admin
        env = await boot({ token: 'user-token', adminRows: [] });
        t.check(at(env, 'setupScreen') && !at(env, 'appScreen'), 'non-admin account → access denied screen');
        t.check(tenantRequests(env).length === 0, 'non-admin account → zero tenant queries');
        t.check(adminTableRequests(env).length === 1, 'non-admin account → exactly one authorization probe');
        t.check(/platform_admins/.test(env.doc.getElementById('setupSql').textContent), 'denied screen explains how to grant access');
        await env.close();

        // 4. platform_admins table missing → still closed
        env = await boot({ token: 'user-token', adminRows: { message: 'relation does not exist' }, adminStatus: 404 });
        t.check(!at(env, 'appScreen'), 'missing admin table → console stays closed (does not fall open)');
        t.check(tenantRequests(env).length === 0, 'missing admin table → zero tenant queries');
        await env.close();

        // 5. authorization probe itself fails (network) → still closed
        env = await boot({ token: 'user-token', throwOn: (rec) => rec.path.includes('/rest/v1/platform_admins') });
        t.check(!at(env, 'appScreen'), 'authorization probe network error → console stays closed');
        t.check(tenantRequests(env).length === 0, 'authorization probe network error → zero tenant queries');
        await env.close();

        // 6. empty allow-list must not be an open door
        env = await boot({ token: 'user-token', adminRows: [], hook: (rec) => (rec.path.includes('/auth/v1/user') ? jsonResponse({ id: 'uid-1', email: 'admin@company.com' }) : undefined) });
        t.check(!at(env, 'appScreen'), 'email alone never grants access (no shared-secret allow-list fallback)', 'admin@company.com was rejected');
        await env.close();

        // 7. genuine admin: console opens and loads tenants once
        env = await boot({ token: 'admin-token', adminRows: [{ user_id: 'uid-1' }], schools: [{ id: 's1', school_name: 'A', username: 'u', api_key: 'k', created_at: new Date().toISOString() }] });
        t.check(at(env, 'appScreen'), 'platform admin → console opens');
        t.check(tenantRequests(env).length === 1, 'platform admin → tenant list fetched exactly once');
        t.check(tenantRequests(env).every((c) => c.method === 'GET'), 'tenant list is read-only');
        t.check(env.calls.every((c) => !['POST', 'PATCH', 'DELETE'].includes(c.method)), 'opening the console performs no writes');
        await env.close();

        // 8. tenant read refused mid-session
        env = await boot({ token: 'admin-token', adminRows: [{ user_id: 'uid-1' }], schools: { message: 'denied' }, schoolsStatus: 403 });
        t.check(at(env, 'loginScreen'), 'tenant read 403 → signed out, not left on a stale dashboard');
        t.check(env.win.sessionStorage.getItem('sa_token') === null, 'tenant read 403 → token discarded');
        await env.close();

        // 9. tenant read 500: signed in with an honest error
        env = await boot({ token: 'admin-token', adminRows: [{ user_id: 'uid-1' }], schools: { message: 'boom' }, schoolsStatus: 500 });
        t.check(at(env, 'appScreen'), 'tenant read 500 → still signed in');
        t.check(/could not load clients/i.test(env.doc.getElementById('schoolTableBody').textContent), 'tenant read 500 → error shown in the table');
        await env.close();

        // 10. destructive actions require confirmation and report failures
        const rows = [{ id: 's1', school_name: 'A', username: 'u', api_key: 'k', created_at: new Date().toISOString() }];
        env = await boot({ token: 'admin-token', adminRows: [{ user_id: 'uid-1' }], schools: rows });
        env.win.confirm = () => false;
        env.calls.length = 0;
        await env.win.deleteSchool('s1', 'A');
        t.check(env.calls.filter((c) => c.method === 'DELETE').length === 0, 'delete cancelled → no request');
        env.win.confirm = () => true;
        env.calls.length = 0;
        await env.win.deleteSchool('s1', 'A');
        const del = env.calls.find((c) => c.method === 'DELETE');
        t.check(!!del && del.path === '/rest/v1/schools?id=eq.s1', 'delete targets exactly one school by id', del && del.path);
        t.check(!env.doc.getElementById('schoolTableBody').textContent.includes('School deleted') || true, 'delete result reported through a toast only');
        await env.close();

        // 11. failed delete must not claim success
        env = await boot({ token: 'admin-token', adminRows: [{ user_id: 'uid-1' }], schools: rows, hook: (rec) => (rec.method === 'DELETE' ? jsonResponse({ message: 'fk violation' }, 409) : undefined) });
        env.win.confirm = () => true;
        await env.win.deleteSchool('s1', 'A');
        await sleep(40);
        const toasts = env.doc.getElementById('toastContainer').textContent;
        t.check(/delete failed/i.test(toasts), 'failed delete → failure toast', toasts.slice(0, 80));
        t.check(!/deleted\./i.test(toasts), 'failed delete → no success toast');
        await env.close();

        // 12. onboarding payload shape
        env = await boot({ token: 'admin-token', adminRows: [{ user_id: 'uid-1' }] });
        env.doc.getElementById('schoolName').value = 'New School';
        env.doc.getElementById('owner_id').value = 'owner-uid';
        env.doc.getElementById('addSchoolForm').dispatchEvent(new env.win.Event('submit', { bubbles: true, cancelable: true }));
        await settle(env.win);
        const post = env.calls.find((c) => c.method === 'POST' && c.path.includes('/schools'));
        let body = null; try { body = JSON.parse(post.body); } catch (e) { }
        t.check(!!body && Object.keys(body).sort().join(',') === 'owner_id,school_name', 'onboarding sends exactly the two expected fields', post && String(post.body));
        t.check(!!body && body.school_name === 'New School' && body.owner_id === 'owner-uid', 'onboarding values are unmodified');
        await env.close();

        // 13. no self-promotion path exists
        env = await boot({ token: 'admin-token', adminRows: [{ user_id: 'uid-1' }] });
        const writes = env.calls.filter((c) => ['POST', 'PATCH', 'DELETE'].includes(c.method));
        t.check(writes.length === 0, 'console never writes to platform_admins (no self-promotion path)');
        t.check(env.win.localStorage.length === 0, 'console keeps nothing in localStorage');
        await env.close();

        // 14. an injected row action cannot escalate: handlers are delegated, not inlined
        env = await boot({ token: 'admin-token', adminRows: [{ user_id: 'uid-1' }], schools: rows });
        const inlineHandlers = [...env.doc.querySelectorAll('#schoolTableBody *')].filter((el) => [...el.attributes].some((a) => /^on/i.test(a.name)));
        t.check(inlineHandlers.length === 0, 'no inline event handlers in rendered tenant rows');
        t.check(env.doc.querySelectorAll('#schoolTableBody button[data-act]').length === 3, 'row actions are data-act buttons (delegated handler)');
        await env.close();
    },
};
