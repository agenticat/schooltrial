'use strict';
/**
 * Suite 5 — PostgREST filter injection (the "SQL injection" surface of a serverless app).
 *
 * Every filter the pages build is `?column=eq.<value>`. If a value is interpolated
 * without percent-encoding, an attacker who controls it can append parameters
 * (`&or=(...)`, `&limit=`, `&select=`) and turn a scoped query into an unscoped one.
 * These cases drive hostile values through every query-filter sink and then parse the
 * resulting URL to prove the value stayed inside a single parameter.
 */
const { makeDom, settle, readRepo, supabaseResponder, jsonResponse } = require('../lib/harness');
const { QUERY_PAYLOADS } = require('../lib/payloads');

const ADMIN = 'admin.html';
const MASTER = 'master_panel.html';
const SITE = 'xyz_school.html';

const paramsOf = (url) => new URL(url).searchParams;
const paramCount = (url) => [...paramsOf(url).keys()].length;

async function bootAdmin() {
    const responder = supabaseResponder({ rows: () => [], tables: { schools: [{ id: 'school-1', school_name: 'S' }] } });
    const env = makeDom(readRepo(ADMIN), { responder });
    env.win.localStorage.setItem('sb_token', 'tok');
    env.win.localStorage.setItem('sid', 'school-1');
    await settle(env.win);
    env.win.showDash('S');
    await settle(env.win);
    return env;
}

module.exports = {
    name: '5. Query-filter injection (PostgREST)',
    description: `${QUERY_PAYLOADS.length} hostile values pushed through school_id, row id, api_key, admin uid and inquiry payloads. Each case re-parses the outgoing URL.`,
    async run(t) {
        // ── admin: school_id filter ────────────────────────────────────────
        const env = await bootAdmin();
        let listOk = 0, writeOk = 0, delOk = 0;
        const examples = [];
        const writeBodies = [];
        env.win.alert = () => { };
        for (const payload of QUERY_PAYLOADS) {
            env.win.localStorage.setItem('sid', payload);
            env.calls.length = 0;
            await env.win.loadList('notices');
            const req = env.calls.find((c) => c.path.includes('/rest/v1/notices'));
            if (req) {
                const p = paramsOf(req.url);
                const clean = paramCount(req.url) === 2 && p.get('school_id') === `eq.${payload}` && p.get('order') === 'created_at.desc';
                if (clean) listOk++; else examples.push(`${payload} → ${req.path}`);
            }

            // write path: value must travel in the JSON body, never in the query string
            env.calls.length = 0;
            env.doc.getElementById('n_title').value = 'x';
            env.doc.getElementById('n_date').value = '2026-01-01';
            env.doc.getElementById('f-notices').dispatchEvent(new env.win.Event('submit', { bubbles: true, cancelable: true }));
            await settle(env.win, { quietFor: 20 });
            const post = env.calls.find((c) => c.method === 'POST');
            if (post) {
                writeBodies.push(post.body);
                let parsed = null;
                try { parsed = JSON.parse(post.body); } catch (e) { }
                if (parsed && parsed.school_id === payload && paramCount(post.url) === 0) writeOk++;
                else examples.push(`POST ${post.url} body=${String(post.body).slice(0, 60)}`);
            }

            // delete path: both id and school_id must be single, round-tripping params
            env.calls.length = 0;
            env.win.confirm = () => true;
            await env.win.delItem('notices', payload);
            const del = env.calls.find((c) => c.method === 'DELETE');
            if (del) {
                const p = paramsOf(del.url);
                if (paramCount(del.url) === 2 && p.get('id') === `eq.${payload}` && p.get('school_id') === `eq.${payload}`) delOk++;
                else examples.push(`DELETE ${del.path}`);
            }
        }
        t.batch(listOk, QUERY_PAYLOADS.length, 'loadList: school_id stays one parameter, value round-trips', examples);
        t.batch(writeOk, QUERY_PAYLOADS.length, 'inserts: value travels in the JSON body, never the query string', examples);
        t.batch(delOk, QUERY_PAYLOADS.length, 'deletes: id + school_id stay single parameters', examples);
        t.check(writeBodies.every((b) => { try { JSON.parse(b); return true; } catch (e) { return false; } }), 'every write body is well-formed JSON');
        await env.close();

        // ── master console: id + admin uid filters ────────────────────────
        let masterOk = 0;
        const masterExamples = [];
        for (const payload of QUERY_PAYLOADS) {
            const responder = supabaseResponder({
                tables: { platform_admins: [{ user_id: 'uid-1' }], schools: [] },
                hook: (rec) => { rec.window.__probe = rec; return undefined; },
            });
            const env = makeDom(readRepo(MASTER), { responder });
            env.win.sessionStorage.setItem('sa_token', 'tok');
            await settle(env.win);
            const adminCall = env.calls.find((c) => c.path.includes('/rest/v1/platform_admins'));
            // now exercise delete + onboarding with hostile values
            env.win.confirm = () => true;
            await env.win.deleteSchool(payload, payload);
            const del = env.calls.find((c) => c.method === 'DELETE');
            env.doc.getElementById('schoolName').value = payload;
            env.doc.getElementById('owner_id').value = payload;
            env.doc.getElementById('addSchoolForm').dispatchEvent(new env.win.Event('submit', { bubbles: true, cancelable: true }));
            await settle(env.win, { quietFor: 20 });
            const post = env.calls.find((c) => c.method === 'POST');
            const uidParam = adminCall ? paramsOf(adminCall.url).get('user_id') : null;
            const delParam = del ? paramsOf(del.url).get('id') : null;
            let postBody = null;
            try { postBody = JSON.parse(post.body); } catch (e) { }
            const ok = uidParam === 'eq.uid-1'
                && adminCall && paramCount(adminCall.url) === 3
                && delParam === `eq.${payload}` && del && paramCount(del.url) === 1
                && postBody && postBody.school_name === payload && paramCount(post.url) === 0;
            if (ok) masterOk++; else masterExamples.push(`${payload} → uid=${uidParam} del=${delParam} body=${String(post && post.body).slice(0, 50)}`);
            await env.close();
        }
        t.batch(masterOk, QUERY_PAYLOADS.length, 'console: admin uid, delete id and onboarding body all stay intact', masterExamples);

        // ── public site: api_key lookup (RPC body + direct-read fallback) ──
        // SCHOOL_API_KEY is a constant baked into the published file, so it is not a runtime
        // input — but it is the one value an operator pastes in by hand. These cases rewrite
        // the constant inside an in-memory copy of the page and check that the generated
        // request can never become more than one query parameter.
        const source = readRepo(SITE);
        let fallbackOk = 0;
        const siteExamples = [];
        for (const payload of QUERY_PAYLOADS) {
            const injected = source.replace(
                'const SCHOOL_API_KEY="bc1dd513-5915-49b7-8b07-4d346e1e0445";',
                `const SCHOOL_API_KEY=${JSON.stringify(payload)};`);
            if (injected === source) { siteExamples.push('anchor for SCHOOL_API_KEY not found'); break; }
            const responder = supabaseResponder({ rpcStatus: 404, tables: { schools: [] } });
            const env = makeDom(injected, {
                url: 'https://school.example/',
                responder: (rec) => (rec.path.includes('/rest/v1/schools') ? jsonResponse([]) : responder(rec)),
            });
            await settle(env.win);
            const call = env.calls.find((c) => c.path.includes('/rest/v1/schools'));
            if (call) {
                const p = paramsOf(call.url);
                if (paramCount(call.url) === 2 && p.get('api_key') === `eq.${payload}` && p.get('select') === '*') fallbackOk++;
                else siteExamples.push(`${JSON.stringify(payload).slice(0, 40)} → ${call.path.slice(0, 90)}`);
            } else siteExamples.push(`${JSON.stringify(payload).slice(0, 40)} → no request issued`);
            await env.close();
        }
        t.batch(fallbackOk, QUERY_PAYLOADS.length, 'public lookup fallback: api_key stays one parameter', siteExamples);

        const rpcEnv = makeDom(readRepo(SITE), {
            url: 'https://school.example/',
            responder: supabaseResponder({ rpcStatus: 200, rpc: [] }),
        });
        await settle(rpcEnv.win);
        const rpcCall = rpcEnv.calls.find((c) => c.path.includes('/rpc/'));
        t.check(!!rpcCall && rpcCall.method === 'POST', 'RPC lookup is a POST (key travels in the body, not the URL)');
        t.check(!!rpcCall && rpcCall.path.endsWith('/rpc/public_school_by_key'), 'RPC targets the intended function');
        let rpcBody = null;
        try { rpcBody = JSON.parse(rpcCall.body); } catch (e) { }
        t.check(!!rpcBody && typeof rpcBody.p_key === 'string' && Object.keys(rpcBody).length === 1, 'RPC body carries exactly the key argument', String(rpcCall.body));
        await rpcEnv.close();
    },
};
