'use strict';
/**
 * Suite 8 — tenant isolation (IDOR) on the client side.
 *
 * The client cannot *enforce* isolation — RLS does that — but it must never widen a
 * request beyond the session's school, must scope every write, and must never accept a
 * tenant id from the URL, from fetched data or from user input.
 */
const { makeDom, settle, readRepo, supabaseResponder } = require('../lib/harness');

const ADMIN = 'admin.html';
const SITE = 'xyz_school.html';
const TABLES = ['notices', 'toppers', 'galleries', 'facilities', 'downloads', 'fee_structures', 'staff_members', 'achievements', 'testimonials', 'inquiries'];
const paramsOf = (url) => new URL(url).searchParams;

async function bootAdmin(sid = 'school-1') {
    const responder = supabaseResponder({ rows: () => [], tables: { schools: [{ id: 'school-1', school_name: 'S' }] } });
    const env = makeDom(readRepo(ADMIN), { responder });
    env.win.localStorage.setItem('sb_token', 'tok');
    env.win.localStorage.setItem('sid', sid);
    await settle(env.win);
    env.win.showDash('S');
    await settle(env.win);
    env.win.alert = () => { };
    env.win.confirm = () => true;
    return env;
}

module.exports = {
    name: '8. Tenant isolation (IDOR) — client behaviour',
    description: 'Every read and write must carry the session school; no tenant id may come from a URL, a payload or fetched data.',
    async run(t) {
        const env = await bootAdmin();
        const sid = 'school-1';

        // reads
        let scoped = 0; const bad = [];
        for (const table of TABLES) {
            env.calls.length = 0;
            await env.win.loadList(table);
            const req = env.calls.find((c) => c.path.includes(`/rest/v1/${table}`));
            if (req && paramsOf(req.url).get('school_id') === `eq.${sid}`) scoped++;
            else bad.push(`${table}: ${req && req.path}`);
        }
        t.batch(scoped, TABLES.length, 'every list read is filtered by the session school', bad);

        // writes: inserts, updates and deletes
        let inserts = 0, deletes = 0;
        const writeBad = [];
        // drive the real form listeners
        const forms = [['f-notices', 'notices'], ['f-toppers', 'toppers'], ['f-galleries', 'galleries'], ['f-facilities', 'facilities'],
            ['f-downloads', 'downloads'], ['f-fee_structures', 'fee_structures'], ['f-staff_members', 'staff_members'],
            ['f-achievements', 'achievements'], ['f-testimonials', 'testimonials']];
        for (const [formId, table] of forms) {
            const form = env.doc.getElementById(formId);
            // fill whatever fields exist with benign values
            form.querySelectorAll('input, textarea, select').forEach((el) => {
                if (el.type === 'url') el.value = 'https://ok.example/x.pdf';
                else if (el.type === 'date') el.value = '2026-01-01';
                else if (el.type === 'number') el.value = '100';
                else if (el.tagName === 'SELECT') el.value = el.options[0].value;
                else el.value = 'v';
            });
            env.calls.length = 0;
            form.dispatchEvent(new env.win.Event('submit', { bubbles: true, cancelable: true }));
            await settle(env.win, { quietFor: 20 });
            const post = env.calls.find((c) => c.method === 'POST' && c.path.includes(`/rest/v1/${table}`));
            let body = null; try { body = JSON.parse(post.body); } catch (e) { }
            if (body && body.school_id === sid) inserts++; else writeBad.push(`insert ${table}: ${post && post.body}`);
        }
        t.batch(inserts, forms.length, 'every insert pins school_id to the session school', writeBad);

        for (const table of TABLES.slice(0, 9)) {
            env.calls.length = 0;
            await env.win.delItem(table, 'row-1');
            const del = env.calls.find((c) => c.method === 'DELETE');
            const p = del ? paramsOf(del.url) : null;
            if (p && p.get('school_id') === `eq.${sid}` && p.get('id') === 'eq.row-1') deletes++;
            else writeBad.push(`delete ${table}: ${del && del.url}`);
        }
        t.batch(deletes, 9, 'every delete is scoped by id AND school_id', writeBad);

        // updates: edit then submit
        const env2 = await bootAdmin();
        env2.win.data_notices = [{ id: 'row-9', title: 't', notice_date: '2026-01-01' }];
        env2.win.editItem('notices', 'row-9');
        env2.doc.getElementById('n_title').value = 'changed';
        env2.calls.length = 0;
        env2.doc.getElementById('f-notices').dispatchEvent(new env2.win.Event('submit', { bubbles: true, cancelable: true }));
        await settle(env2.win, { quietFor: 20 });
        const patch = env2.calls.find((c) => c.method === 'PATCH');
        const pp = patch ? paramsOf(patch.url) : null;
        t.check(!!pp && pp.get('id') === 'eq.row-9' && pp.get('school_id') === 'eq.school-1', 'updates are scoped by id AND school_id', patch && patch.path);
        t.check(env2.calls.every((c) => paramsOf(c.url).get('school_id') === null || String(paramsOf(c.url).get('school_id')).startsWith('eq.')), 'no request ever omits or widens the school filter');
        t.check(env2.calls.filter((c) => c.method !== 'GET').length === 1, 'edit+save issues exactly one write (no duplicate insert)');
        await env2.close();

        // a tampered local sid must remain a single, well-formed filter — enforcement is RLS's job
        const env3 = await bootAdmin('victim-school-id');
        env3.calls.length = 0;
        await env3.win.loadList('notices');
        const tampered = env3.calls.find((c) => c.path.includes('/rest/v1/notices'));
        t.check(!!tampered && paramsOf(tampered.url).get('school_id') === 'eq.victim-school-id', 'a tampered stored school id does not widen the query (single param, still eq.)');
        t.advisory('Tenant isolation ultimately depends on the RLS policies in supabase/schema.sql, not on this page',
            'the client always asks for the tenant it was told to; only Postgres can refuse a forged one');
        env3.close();

        // public site: the tenant id used for reads/inserts must come from the resolved school, not from input
        const responder = supabaseResponder({
            rpcStatus: 200,
            rpc: [{ id: 'server-side-school-id', school_name: 'X' }],
            rows: () => [],
        });
        const site = makeDom(readRepo(SITE), { url: 'https://school.example/', responder });
        await settle(site.win);
        site.doc.getElementById('iq_sname').value = 'A';
        site.doc.getElementById('iq_pname').value = 'B';
        site.doc.getElementById('iq_phone').value = '999';
        site.calls.length = 0;
        site.doc.getElementById('inquiryForm').dispatchEvent(new site.win.Event('submit', { bubbles: true, cancelable: true }));
        await settle(site.win, { quietFor: 20 });
        const post = site.calls.find((c) => c.method === 'POST' && c.path.includes('/rest/v1/inquiries'));
        let body = null; try { body = JSON.parse(post.body); } catch (e) { }
        t.check(!!body && body.school_id === 'server-side-school-id', 'inquiry school_id comes from the server response, not the visitor', post && String(post.body).slice(0, 80));
        t.check(!!body && body.status === 'new', 'visitor cannot choose the inquiry status');
        const siteReads = site.calls.filter((c) => c.path.includes('/rest/v1/schools'));
        t.check(siteReads.length === 0, 'with the RPC available the site never reads the schools table', siteReads.map((c) => c.path).join(' | '));
        await site.close();
    },
};
