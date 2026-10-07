'use strict';
/**
 * Suite 3 — XSS and attribute-injection against the super-admin console.
 *
 * Two distinct risks here:
 *  1. school_name is rendered into the tenant table (the console that can delete schools),
 *  2. api_key / id / name are rendered into HTML *attributes* (data-key, data-id, data-name),
 *     where a quote breakout would create new attributes such as onmouseover=...
 */
const { makeDom, settle, readRepo, dangerousNodes, supabaseResponder, snippet } = require('../lib/harness');
const { HTML_PAYLOADS } = require('../lib/payloads');

const MASTER = 'master_panel.html';

async function bootMaster(schools) {
    const responder = supabaseResponder({
        tables: { platform_admins: [{ user_id: 'uid-1' }], schools },
    });
    const env = makeDom(readRepo(MASTER), { responder });
    env.win.sessionStorage.setItem('sa_token', 'ADMIN-SESSION-9f3a-SECRET');
    await settle(env.win);
    return env;
}

module.exports = {
    name: '3. XSS — super-admin console (master_panel.html)',
    description: `Tenant names, api keys and row ids set to ${HTML_PAYLOADS.length} attack payloads each, including quote-breakout attempts against data-* attributes.`,
    async run(t) {
        const schools = HTML_PAYLOADS.map((p, i) => ({
            id: `id-${i}-${p.slice(0, 8)}`,
            school_name: p,
            username: p,
            api_key: `key-${i}-${p}`,
            created_at: new Date().toISOString(),
        }));
        const env = await bootMaster(schools);
        const body = env.doc.getElementById('schoolTableBody');
        const findings = dangerousNodes(body);

        let safe = 0, textOk = 0, structureOk = 0, attrOk = 0;
        const rows = body.querySelectorAll('tr:not(:has(td[colspan]))');
        for (let i = 0; i < HTML_PAYLOADS.length; i++) {
            const payload = HTML_PAYLOADS[i];
            const row = rows[i];
            if (row && dangerousNodes(row).length === 0) safe++;
            if (row && (row.textContent || '').includes(payload)) textOk++;
            if (row && row.querySelectorAll('td').length === 4) structureOk++;
            // attribute round-trip: the button must carry the exact raw value, not a broken fragment
            const copy = row && row.querySelector('[data-act="copy"]');
            const del = row && row.querySelector('[data-act="delete"]');
            if (copy && copy.dataset.key === `key-${i}-${payload}` && del && del.dataset.name === payload) attrOk++;
        }
        t.batch(safe, HTML_PAYLOADS.length, 'tenant name: no markup/handler rendered in the client table', findings.length ? [snippet(body)] : []);
        t.batch(textOk, HTML_PAYLOADS.length, 'tenant name: hostile value still readable as text');
        t.batch(structureOk, HTML_PAYLOADS.length, 'table structure intact (4 cells per row) for every payload');
        t.batch(attrOk, HTML_PAYLOADS.length, 'no attribute breakout: data-key/data-name round-trip byte-for-byte', findings.length ? [snippet(body)] : []);

        // the admin's own identity and the token must not be injectable either
        t.check(!env.doc.documentElement.outerHTML.includes('ADMIN-SESSION-9f3a-SECRET'), 'session token never rendered into the page');
        t.check(env.win.localStorage.length === 0, 'console keeps nothing in localStorage');
        await env.close();

        // quote/backtick-breakout specialist payloads aimed straight at attribute sinks
        const breakout = [
            '" onmouseover="window.__xss=1',
            "' onmouseover='window.__xss=2",
            '` onmouseover=`window.__xss=3',
            '" autofocus onfocus="window.__xss=4',
            '" style="background:url(javascript:window.__xss=5)',
            '"><img src=x onerror=window.__xss=6>',
            '&quot; onmouseover=&quot;window.__xss=7',
            '&#34; onmouseover=&#34;window.__xss=8',
            '" formaction="javascript:window.__xss=9',
            'x" data-key="forged',
        ];
        const env2 = await bootMaster(breakout.map((p, i) => ({ id: `b-${i}`, school_name: p, username: p, api_key: p, created_at: new Date().toISOString() })));
        const body2 = env2.doc.getElementById('schoolTableBody');
        const findings2 = dangerousNodes(body2);
        let breakoutOk = 0;
        const breakoutRows = body2.querySelectorAll('tr:not(:has(td[colspan]))');
        for (let i = 0; i < breakout.length; i++) {
            const copy = breakoutRows[i] && breakoutRows[i].querySelector('[data-act="copy"]');
            if (copy && copy.dataset.key === breakout[i]) breakoutOk++;
        }
        t.batch(breakoutOk, breakout.length, 'quote/backtick breakouts cannot forge or split attributes', findings2.length ? [snippet(body2)] : []);
        t.check(findings2.length === 0, 'no dangerous node from breakout payloads', findings2.join(' | '));
        await env2.close();
    },
};
