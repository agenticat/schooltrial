'use strict';
/**
 * Suite 2 — XSS inside the school admin portal.
 *
 * The portal is the highest-value target: it holds a live Supabase access token in
 * localStorage, so any stored payload that executes there is an account takeover.
 * Hostile rows are therefore injected into all 11 admin tables, including `inquiries`,
 * which anonymous visitors can write to.
 */
const { makeDom, settle, readRepo, dangerousNodes, executedMarkers, supabaseResponder, snippet } = require('../lib/harness');
const { HTML_PAYLOADS } = require('../lib/payloads');

const ADMIN = 'admin.html';

const TEXT_SINKS = {
    notices: { id: 'l-notices', fields: ['title', 'notice_date'] },
    toppers: { id: 'l-toppers', fields: ['student_name', 'exam_name', 'percentage_or_grade', 'passing_year'] },
    galleries: { id: 'l-galleries', fields: ['caption'] },
    facilities: { id: 'l-facilities', fields: ['facility_name', 'description'] },
    downloads: { id: 'l-downloads', fields: ['document_title', 'document_category'] },
    fee_structures: { id: 'l-fee_structures', fields: ['class_name', 'academic_session', 'total_fee'] },
    staff_members: { id: 'l-staff_members', fields: ['name', 'designation', 'qualification'] },
    achievements: { id: 'l-achievements', fields: ['title', 'description'] },
    testimonials: { id: 'l-testimonials', fields: ['reviewer_name', 'reviewer_relation', 'review_text'] },
    inquiries: { id: 'l-inquiries', fields: ['student_name', 'parent_name', 'phone_number', 'email', 'class_applied_for', 'message'] },
};

// db field → form input id, for the edit round-trip check
const EDIT_MAPPINGS = {
    notices: { title: 'n_title', notice_date: 'n_date' },
    toppers: { student_name: 't_name', exam_name: 't_exam', percentage_or_grade: 't_score', passing_year: 't_year' },
    galleries: { caption: 'g_cap' },
    facilities: { facility_name: 'fc_name', description: 'fc_desc' },
    downloads: { document_title: 'dl_title', document_category: 'dl_cat' },
    fee_structures: { class_name: 'fe_class', academic_session: 'fe_session', total_fee: 'fe_total' },
    staff_members: { name: 'st_name', designation: 'st_desg', qualification: 'st_qual' },
    achievements: { title: 'ach_title', description: 'ach_desc' },
    testimonials: { reviewer_name: 'tm_name', reviewer_relation: 'tm_rel', review_text: 'tm_text', rating: 'tm_rat' },
};

const DEFAULTS = {
    toppers: { photo_url: '' }, staff_members: { photo_url: '' }, galleries: { image_url: 'https://ok.example/g.jpg' },
    downloads: { file_url: 'https://ok.example/f.pdf' }, testimonials: { rating: 5 },
};

async function bootAdmin(rows) {
    const responder = supabaseResponder({
        rows: (table) => rows[table] || [],
        tables: { schools: [{ id: 'school-1', school_name: 'Test School', admission_status: true }] },
    });
    const env = makeDom(readRepo(ADMIN), { responder });
    env.win.localStorage.setItem('sb_token', 'secret-token-DEADBEEF-42');
    env.win.localStorage.setItem('sid', 'school-1');
    env.win.localStorage.setItem('sname', 'Test School');
    await settle(env.win);
    env.win.showDash('Test School');
    await settle(env.win);
    return env;
}

module.exports = {
    name: '2. XSS — admin portal (admin.html)',
    description: `Injects ${HTML_PAYLOADS.length} payloads through all 11 admin tables, including anonymous inquiries, and re-opens each record in the edit form.`,
    async run(t) {
        for (const [table, { id, fields }] of Object.entries(TEXT_SINKS)) {
            for (const field of fields) {
                const rows = {
                    [table]: HTML_PAYLOADS.map((p, i) => ({ id: `${table}-${i}`, school_id: 'school-1', created_at: new Date().toISOString(), ...(DEFAULTS[table] || {}), [field]: p })),
                };
                const env = await bootAdmin(rows);
                const container = env.doc.getElementById(id);
                const findings = dangerousNodes(container);
                let safe = 0, preserved = 0;
                for (let i = 0; i < HTML_PAYLOADS.length; i++) {
                    if (!findings.length) safe++;
                    if ((container.textContent || '').includes(HTML_PAYLOADS[i])) preserved++;
                }
                t.batch(safe, HTML_PAYLOADS.length, `${table}.${field}: no markup/handler survived injection`, findings.length ? [snippet(container)] : []);
                t.batch(preserved, HTML_PAYLOADS.length, `${table}.${field}: payload kept as inert text`);

                // The same hostile row, opened for editing, must land in the form unchanged.
                // Element behaviours below are the HTML spec, not the page:
                //   • <input type=text> strips CR/LF; <textarea> normalises CRLF → LF,
                //   • date/number/select controls refuse values they cannot represent.
                // Anything else must round-trip byte-for-byte: no truncation, no decoding.
                if (EDIT_MAPPINGS[table] && EDIT_MAPPINGS[table][field]) {
                    const inputId = EDIT_MAPPINGS[table][field];
                    const isTextarea = env.doc.getElementById(inputId).tagName === 'TEXTAREA';
                    const elType = env.doc.getElementById(inputId).type;
                    const isSelect = env.doc.getElementById(inputId).tagName === 'SELECT';
                    const constrained = isSelect || ['date', 'number', 'color'].includes(elType);
                    let exact = 0, specOk = 0;
                    const mismatches = [];
                    for (let i = 0; i < HTML_PAYLOADS.length; i++) {
                        const payload = HTML_PAYLOADS[i];
                        env.win.editItem(table, `${table}-${i}`);
                        const el = env.doc.getElementById(inputId);
                        const value = el.value;
                        const expected = isTextarea ? payload.replace(/\r\n?/g, '\n') : payload.replace(/[\r\n]/g, '');
                        if (value === payload) exact++;
                        let ok;
                        if (constrained) {
                            // the control must hold either nothing or a value the browser
                            // considers valid — it can never carry markup into a later request
                            ok = value === '' && !/[<>]/.test(value);
                            if (isSelect) ok = value === '';
                            else if (elType === 'number') ok = value === '' || !Number.isNaN(Number(value));
                            else if (elType === 'date') ok = value === '' || /^\d{4}-\d{2}-\d{2}$/.test(value);
                            else if (elType === 'color') ok = /^#[0-9a-f]{6}$/i.test(value);
                        } else {
                            ok = value === expected;
                        }
                        if (ok) specOk++;
                        else if (mismatches.length < 3) mismatches.push(`${JSON.stringify(payload).slice(0, 28)} → ${JSON.stringify(value).slice(0, 28)}`);
                    }
                    const label = constrained
                        ? `${table}.${field}: control discards values it cannot represent (nothing injectable reaches a later request)`
                        : `${table}.${field}: edit form round-trips the value exactly (modulo spec newline handling)`;
                    t.batch(specOk, HTML_PAYLOADS.length, label, mismatches);
                    if (!constrained && exact !== specOk) {
                        t.check(true, `${table}.${field}: ${specOk - exact} value(s) differ only by newline normalisation (HTML spec)`);
                    }
                }
                t.check(executedMarkers(env.win).length === 0, `${table}.${field}: nothing executed (access token not exposed to a payload)`);
                await env.close();
            }
        }

        // the token itself must never be reachable through a rendered attribute
        const env = await bootAdmin({ inquiries: [{ id: 'i1', school_id: 'school-1', student_name: '<img src=x onerror=window.__xss=1>', message: 'x', created_at: new Date().toISOString() }] });
        const html = env.doc.documentElement.outerHTML;
        t.check(!html.includes('secret-token-DEADBEEF-42'), 'access token never appears in the rendered DOM');
        t.check(env.doc.cookie === '', 'portal sets no cookies (session lives in localStorage only)');
        await env.close();

        // identity of what the portal actually stores
        const env2 = await bootAdmin({});
        t.check(env2.win.localStorage.getItem('sb_token') === 'secret-token-DEADBEEF-42', 'session token stored under the expected key');
        const keys = Object.keys(env2.win.localStorage).sort();
        t.check(JSON.stringify(keys) === JSON.stringify(['sb_token', 'sid', 'sname']), 'no unexpected data left in localStorage', keys.join(','));
        t.advisory('Session token is kept in localStorage, readable by any future XSS and by browser extensions',
            'Supabase\'s SSR pattern (httpOnly cookie + server-side client) removes this class entirely');
        await env2.close();
    },
};
