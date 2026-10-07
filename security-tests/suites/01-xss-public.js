'use strict';
/**
 * Suite 1 — reflected/stored XSS against the public school website.
 *
 * Method: for every (table, field) pair the website renders, we return one row per
 * attack payload from the mocked Supabase API, boot the real xyz_school.html, and then
 * assert for EVERY payload that
 *    a) no script-capable node or event handler exists anywhere in the rendered page,
 *    b) the payload survived as inert visible text (so escaping is not silently dropping data),
 *    c) nothing executed (no payload marker became a global).
 */
const { makeDom, settle, readRepo, dangerousNodes, executedMarkers, supabaseResponder, snippet } = require('../lib/harness');
const { HTML_PAYLOADS } = require('../lib/payloads');

const SITE = 'xyz_school.html';

// everything the public site renders as text
const TEXT_SINKS = {
    notices: { fields: ['title', 'notice_date'], defaults: {} },
    toppers: { fields: ['student_name', 'exam_name', 'percentage_or_grade', 'passing_year'], defaults: { photo_url: '', rating: 5 } },
    galleries: { fields: ['caption'], defaults: { image_url: 'https://ok.example/g.jpg' } },
    facilities: { fields: ['facility_name', 'description'], defaults: {} },
    downloads: { fields: ['document_title', 'document_category'], defaults: { file_url: 'https://ok.example/f.pdf' } },
    fee_structures: { fields: ['class_name', 'academic_session', 'total_fee'], defaults: {} },
    staff_members: { fields: ['name', 'designation', 'qualification'], defaults: { photo_url: '' } },
    achievements: { fields: ['title', 'description'], defaults: {} },
    testimonials: { fields: ['reviewer_name', 'reviewer_relation', 'review_text'], defaults: { rating: 5 } },
};

// every school-level text field, with the place(s) it is rendered
const SCHOOL_FIELDS = {
    school_name: ['#siteName', '#footName', '#footNameCopy'],
    tagline: ['#siteTagline'],
    about_us_text: ['#aboutText', '#footAbout'],
    vision_text: ['#visionText'],
    mission_text: ['#missionText'],
    principal_name: ['#leadersGrid'],
    principal_qualification: ['#leadersGrid'],
    principal_message: ['#leadersGrid'],
    director_name: ['#leadersGrid'],
    director_qualification: ['#leadersGrid'],
    director_message: ['#leadersGrid'],
    address: ['#footAddr', '#footContact'],
    city: ['#footContact'],
    state: ['#footAddr'],
    pincode: ['#footAddr', '#footContact'],
    phone_primary: ['#topPhone', '#footPh1', '#footContact'],
    phone_secondary: ['#footPh2'],
    email_primary: ['#topEmail', '#footEm', '#footContact'],
    school_timing: ['#topTiming'],
    established_year: ['#heroEst'],
    affiliation_board: ['#heroBoard'],
    affiliation_number: ['#heroAff'],
};

const BENIGN_SCHOOL = {
    id: 'school-1', school_name: 'Test School', tagline: 'tag',
    phone_primary: '999', phone_secondary: '998', email_primary: 'a@b.c',
    school_timing: '9-4', established_year: '1999', affiliation_board: 'CBSE',
    affiliation_number: '123', admission_status: true,
};

async function boot(rows, school = BENIGN_SCHOOL) {
    const responder = supabaseResponder({ rpcStatus: 200, rpc: [school], rows: (t) => rows[t] || [] });
    const env = makeDom(readRepo(SITE), { url: 'https://school.example/', responder });
    await settle(env.win);
    return env;
}

module.exports = {
    name: '1. XSS — public website (xyz_school.html)',
    description: `Sends ${HTML_PAYLOADS.length} attack payloads through every text sink the public site renders.`,
    async run(t) {
        // ── table fields ────────────────────────────────────────────────────
        for (const [table, { fields, defaults }] of Object.entries(TEXT_SINKS)) {
            for (const field of fields) {
                const rows = {
                    [table]: HTML_PAYLOADS.map((p, i) => ({ id: `${table}-${i}`, school_id: 'school-1', ...defaults, [field]: p })),
                };
                const env = await boot(rows);
                const container = env.doc.getElementById(
                    { notices: 'marqueeText', toppers: 'topperGrid', galleries: 'galleryGrid', facilities: 'facilityGrid', downloads: 'dlGrid', fee_structures: 'feeTable', staff_members: 'staffGrid', achievements: 'achieveGrid', testimonials: 'testGrid' }[table]
                );
                const findings = dangerousNodes(container);
                let safe = 0, preserved = 0;
                const examples = [];
                for (let i = 0; i < HTML_PAYLOADS.length; i++) {
                    const payload = HTML_PAYLOADS[i];
                    if (findings.length === 0) safe++; else examples.push(`${snippet(container)} ← ${payload.slice(0, 40)}`);
                    if ((container.textContent || '').includes(payload)) preserved++;
                }
                t.batch(safe, HTML_PAYLOADS.length, `${table}.${field}: no markup/handler survived injection`, findings.concat(examples));
                t.batch(preserved, HTML_PAYLOADS.length, `${table}.${field}: payload kept as inert text (no data loss)`);
                if (executedMarkers(env.win).length) t.check(false, `${table}.${field}: nothing executed`, executedMarkers(env.win).join(','));
                await env.close();
            }
        }

        // ── school-level fields (one boot per payload, all fields at once) ──
        let safe = 0, preserved = 0, executed = 0;
        const failures = [];
        for (const payload of HTML_PAYLOADS) {
            const school = { ...BENIGN_SCHOOL };
            for (const field of Object.keys(SCHOOL_FIELDS)) school[field] = payload;
            const env = await boot({}, school);
            let payloadSafe = true;
            for (const [field, selectors] of Object.entries(SCHOOL_FIELDS)) {
                for (const sel of selectors) {
                    const el = env.doc.querySelector(sel);
                    if (!el) { payloadSafe = false; failures.push(`${field}: missing ${sel}`); continue; }
                    const findings = dangerousNodes(el);
                    if (findings.length) { payloadSafe = false; failures.push(`${field} ${sel} → ${findings[0]}`); }
                    const text = el.textContent || '';
                    if (text.includes(payload)) preserved++;
                }
            }
            if (payloadSafe) safe++; else failures.push(`payload: ${payload.slice(0, 50)}`);
            if (executedMarkers(env.win).length) executed++;
            await env.close();
        }
        t.batch(safe, HTML_PAYLOADS.length, 'school profile fields: no markup/handler survived injection (all 22 fields per payload)', failures);
        t.batch(preserved, HTML_PAYLOADS.length * Object.values(SCHOOL_FIELDS).flat().length, 'school profile fields: payload kept as inert text');
        t.check(executed === 0, 'no payload executed anywhere in the public site', `${executed} payload(s) executed`);
    },
};
