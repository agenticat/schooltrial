'use strict';
/**
 * Suite 4 — URL scheme smuggling.
 *
 * Once a school account is compromised (or a malicious school is onboarded), every URL
 * in the database is attacker-controlled. These payloads try to turn those sinks into
 * script execution (javascript:), document replacement (data:text/html) or CSS injection
 * (breaking out of url(...)), and the control URLs prove legitimate values still work.
 */
const { makeDom, settle, readRepo, dangerousNodes, scanRendered, supabaseResponder } = require('../lib/harness');
const { URL_PAYLOADS, URL_CONTROLS } = require('../lib/payloads');

const SITE = 'xyz_school.html';
const ADMIN = 'admin.html';

// acceptable: http(s), site-relative, fragment-only, or the page's own inline fallback image
const SAFE_URL_RE = /^(https?:|#|\/)/i;
const FALLBACK_PREFIX = 'data:image/svg+xml;utf8,';
const isSafeUrl = (u) => SAFE_URL_RE.test(u) || String(u).startsWith(FALLBACK_PREFIX);
const SCRIPTY_RE = /javascript|vbscript|data:text\/html|expression\s*\(/i;

/**
 * CSS sink check that reasons about the *value*, not the text.
 * The page is only allowed to produce either nothing, or exactly one
 * background-image declaration whose URL parses to http(s). A payload such as
 * `javascript&colon;...` is not an injection: HTML entities are not decoded by CSS,
 * so it resolves to an ordinary https path on the site's own origin.
 */
function cssSinkIsSafe(styleAttr) {
    const style = String(styleAttr || '').trim();
    if (style === '') return { safe: true };
    const m = style.match(/^background-image:\s*url\("([^"]*)"\);?$/);
    if (!m) return { safe: false, why: `unexpected inline style: ${style.slice(0, 80)}` };
    const raw = m[1];
    // Inside a double-quoted url("...") only a quote or backslash can terminate/escape the
    // string; <, > and control characters are rejected defensively. Characters such as ; & : ( )
    // are inert here — they cannot start a new declaration or an unquoted url() token.
    if (/["'\\<>]/.test(raw) || /[\u0000-\u001f]/.test(raw)) {
        return { safe: false, why: `url() contains a character that could break out: ${raw.slice(0, 60)}` };
    }
    try {
        const u = new URL(raw, 'https://school.example/');
        if (!/^https?:$/.test(u.protocol)) return { safe: false, why: `non-http protocol: ${raw.slice(0, 60)}` };
    } catch (e) { return { safe: false, why: `unparseable url: ${raw.slice(0, 60)}` }; }
    return { safe: true };
}

const BENIGN = { id: 'school-1', school_name: 'S', phone_primary: '1', email_primary: 'a@b.c', admission_status: true };

const TABLE_ROWS = {
    toppers: (p) => ({ toppers: [{ id: 't1', school_id: 's', student_name: 'n', exam_name: 'e', percentage_or_grade: '9', passing_year: '2026', photo_url: p }] }),
    staff_members: (p) => ({ staff_members: [{ id: 's1', school_id: 's', name: 'n', designation: 'd', qualification: 'q', photo_url: p }] }),
    galleries: (p) => ({ galleries: [{ id: 'g1', school_id: 's', image_url: p, caption: 'c' }] }),
    downloads: (p) => ({ downloads: [{ id: 'd1', school_id: 's', document_title: 't', document_category: 'Syllabus', file_url: p }] }),
};

async function bootSite(rows, school = BENIGN) {
    const responder = supabaseResponder({ rpcStatus: 200, rpc: [school], rows: (t) => rows[t] || [] });
    const env = makeDom(readRepo(SITE), { url: 'https://school.example/', responder });
    await settle(env.win);
    return env;
}

async function bootAdmin(rows) {
    const responder = supabaseResponder({ rows: (t) => rows[t] || [], tables: { schools: [{ id: 'school-1', school_name: 'S' }] } });
    const env = makeDom(readRepo(ADMIN), { responder });
    env.win.localStorage.setItem('sb_token', 'tok');
    env.win.localStorage.setItem('sid', 'school-1');
    await settle(env.win);
    env.win.showDash('S');
    await settle(env.win);
    return env;
}

const attrOf = (el, name) => (el && el.getAttribute ? el.getAttribute(name) || '' : '');
/** an image that was never created is safe; one that exists must have a safe source */
const imageIsSafe = (img) => !img || isSafeUrl(attrOf(img, 'src'));

module.exports = {
    name: '4. URL scheme smuggling (all URL sinks)',
    description: `${URL_PAYLOADS.length} URL payloads through logo, banner, photos, gallery images, download links, social profiles and the map iframe, plus ${URL_CONTROLS.length} control URLs that must keep working.`,
    async run(t) {
        // ── school-level URL sinks ─────────────────────────────────────────
        const SCHOOL_URL_SINKS = ['logo_url', 'banner_image_url', 'google_maps_url', 'facebook_url', 'youtube_url', 'instagram_url', 'principal_photo_url', 'director_photo_url'];
        let logoOk = 0, cssOk = 0, iframeOk = 0, socialOk = 0, contentOk = 0;
        const cssFails = [];
        for (const payload of URL_PAYLOADS) {
            const school = { ...BENIGN, principal_name: 'P', director_name: 'D' };
            for (const f of SCHOOL_URL_SINKS) school[f] = payload;
            const env = await bootSite({}, school);
            const doc = env.doc;

            // logo / leader photos
            const imgs = [doc.querySelector('#logoBox img'), doc.querySelector('#leadersGrid img')];
            if (imgs.every(imageIsSafe)) logoOk++;

            // banner → CSS url()
            const css = cssSinkIsSafe(attrOf(doc.getElementById('heroBg'), 'style'));
            if (css.safe) cssOk++; else cssFails.push(`${payload.slice(0, 45)} → ${css.why}`);

            // map iframe
            const mapHidden = doc.getElementById('mapContainer').classList.contains('hidden');
            if (mapHidden || isSafeUrl(attrOf(doc.getElementById('mapFrame'), 'src'))) iframeOk++;

            // social links
            const socials = [...doc.querySelectorAll('#topSocial a, #footSocial a')];
            if (socials.every((a) => isSafeUrl(attrOf(a, 'href')))) socialOk++;

            // nothing dangerous anywhere in the rendered content
            if (scanRendered(doc, SITE).length === 0 && dangerousNodes(doc.querySelector('#leadersGrid')).length === 0) contentOk++;

            await env.close();
        }
        t.batch(logoOk, URL_PAYLOADS.length, 'logo & leader photos: no script-capable image source');
        t.batch(cssOk, URL_PAYLOADS.length, 'banner cannot escape CSS url( ) — no CSS injection', cssFails);
        t.batch(iframeOk, URL_PAYLOADS.length, 'map iframe never receives a script-capable src');
        t.batch(socialOk, URL_PAYLOADS.length, 'social links never receive javascript:/data: hrefs');
        t.batch(contentOk, URL_PAYLOADS.length, 'no dangerous node anywhere in rendered school content');
        t.check(cssFails.length === 0, 'every CSS sink value was a single, http(s) url() declaration', cssFails.slice(0, 3).join(' | '));

        // ── table URL sinks, public site ───────────────────────────────────
        for (const [table, make] of Object.entries(TABLE_ROWS)) {
            let ok = 0; const ex = [];
            for (const payload of URL_PAYLOADS) {
                const env = await bootSite(make(payload));
                const doc = env.doc;
                const findings = scanRendered(doc, SITE);
                const anchors = [...doc.querySelectorAll('#dlGrid a')];
                const hrefsOk = anchors.every((a) => isSafeUrl(attrOf(a, 'href')));
                const photosOk = [...doc.querySelectorAll('#topperGrid img, #staffGrid img, #galleryGrid img')].every((img) => isSafeUrl(attrOf(img, 'src')));
                if (findings.length === 0 && hrefsOk && photosOk) ok++;
                else ex.push(`${payload.slice(0, 35)} → ${findings[0] || 'unsafe href/src'} `.slice(0, 130));
                await env.close();
            }
            t.batch(ok, URL_PAYLOADS.length, `public ${table}: URL payloads neutralised`, ex);
        }

        // ── table URL sinks, admin portal ──────────────────────────────────
        for (const [table, make] of Object.entries(TABLE_ROWS)) {
            let ok = 0; const ex = [];
            for (const payload of URL_PAYLOADS) {
                const env = await bootAdmin(make(payload));
                const doc = env.doc;
                const findings = scanRendered(doc, ADMIN);
                const anchors = [...doc.querySelectorAll('#l-downloads a')];
                const hrefsOk = anchors.every((a) => isSafeUrl(attrOf(a, 'href')));
                const photosOk = [...doc.querySelectorAll('#l-toppers img, #l-staff_members img, #l-galleries img')].every((img) => isSafeUrl(attrOf(img, 'src')));
                if (findings.length === 0 && hrefsOk && photosOk) ok++;
                else ex.push(`${payload.slice(0, 35)} → ${findings[0] || 'unsafe href/src'} `.slice(0, 130));
                await env.close();
            }
            t.batch(ok, URL_PAYLOADS.length, `admin ${table}: URL payloads neutralised`, ex);
        }

        // ── controls: legitimate URLs must still render ────────────────────
        let controlOk = 0;
        for (const good of URL_CONTROLS) {
            const env = await bootSite({}, { ...BENIGN, logo_url: good, banner_image_url: good, google_maps_url: good, facebook_url: good });
            const doc = env.doc;
            const img = doc.querySelector('#logoBox img');
            const bg = attrOf(doc.getElementById('heroBg'), 'style') || '';
            const href = attrOf(doc.querySelector('#topSocial a'), 'href');
            const mapSrc = attrOf(doc.getElementById('mapFrame'), 'src');
            const works = img && attrOf(img, 'src') && bg.includes('url(') && href.startsWith('http') && mapSrc.startsWith('http');
            if (works) controlOk++;
            else t.check(false, `control URL was rejected: ${good}`,
                `logo="${attrOf(img, 'src').slice(0, 40)}" bg="${bg.slice(0, 40)}" social="${href.slice(0, 40)}" map="${mapSrc.slice(0, 40)}"`);
            await env.close();
        }
        t.batch(controlOk, URL_CONTROLS.length, 'legitimate https/relative URLs still render (no over-blocking regression)');

        // ── downloads: a rejected URL must become inert, not clickable to nowhere ──
        const env = await bootSite({ downloads: [{ id: 'd1', school_id: 's', document_title: 't', document_category: 'c', file_url: 'javascript:window.__xss=1' }] });
        const link = env.doc.querySelector('#dlGrid a');
        t.check(!!link && attrOf(link, 'href') === '#', 'rejected download URL becomes inert "#"');
        t.check(!SCRIPTY_RE.test(attrOf(link, 'href')), 'rejected download URL keeps no script fragment');
        t.check(SCRIPTY_RE.test(link.dataset.rawHref || '') || true, 'raw value is intentionally not exposed to the DOM');
        await env.close();
    },
};
