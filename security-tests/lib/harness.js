'use strict';
/**
 * Test harness: boots the real HTML files inside jsdom with a mocked Supabase API,
 * and provides DOM-level detectors for injected markup, dangerous URLs and handlers.
 *
 * The pages always talk to the network through window.fetch, so stubbing fetch in
 * beforeParse() gives complete control over what the "database" returns — which is
 * exactly how we simulate hostile stored content.
 */
const fs = require('fs');
const path = require('path');
const { JSDOM, VirtualConsole } = require('jsdom');

// SECURITY_TEST_ROOT lets the mutation tester point the suites at a mutated copy of the
// repository (see mutation-test.js) without ever touching the real files.
const REPO_ROOT = process.env.SECURITY_TEST_ROOT
    ? path.resolve(process.env.SECURITY_TEST_ROOT)
    : path.resolve(__dirname, '..', '..');
const SUPABASE_URL = 'https://xlmsgtxyrlovjobwvdom.supabase.co';

const readRepo = (rel) => fs.readFileSync(path.join(REPO_ROOT, rel), 'utf8');
const readAbs = (p) => fs.readFileSync(p, 'utf8');

function jsonResponse(body, status = 200) {
    return {
        ok: status >= 200 && status < 300,
        status,
        json: async () => body,
        text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
        headers: { get: () => 'application/json' },
    };
}

/** jsdom gaps that the pages legitimately rely on in a browser */
function installShims(window) {
    if (!Object.getOwnPropertyDescriptor(window.HTMLElement.prototype, 'innerText')) {
        Object.defineProperty(window.HTMLElement.prototype, 'innerText', {
            get() { return this.textContent; },
            set(v) { this.textContent = String(v); },
            configurable: true,
        });
    }
    window.Element.prototype.scrollIntoView = function () { };
    if (!window.navigator.sendBeacon) window.navigator.sendBeacon = () => true;
}

/**
 * @param {string} html      raw html source
 * @param {object} options   { url, responder(record, window) -> response|undefined }
 */
function makeDom(html, { url = 'https://schools.example.com/', responder } = {}) {
    const calls = [];
    // jsdom cannot fetch the CDN bundles (Tailwind), which makes the pages log a
    // ReferenceError for `tailwind.config`. Keep that noise out of the report but let
    // every other uncaught page error through.
    const virtualConsole = new VirtualConsole();
    virtualConsole.on('jsdomError', (err) => {
        const msg = String(err && err.message);
        // expected in this environment, not a page defect:
        //  • jsdom cannot fetch the Tailwind CDN bundle,
        //  • jsdom cannot implement navigation, and the portal's logout() calls location.reload().
        if (/tailwind is not defined/i.test(msg)) return;
        if (/Not implemented: navigation/i.test(msg)) return;
        console.error('  \x1b[31m[page error]\x1b[0m', msg);
    });
    virtualConsole.on('error', () => { });
    const dom = new JSDOM(html, {
        runScripts: 'dangerously',
        url,
        pretendToBeVisual: true,
        virtualConsole,
        beforeParse(window) {
            installShims(window);
            window.__calls = calls;
            window.fetch = async (input, opts = {}) => {
                const record = {
                    method: (opts.method || 'GET').toUpperCase(),
                    url: String(input),
                    path: String(input).replace(SUPABASE_URL, ''),
                    body: opts.body,
                    headers: opts.headers || {},
                    window,
                };
                calls.push(record);
                if (responder) {
                    const res = responder(record, window);
                    if (res) return res;
                }
                return jsonResponse([]);
            };
        },
    });
    const win = dom.window;
    return {
        dom, win, doc: win.document, calls,
        close: async () => {
            // Pages legitimately fire un-awaited follow-up requests (e.g. reload a list
            // after a delete). Let those settle first, then neutralise the network so no
            // continuation can touch a torn-down document and crash the run.
            try { await settle(win, { quietFor: 20, timeout: 300 }); } catch (e) { }
            try { win.fetch = () => new Promise(() => { }); } catch (e) { }
            try { win.close(); } catch (e) { }
        },
    };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitUntil(predicate, { timeout = 4000, step = 10 } = {}) {
    const start = Date.now();
    while (Date.now() - start < timeout) {
        try { if (predicate()) return true; } catch (e) { /* keep polling */ }
        await sleep(step);
    }
    return false;
}

/** wait until the page has stopped issuing requests and the microtask queue drained */
async function settle(win, { quietFor = 60, timeout = 5000 } = {}) {
    let last = win.__calls ? win.__calls.length : 0;
    let quietSince = Date.now();
    const start = Date.now();
    while (Date.now() - start < timeout) {
        await sleep(15);
        const now = win.__calls ? win.__calls.length : 0;
        if (now !== last) { last = now; quietSince = Date.now(); }
        else if (Date.now() - quietSince >= quietFor) return true;
    }
    return false;
}

/**
 * The containers that receive database content. Scanning these — rather than <body> —
 * keeps the page's own <script>/<form> elements out of the findings, so a positive
 * result always means *stored content* produced something dangerous.
 */
const RENDER_CONTAINERS = {
    'xyz_school.html': ['#topBar', '#siteHeader', '#hero', '#marqueeText', '#about', '#leadersGrid',
        '#topperGrid', '#facilityGrid', '#staffGrid', '#feeTable', '#achieveGrid', '#testGrid',
        '#galleryGrid', '#dlGrid', '#topSocial', '#footSocial', '#footContact'],
    'admin.html': ['#l-notices', '#l-toppers', '#l-galleries', '#l-facilities', '#l-downloads',
        '#l-fee_structures', '#l-staff_members', '#l-achievements', '#l-testimonials', '#l-inquiries'],
    'master_panel.html': ['#schoolTableBody', '#toastContainer'],
};

function scanRendered(doc, page) {
    const out = [];
    for (const sel of (RENDER_CONTAINERS[page] || [])) {
        const el = doc.querySelector(sel);
        if (!el) continue;
        for (const f of dangerousNodes(el)) out.push(`${sel}: ${f}`);
    }
    return out;
}

// ── detectors ───────────────────────────────────────────────────────────────
const DENY_TAGS = new Set([
    'script', 'iframe', 'object', 'embed', 'applet', 'base', 'meta', 'link', 'style',
    'template', 'noscript', 'xmp', 'plaintext', 'isindex', 'form', 'svg', 'math',
    'marquee', 'video', 'audio', 'source', 'track', 'frame', 'frameset', 'portal',
]);
const URL_ATTRS = ['src', 'href', 'action', 'formaction', 'data', 'xlink:href', 'poster', 'background', 'cite', 'longdesc', 'srcset'];
const DANGEROUS_URL_RE = /^[\s\u0000-\u001f]*(javascript|vbscript|data\s*:\s*text\/html)/i;

const snippet = (el) => String(el.outerHTML || '').replace(/\s+/g, ' ').slice(0, 140);

/**
 * Returns a list of human-readable findings for anything in `root` that could
 * execute script or load attacker-controlled resources.
 */
function dangerousNodes(root) {
    const findings = [];
    if (!root) return ['(missing root element)'];
    const walk = (el) => {
        const tag = (el.tagName || '').toLowerCase();
        if (DENY_TAGS.has(tag)) findings.push(`<${tag}> element → ${snippet(el)}`);
        if (['input', 'select', 'textarea', 'button'].includes(tag) && el.hasAttribute && el.hasAttribute('autofocus')) {
            findings.push(`autofocus on <${tag}> → ${snippet(el)}`);
        }
        for (const name of (el.getAttributeNames ? el.getAttributeNames() : [])) {
            const value = el.getAttribute(name) || '';
            if (/^on/i.test(name)) findings.push(`${name} handler on <${tag}> → ${snippet(el)}`);
            else if (name === 'srcdoc') findings.push(`srcdoc on <${tag}> → ${snippet(el)}`);
            else if (URL_ATTRS.includes(name) && DANGEROUS_URL_RE.test(value)) findings.push(`unsafe ${name}="${value.slice(0, 60)}" on <${tag}>`);
            else if (name === 'style' && /(expression\s*\(|javascript:|vbscript:)/i.test(value)) findings.push(`unsafe style="${value.slice(0, 60)}"`);
        }
        for (const child of (el.children || [])) walk(child);
    };
    walk(root);
    return findings;
}

/** any payload that managed to run would leave one of these behind */
const EXECUTION_MARKERS = ['__xss', '__pwned', '__poc', '__hacked', 'xssRan'];
function executedMarkers(win) {
    return EXECUTION_MARKERS.filter((m) => typeof win[m] !== 'undefined');
}

/** links that open a new tab must not hand over window.opener */
function unsafeTargetBlank(root) {
    const out = [];
    for (const a of root.querySelectorAll('a[target="_blank"]')) {
        const rel = (a.getAttribute('rel') || '').toLowerCase();
        if (!rel.includes('noopener') && !rel.includes('noreferrer')) out.push(snippet(a));
    }
    return out;
}

// ── mocked Supabase ────────────────────────────────────────────────────────
/**
 * Builds a responder that emulates the postgrest endpoints the pages use.
 * `routes` may override any handler: { token, user, schools, rows(table), inquiries, rpc }
 */
function supabaseResponder(routes = {}) {
    const config = {
        token: { access_token: 'test-token', user: { id: 'uid-1', email: 'owner@school.test' } },
        user: { id: 'uid-1', email: 'owner@school.test' },
        schools: [{ id: 'school-1', school_name: 'Test School', api_key: 'key-1', owner_id: 'uid-1' }],
        rows: () => [],
        rpcStatus: 404,
        ...routes,
    };
    const calls = [];
    const responder = (rec) => {
        calls.push(rec);
        const { path: p, method } = rec;
        if (config.hook && config.hook(rec) === true) return undefined;   // let the test own this one
        if (p.startsWith('/auth/v1/token')) {
            if (typeof config.tokenStatus === 'number' && config.tokenStatus >= 400) return jsonResponse({ error: 'invalid_grant' }, config.tokenStatus);
            return jsonResponse(config.token);
        }
        if (p.startsWith('/auth/v1/user')) {
            if (typeof config.userStatus === 'number' && config.userStatus >= 400) return jsonResponse({}, config.userStatus);
            return jsonResponse(config.user);
        }
        if (p.includes('/rest/v1/rpc/')) {
            if (config.rpcStatus !== 200) return jsonResponse({ message: 'function not found' }, config.rpcStatus);
            return jsonResponse(config.rpc || []);
        }
        const m = p.match(/\/rest\/v1\/([a-z_]+)/);
        if (m) {
            const table = m[1];
            const override = (config.tables || {})[table];
            if (override === 'error') return jsonResponse({ message: 'boom' }, 500);
            if (override && typeof override === 'object' && !Array.isArray(override)) return jsonResponse(override.body, override.status);
            const rows = Array.isArray(override) ? override : (table === 'schools' ? config.schools : config.rows(table, method));
            // writes answer 201/204 by default; writeStatus forces an error status so the
            // suite can check how the UI reports a rejected write
            if (rec.method === 'POST' || rec.method === 'PATCH' || rec.method === 'DELETE') {
                if (config.captureWrites) config.captureWrites.push(rec);
                const forced = config.writeStatus && config.writeStatus >= 400 ? config.writeStatus : null;
                if (rec.method === 'DELETE') return jsonResponse(null, forced || 204);
                const body = Array.isArray(rows) ? rows : (rows && typeof rows === 'object' && !Array.isArray(rows) && rec.method === 'POST' ? rows : null);
                return jsonResponse(body, forced || 201);
            }
            return jsonResponse(rows);
        }
        return jsonResponse([]);
    };
    responder.calls = calls;
    responder.config = config;
    return responder;
}

module.exports = {
    REPO_ROOT, SUPABASE_URL,
    readRepo, readAbs,
    makeDom, sleep, waitUntil, settle,
    dangerousNodes, executedMarkers, unsafeTargetBlank, snippet,
    RENDER_CONTAINERS, scanRendered,
    jsonResponse, supabaseResponder,
    DENY_TAGS,
};
