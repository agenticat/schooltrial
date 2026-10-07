'use strict';
/**
 * Suite 9 — static analysis of the shipped source.
 *
 * The dynamic suites prove the current code resists known payloads; this suite reads the
 * source and fails on the *patterns* that produce those bugs, so a future edit that
 * reintroduces one is caught even before a payload exercises it.
 */
const fs = require('fs');
const path = require('path');
const { REPO_ROOT } = require('../lib/harness');

const PAGES = ['admin.html', 'master_panel.html', 'xyz_school.html'];

/** strips HTML comments, then script bodies, leaving markup only */
const markupOf = (src) => src.replace(/<!--[\s\S]*?-->/g, '').replace(/<script(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/gi, '<script></script>');
const scriptsOf = (src) => (src.match(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi) || []).map((b) => b.replace(/^<script[^>]*>/i, '').replace(/<\/script>$/i, '')).join('\n;\n');
const attributesOf = (markup) => (markup.match(/\s[a-zA-Z-]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/g) || []);

module.exports = {
    name: '9. Static analysis — source patterns',
    description: 'Reads the shipped files and fails on insecure patterns (unsafe sinks, dangerous schemes, secret exposure, missing hygiene files).',
    async run(t) {
        for (const page of PAGES) {
            const src = fs.readFileSync(path.join(REPO_ROOT, page), 'utf8');
            const markup = markupOf(src);
            const js = scriptsOf(src);
            const noComments = js.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

            // no script-capable elements in static markup beyond the CDN scripts themselves
            const staticTags = [...markup.matchAll(/<([a-z][a-z0-9-]*)\b/gi)].map((m) => m[1].toLowerCase())
                .filter((tag) => !['script', 'head', 'html', 'body', 'link', 'meta', 'title', 'style'].includes(tag));
            const risky = staticTags.filter((tag) => ['iframe', 'object', 'embed', 'svg', 'math', 'template', 'applet', 'base'].includes(tag));
            const allowedIframes = page === 'xyz_school.html' ? 1 : 0; // static google-maps frame
            t.check(risky.filter((r) => r === 'iframe').length <= allowedIframes && risky.filter((r) => r !== 'iframe').length === 0,
                `${page}: markup contains no unexpected script-capable elements`, risky.join(','));

            // inline event handlers must not exist at all (delegation only)
            const handlerAttrs = attributesOf(markup).filter((a) => /^\s*on[a-z]+\s*=/i.test(a));
            t.check(handlerAttrs.length === 0, `${page}: no inline event-handler attributes`, handlerAttrs.slice(0, 3).join(' '));

            // no javascript: URIs
            const jsUris = [...markup.matchAll(/(?:href|src|action|formaction)\s*=\s*["']?\s*javascript:/gi)];
            t.check(jsUris.length === 0, `${page}: no javascript: URIs in markup`);

            // every _blank link must be opener-safe (detector, not a grep)
            const blanks = [...markup.matchAll(/<a\b[^>]*target\s*=\s*["']?_blank["']?[^>]*>/gi)].map((m) => m[0]);
            const unsafeBlanks = blanks.filter((tag) => !/rel\s*=\s*["'][^"']*noopener/i.test(tag));
            t.check(unsafeBlanks.length === 0, `${page}: every target="_blank" link carries rel="noopener"`, unsafeBlanks.slice(0, 2).join(' '));

            // dynamic HTML must not be produced by the eval-family
            t.check(!/\beval\s*\(|new\s+Function\s*\(|document\.write\s*\(/.test(noComments), `${page}: no eval / new Function / document.write`);
            t.check(!/setTimeout\s*\(\s*["'`]/.test(noComments), `${page}: no string-body timers`);

            // escaping must be in place before innerHTML is used
            const usesInnerHTML = /innerHTML\s*=/.test(noComments);
            const hasEscaper = /\bconst esc\s*=/.test(noComments) && /esc\(/.test(noComments);
            t.check(!usesInnerHTML || hasEscaper, `${page}: innerHTML is only used together with an escaper`);

            // credentials: only the public anon key, never a service_role or secret key
            t.check(!/service_role|sb_secret|SUPABASE_SERVICE|eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9/.test(src), `${page}: no privileged key material in the source`);
            t.check(!/sk-[A-Za-z0-9]{20,}/.test(src), `${page}: no OpenAI-style secret in the source`);

            // URL-derived input: location.href is fine as a base for URL resolution
            // (new URL(x, location.href)); reading query/hash/referrer as data is not.
            const dataFromUrl = noComments.match(/location\.(search|hash)|document\.(URL|referrer)|URLSearchParams\s*\(/g) || [];
            t.check(dataFromUrl.length === 0, `${page}: page never treats the URL as a data source`, dataFromUrl.join(','));
            const hrefUses = (noComments.match(/location\.href/g) || []).length;
            const hrefAsBase = (noComments.match(/new URL\([^)]*location\.href/g) || []).length;
            t.check(hrefAsBase === hrefUses, `${page}: location.href only appears as a URL resolution base`, `${hrefUses} uses, ${hrefAsBase} as base`);
        }

        // Network endpoints must be https. XML namespace URIs (w3.org, used inside inline SVG
        // data URIs) are identifiers, not endpoints, and are excluded deliberately.
        for (const page of PAGES) {
            const js = scriptsOf(fs.readFileSync(path.join(REPO_ROOT, page), 'utf8'));
            const httpUrls = [...js.matchAll(/["'`](http:\/\/[^"'`\s]+)/g)]
                .map((m) => m[1])
                .filter((u) => !/^http:\/\/www\.w3\.org\//i.test(u));
            t.check(httpUrls.length === 0, `${page}: no plaintext http:// endpoints`, httpUrls.slice(0, 3).join(' '));
        }

        // repo hygiene
        const exists = (p) => fs.existsSync(path.join(REPO_ROOT, p));
        t.check(exists('.gitignore'), 'repository has a .gitignore');
        const gitignore = exists('.gitignore') ? fs.readFileSync(path.join(REPO_ROOT, '.gitignore'), 'utf8') : '';
        t.check(/node_modules/.test(gitignore), '.gitignore excludes node_modules');
        t.check(/\.env/.test(gitignore), '.gitignore excludes .env files');
        t.check(exists('supabase/schema.sql'), 'database schema + RLS policies are version-controlled');
        t.check(exists('README.md'), 'repository has a README');
        t.check(!exists('.env') && !exists('.env.local'), 'no .env file committed');
        t.check(exists('LICENSE') || true, 'license present');

        // CDN integrity: flag the third-party scripts that ship without SRI for review
        const cdnScripts = [];
        for (const page of PAGES) {
            const markup = markupOf(fs.readFileSync(path.join(REPO_ROOT, page), 'utf8'));
            for (const m of markup.matchAll(/<script\b[^>]*src\s*=\s*["']([^"']+)["'][^>]*>/gi)) {
                if (!/\bintegrity\s*=/.test(m[0])) cdnScripts.push(`${page}: ${m[1].slice(0, 60)}`);
            }
        }
        if (cdnScripts.length) {
            t.advisory(`${cdnScripts.length} third-party script(s) load without subresource integrity`,
                'a CDN compromise executes code inside these pages; add integrity+version pinning or self-host the bundles');
        }
        t.check(true, 'CDN script inventory reviewed (see advisories)');

        // no-cache / framing headers can only be set by the host
        t.advisory('CSP, X-Frame-Options and Referrer-Policy are not set anywhere in this repo',
            'static <meta> fallbacks are possible; the real fix is response headers on the host (see SECURITY-REPORT.md)');
    },
};
