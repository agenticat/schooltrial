'use strict';
/**
 * Mutation testing — "who tests the tests?"
 *
 * A green suite proves nothing unless it can fail. This script injects the classic
 * vulnerabilities back into copies of the pages (escaping removed, URL checks removed,
 * queries unencoded, auth probe bypassed, token stored insecurely) and re-runs the
 * suites. Every mutation that is NOT caught is a blind spot in the test suite.
 *
 * The repository files are never modified: mutated copies are written to a temp dir and
 * the child test run is pointed at them via SECURITY_TEST_ROOT.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');

const MUTATIONS = [
    {
        id: 'M1',
        name: 'remove HTML escaping from the public site',
        page: 'xyz_school.html',
        apply: (s) => s.replace(
            "const esc = s => String(s ?? '').replace(/[&<>\"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;' }[c]));",
            "const esc = s => String(s ?? '');"),
        expectSuite: '01',
    },
    {
        id: 'M2',
        name: 'remove HTML escaping from the admin portal',
        page: 'admin.html',
        apply: (s) => s.replace(
            "const esc = s => String(s ?? '').replace(/[&<>\"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;' }[c]));",
            "const esc = s => String(s ?? '');"),
        expectSuite: '02',
    },
    {
        id: 'M3',
        name: 'disable URL protocol checking on the public site',
        page: 'xyz_school.html',
        apply: (s) => s.replace(
            "const safeUrl = u => { const s = String(u ?? '').trim(); if (!s) return ''; try { const x = new URL(s, location.href); return (x.protocol === 'http:' || x.protocol === 'https:') ? x.href : ''; } catch { return ''; } };",
            "const safeUrl = u => String(u ?? '').trim();"),
        expectSuite: '04',
    },
    {
        id: 'M4',
        name: 'disable URL protocol checking in the admin portal',
        page: 'admin.html',
        apply: (s) => s.replace(
            "const safeUrl = u => { const s = String(u ?? '').trim(); if (!s) return ''; try { const x = new URL(s, location.href); return (x.protocol === 'http:' || x.protocol === 'https:') ? x.href : ''; } catch { return ''; } };",
            "const safeUrl = u => String(u ?? '').trim();"),
        expectSuite: '04',
    },
    {
        id: 'M5',
        name: 'stop percent-encoding PostgREST filter values',
        page: 'admin.html',
        apply: (s) => s.replace(
            "const q = s => encodeURIComponent(String(s ?? ''));",
            "const q = s => String(s ?? '');"),
        expectSuite: '05',
    },
    {
        id: 'M6',
        name: 'drop the tenant filter from writes',
        page: 'admin.html',
        apply: (s) => s.replace("&school_id=eq.${q(sid())}`", "`")
            .replace('?id=eq.${q(id)}&school_id=eq.${q(sid())}', '?id=eq.${q(id)}'),
        expectSuite: '08',
    },
    {
        id: 'M7',
        name: 'bypass the super-admin authorization probe',
        page: 'master_panel.html',
        apply: (s) => s.replace(
            "                if (r.ok) {\n                    const d = await r.json();\n                    return { allowed: Array.isArray(d) && d.length > 0, tableMissing: false };\n                }",
            "                if (r.ok) {\n                    const d = await r.json();\n                    return { allowed: true, tableMissing: false };\n                }"),
        expectSuite: '07',
    },
    {
        id: 'M8',
        name: 'make escaping a no-op in the super-admin console',
        page: 'master_panel.html',
        apply: (s) => s.replace(
            "const esc = s => String(s ?? '').replace(/[&<>\"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', \"'\": '&#39;' }[c]));",
            "const esc = s => String(s ?? '');"),
        expectSuite: '03',
    },
    {
        id: 'M9',
        name: 'treat any API response as a valid session (no re-auth on 401)',
        page: 'admin.html',
        apply: (s) => s.replace(/if \(r\.status === 401 \|\| r\.status === 403\) return forceLogin\('Your session has expired\. Please sign in again\.'\);\n\s*if \(!r\.ok\) \{ el\.innerHTML/, "if (false) return forceLogin('x');\n        if (!r.ok) { el.innerHTML"),
        expectSuite: '06',
    },
    {
        id: 'M10',
        name: 'accept any school returned by the API on login (no owner check)',
        page: 'admin.html',
        apply: (s) => s.replace(
            "const r = await fetch(`${SB}/rest/v1/schools?owner_id=eq.${q(authData.user.id)}&select=*`, { headers: getH() });",
            "const r = await fetch(`${SB}/rest/v1/schools?select=*`, { headers: getH() });"),
        expectSuite: '06',
    },
];

function runSuite(only, root) {
    const args = [path.join(__dirname, 'run-all.js'), '--quiet'];
    if (only) args.push('--only', only);
    try {
        const out = execFileSync(process.execPath, args, {
            encoding: 'utf8',
            env: { ...process.env, SECURITY_TEST_ROOT: root },
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        return { code: 0, out };
    } catch (err) {
        return { code: err.status === undefined ? 1 : err.status, out: String(err.stdout || '') + String(err.stderr || '') };
    }
}

console.log('\n╔══════════════════════════════════════════════════════════════════════════╗');
console.log('║  mutation testing — injecting real vulnerabilities into copies of the code');
console.log('╚══════════════════════════════════════════════════════════════════════════╝\n');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'schooltrial-mut-'));
const pages = ['admin.html', 'master_panel.html', 'xyz_school.html'];
for (const p of pages) fs.copyFileSync(path.join(ROOT, p), path.join(tmp, p));
fs.mkdirSync(path.join(tmp, 'supabase'), { recursive: true });
for (const p of fs.readdirSync(path.join(ROOT, 'supabase'))) fs.copyFileSync(path.join(ROOT, 'supabase', p), path.join(tmp, 'supabase', p));
fs.copyFileSync(path.join(ROOT, '.gitignore'), path.join(tmp, '.gitignore'));
if (fs.existsSync(path.join(ROOT, 'README.md'))) fs.copyFileSync(path.join(ROOT, 'README.md'), path.join(tmp, 'README.md'));
if (fs.existsSync(path.join(ROOT, 'LICENSE'))) fs.copyFileSync(path.join(ROOT, 'LICENSE'), path.join(tmp, 'LICENSE'));

console.log('baseline (unmutated copy) vs every suite:');
const baseline = runSuite(null, tmp);
const baselineOk = baseline.code === 0;
const baselineCases = parseInt((baseline.out.match(/\((\d+) test cases\)/) || [])[1] || '0', 10);
console.log(`  baseline ran ${baselineCases} cases`);
console.log(`  ${baselineOk && baselineCases > 0 ? '\x1b[32m✓ baseline passes\x1b[0m' : '\x1b[31m✗ baseline FAILS or ran nothing — fix the harness before trusting mutations\x1b[0m'}\n`);
if (!baselineOk || baselineCases === 0) process.exitCode = 1;

let caught = 0;
const escapes = [];
for (const m of MUTATIONS) {
    const file = path.join(tmp, m.page);
    const original = fs.readFileSync(path.join(ROOT, m.page), 'utf8');
    const mutated = m.apply(original);
    if (mutated === original) {
        console.log(`  \x1b[33m? ${m.id} ${m.name}\x1b[0m — mutation did not apply (source changed?), skipping`);
        escapes.push({ ...m, reason: 'not applied' });
        continue;
    }
    fs.writeFileSync(file, mutated);
    const res = runSuite(m.expectSuite, tmp);
    // A child only counts as a real detection if it produced a summary AND that summary
    // covers a non-zero number of cases. A crash or an empty run is a blind spot.
    const cases = parseInt((res.out.match(/\((\d+) test cases\)/) || [])[1] || '0', 10);
    const completed = /TOTAL/.test(res.out) && cases > 0;
    const detected = res.code !== 0 && completed;
    if (detected) { caught++; console.log(`  \x1b[32m✓ ${m.id} caught\x1b[0m — ${m.name} (suite ${m.expectSuite})`); }
    else if (!completed) { console.log(`  \x1b[31m✗ ${m.id} ERROR\x1b[0m — suite ${m.expectSuite} did not run/report (cases=${cases}); treating as a blind spot`); escapes.push({ ...m, reason: 'suite did not run' }); }
    else { console.log(`  \x1b[31m✗ ${m.id} ESCAPED\x1b[0m — ${m.name} (suite ${m.expectSuite} stayed green)`); escapes.push(m); }
    fs.writeFileSync(file, original);
}

console.log(`\n  mutation score: ${caught}/${MUTATIONS.length} injected vulnerabilities detected`);
if (escapes.length) {
    console.log('\n  escapes (test blind spots):');
    for (const e of escapes) console.log(`    • ${e.id} ${e.name}`);
}
fs.rmSync(tmp, { recursive: true, force: true });
console.log('');
process.exitCode = escapes.length ? 1 : 0;
