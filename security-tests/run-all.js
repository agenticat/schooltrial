'use strict';
/**
 * Orchestrates every suite, prints totals, and writes sec-results.json for the report.
 *   node run-all.js            full detail
 *   node run-all.js --quiet     summary only
 *   node run-all.js --only 06   single suite (prefix match)
 */
const fs = require('fs');
const path = require('path');
const { Runner } = require('./lib/runner');

const SUITE_FILES = [
    '01-xss-public.js',
    '02-xss-admin.js',
    '03-xss-master.js',
    '04-url-sinks.js',
    '05-query-injection.js',
    '06-auth-session.js',
    '07-auth-master.js',
    '08-tenant-scoping.js',
    '09-static-analysis.js',
];

// A security suite that dies must not look like a pass. Record crashes as failures and
// always print the summary.
process.on('unhandledRejection', (err) => {
    const runner = global.__runner;
    const msg = 'unhandled rejection: ' + ((err && err.message) || String(err));
    if (runner) runner.check(false, msg, err && err.stack && err.stack.split('\n')[1]);
    else { console.error('FATAL ' + msg); process.exitCode = 1; }
});
process.on('uncaughtException', (err) => {
    const runner = global.__runner;
    const msg = 'uncaught exception: ' + ((err && err.message) || String(err));
    if (runner) runner.check(false, msg, err && err.stack && err.stack.split('\n')[1]);
    else { console.error('FATAL ' + msg); process.exitCode = 1; }
});

(async () => {
    const args = process.argv.slice(2);
    const quiet = args.includes('--quiet');
    const onlyIdx = args.indexOf('--only');
    // accept --only 4 and --only 04; suite files are zero-padded
    const only = onlyIdx >= 0 ? String(args[onlyIdx + 1]).padStart(2, '0') : null;

    const files = only ? SUITE_FILES.filter((f) => f.startsWith(only)) : SUITE_FILES;
    if (only && files.length === 0) {
        console.error(`No suite matches --only ${only}. Available: ${SUITE_FILES.join(', ')}`);
        process.exitCode = 1;
        return;
    }
    const runner = new Runner({ quiet });
    global.__runner = runner;
    const started = Date.now();

    console.log('\n╔══════════════════════════════════════════════════════════════════════════╗');
    console.log('║  schooltrial — adversarial security test suite                           ║');
    console.log(`║  ${new Date().toISOString().padEnd(72)}║`);
    console.log('╚══════════════════════════════════════════════════════════════════════════╝');

    for (const file of files) {
        const suite = require(path.join(__dirname, 'suites', file));
        const t0 = Date.now();
        runner.suite(suite.name, suite.description);
        try {
            await suite.run(runner);
        } catch (err) {
            runner.check(false, `${suite.name}: suite crashed — ${err && err.message}`, err && err.stack && err.stack.split('\n').slice(0, 3).join(' / '));
        }
        if (!quiet) console.log(`  (${((Date.now() - t0) / 1000).toFixed(1)}s)`);
    }

    const summary = runner.report();
    summary.durationMs = Date.now() - started;
    summary.generatedAt = new Date().toISOString();
    summary.advisories = runner.advisories;

    fs.writeFileSync(path.join(__dirname, 'sec-results.json'), JSON.stringify(summary, null, 2));
    console.log(`Wrote sec-results.json  •  ${summary.total} cases in ${(summary.durationMs / 1000).toFixed(1)}s  •  ${summary.fail} failing  •  ${summary.advisories.length} advisory`);
    // set exitCode instead of calling process.exit(): on a piped stdout, exit() can
    // truncate buffered output and swallow the summary
    process.exitCode = summary.fail ? 1 : 0;
})();
