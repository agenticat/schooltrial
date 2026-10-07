'use strict';
/**
 * Tiny zero-dependency test runner with per-suite and grand totals.
 * Every call to check() is one test case; the run exits non-zero if any fail.
 */

class Runner {
    constructor({ quiet = false } = {}) {
        this.pass = 0;
        this.fail = 0;
        this.failures = [];
        this.groups = [];
        this.current = null;
        this.quiet = quiet;
        this.advisories = [];
    }

    suite(name, description) {
        this.current = { name, description, pass: 0, fail: 0 };
        this.groups.push(this.current);
        if (!this.quiet) console.log(`\n\x1b[1m═══ ${name} ═══\x1b[0m\n${description}\n`);
    }

    check(condition, message, detail) {
        if (condition) {
            this.pass++;
            if (this.current) this.current.pass++;
            if (!this.quiet) console.log(`  \x1b[32m✓\x1b[0m ${message}`);
        } else {
            this.fail++;
            if (this.current) this.current.fail++;
            const entry = { suite: this.current ? this.current.name : '(none)', message, detail };
            this.failures.push(entry);
            console.log(`  \x1b[31m✗ FAIL\x1b[0m ${message}${detail ? `\n         ↳ ${detail}` : ''}`);
        }
        return condition;
    }

    /**
     * A non-blocking finding: real hardening advice that is a deployment/architecture
     * decision rather than an exploitable code defect. Counted separately and reported
     * at the end so it cannot be mistaken for a passing security control.
     */
    advisory(message, detail) {
        this.advisories.push({ suite: this.current ? this.current.name : '(none)', message, detail });
        console.log(`  \x1b[33m⚠ ADVISORY\x1b[0m ${message}${detail ? ` — ${detail}` : ''}`);
        return false;
    }

    /** counts a batch of payload cases without printing one line per case */
    batch(okCount, totalCount, message, exampleFailures = []) {
        if (okCount === totalCount) {
            this.check(true, `${message} (${okCount}/${totalCount})`);
        } else {
            this.check(false, `${message} — ${totalCount - okCount} of ${totalCount} cases FAILED`, exampleFailures.slice(0, 5).join(' | '));
        }
    }

    report() {
        const total = this.pass + this.fail;
        console.log('\n' + '─'.repeat(78));
        console.log('  SUITE                                   PASS    FAIL');
        console.log('─'.repeat(78));
        for (const g of this.groups) {
            console.log(`  ${g.name.padEnd(38)} ${String(g.pass).padStart(5)} ${String(g.fail).padStart(7)}`);
        }
        console.log('─'.repeat(78));
        console.log(`  ${'TOTAL'.padEnd(38)} ${String(this.pass).padStart(5)} ${String(this.fail).padStart(7)}  (${total} test cases)`);
        console.log('─'.repeat(78));
        if (this.fail) {
            console.log(`\n\x1b[31m${this.fail} FAILING CASE(S):\x1b[0m`);
            for (const f of this.failures) console.log(`  • [${f.suite}] ${f.message}${f.detail ? `\n      ↳ ${f.detail}` : ''}`);
        } else {
            console.log('\n\x1b[32mAll test cases passed.\x1b[0m');
        }
        if (this.advisories.length) {
            console.log(`\n\x1b[33m${this.advisories.length} advisory finding(s) (not failures — see SECURITY-REPORT.md):\x1b[0m`);
            for (const a of this.advisories) console.log(`  ⚠ [${a.suite}] ${a.message}${a.detail ? ` — ${a.detail}` : ''}`);
        }
        console.log('');
        return { total, pass: this.pass, fail: this.fail, advisories: this.advisories.length };
    }
}

module.exports = { Runner };
