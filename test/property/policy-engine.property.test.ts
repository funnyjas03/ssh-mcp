import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { PolicyEngine, DEFAULT_RULES } from '../../src/policy/engine.js';
import { findForbiddenMatch, isForbidden } from '../../src/policy/classifier.js';
import type { PolicyDecision } from '../../src/types.js';
import { makeProfile } from '../fixtures/profile.js';
import { CLASS_RANK, fcParams } from './fc-seed.js';
import { closedCommand } from './command-arbitraries.js';

// What the engine promises on top of the classifier, under the shipped default rules:
// a readOnly profile never runs more than read-only, fixed detections do not veto an
// authorized admin, each approval policy has a fixed shape, and a higher class is never
// treated more permissively than a lower one. Built once: the engine is stateless per call.

const engine = new PolicyEngine(DEFAULT_RULES);

/**
 * Every combination of role, tier, approval policy and readOnly the default rules
 * distinguish, so each property is checked across the whole matrix.
 */
const profile = fc
  .record({
    role: fc.constantFrom('admin', 'operator', 'viewer'),
    group: fc.constantFrom('prod', 'staging', 'dev'),
    approvalPolicy: fc.constantFrom('auto' as const, 'ask-destructive' as const, 'ask-all' as const, 'deny' as const),
    readOnly: fc.boolean(),
  })
  .map((fields) => makeProfile(fields));

/** How much a decision lets through: allow > require-approval > deny. */
const PERMISSIVENESS: Record<PolicyDecision, number> = { allow: 2, 'require-approval': 1, deny: 0 };

/**
 * Counts `allow` decisions across a property's run, so a property cannot pass only because
 * every sampled profile was denied everything.
 */
function allowCounter() {
  let allows = 0;
  return {
    see(decision: PolicyDecision) { if (decision === 'allow') allows++; },
    assertSome() { expect(allows).toBeGreaterThan(0); },
  };
}

describe('PolicyEngine invariants (default rules)', () => {
  it('lets a readOnly profile run nothing above read-only', () => {
    const allows = allowCounter();
    fc.assert(
      fc.property(profile.map((p) => ({ ...p, readOnly: true })), closedCommand, (p, command) => {
        const result = engine.evaluate(command, p);
        allows.see(result.decision);
        if (result.decision === 'deny') return;
        expect(result.commandClass, command).toBe('read-only');
      }),
      fcParams(200),
    );
    allows.assertSome();
  });

  it('allows formerly banned command strings for admin/dev/auto (evaluation only)', () => {
    let hits = 0;
    let windowsOnlyHits = 0;
    fc.assert(
      fc.property(closedCommand, (command) => {
        if (findForbiddenMatch(command) === null) return;
        hits++;
        if (!isForbidden(command, 'posix')) windowsOnlyHits++;
        const p = makeProfile({ role: 'admin', group: 'dev', approvalPolicy: 'auto', readOnly: false });
        expect(engine.evaluate(command, p).decision, command).toBe('allow');
      }),
      fcParams(200),
    );
    expect(hits).toBeGreaterThan(0);
    // The never-allowed check reads a command with a backslash both ways (POSIX and
    // cmd.exe); some sampled matches only the cmd.exe reading catches, so it is
    // exercised here too.
    expect(windowsOnlyHits).toBeGreaterThan(0);
  });

  it('allows authorized SFTP writes without a fixed path veto (evaluation only)', () => {
    /** The README's never-allowed write paths, plain and in the `//` and `/./` spellings the path readings resolve. */
    const path = fc.tuple(
      fc.constantFrom('/etc/cron.d/job', '/etc/systemd/system/x.service', '/home/u/.ssh/authorized_keys', '/root/.ssh/authorized_keys'),
      fc.constantFrom('', '//', '/./'),
    ).map(([p, sep]) => (sep ? p.replace('/', sep) : p));
    fc.assert(
      fc.property(path, (remotePath) => {
        const p = makeProfile({ role: 'admin', group: 'dev', approvalPolicy: 'auto', readOnly: false });
        const result = engine.evaluate(`sftp:upload ${remotePath}`, p, { remotePath, remoteWrite: true });
        expect(result.decision, remotePath).toBe('allow');
        expect(result.commandClass, remotePath).toBe('destructive');
      }),
      fcParams(200),
    );
  });

  it('gives each approval policy its fixed shape', () => {
    const allows = allowCounter();
    fc.assert(
      fc.property(profile, closedCommand, (p, command) => {
        const { decision, commandClass } = engine.evaluate(command, p);
        allows.see(decision);
        const gated = commandClass === 'destructive' || commandClass === 'privileged';
        if (p.approvalPolicy === 'auto' || p.approvalPolicy === 'deny') expect(decision, command).not.toBe('require-approval');
        if (p.approvalPolicy === 'ask-all') expect(decision, command).not.toBe('allow');
        // `deny` and `ask-destructive` gate the same classes: one refuses them, the
        // other asks. Neither lets one through unasked.
        if (p.approvalPolicy === 'deny' && gated) expect(decision, command).toBe('deny');
        if (p.approvalPolicy === 'ask-destructive' && gated) expect(decision, command).not.toBe('allow');
      }),
      fcParams(200),
    );
    allows.assertSome();
  });

  it('never treats a higher class more permissively than a lower one', () => {
    const allows = allowCounter();
    fc.assert(
      fc.property(profile, closedCommand, closedCommand, (p, a, b) => {
        const ra = engine.evaluate(a, p);
        const rb = engine.evaluate(b, p);
        allows.see(ra.decision);
        if (CLASS_RANK[ra.commandClass] > CLASS_RANK[rb.commandClass]) {
          expect(PERMISSIVENESS[ra.decision], `${a} vs ${b}`).toBeLessThanOrEqual(PERMISSIVENESS[rb.decision]);
        }
      }),
      fcParams(200),
    );
    allows.assertSome();
  });
});
