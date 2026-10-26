import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { CompanyId, DeviceId } from '@work-dns/shared-types';
import { SqliteEventStore } from '../src/sqlite-store.js';
import { Ed25519Signer, createCheckpoint, publicKeyIdOf } from '../src/checkpoint.js';
import { buildReport, eventsToCsv, filterEvents, formatReportText, CSV_COLUMNS } from '../src/audit-report.js';

const A = 'comp-a' as CompanyId;
const D1 = 'dev-1' as DeviceId;
const D2 = 'dev-2' as DeviceId;

describe('audit report', () => {
    let dir: string;
    let store: SqliteEventStore;
    let tick: number;
    let signer: Ed25519Signer;
    let keys: Record<string, string>;
    const clock = () => new Date(Date.UTC(2026, 9, 24, 10, tick++, 0));

    const block = (id: string, domain: string, opts: { device?: DeviceId; user?: string; count?: number } = {}) =>
        store.append({
            id,
            type: 'dns_blocked',
            companyId: A,
            deviceId: opts.device ?? D1,
            payload: { domain, loggedOsUser: opts.user ?? 'unknown', policyVersion: 1, reasonCode: 'DEFAULT_DENY', count: opts.count ?? 1 },
        });

    const started = (id: string) =>
        store.append({ id, type: 'agent_started', companyId: A, deviceId: D1, payload: { agentVersion: '0.1.0' } });

    function withRaw(fn: (db: DatabaseSync) => void): void {
        const db = new DatabaseSync(path.join(dir, 'audit.db'));
        try {
            fn(db);
        } finally {
            db.close();
        }
    }

    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-report-'));
        tick = 0;
        store = new SqliteEventStore(path.join(dir, 'audit.db'), { now: clock });
        signer = new Ed25519Signer();
        keys = { [signer.keyId]: signer.publicKeyPem };
    });

    afterEach(() => {
        store.close();
        fs.rmSync(dir, { recursive: true, force: true });
    });

    it('filters by device, domain (with subdomains), type and time range', () => {
        block('e1', 'facebook.com', { device: D1 });
        block('e2', 'www.facebook.com', { device: D2 });
        block('e3', 'twitter.com', { device: D1 });
        started('e4');
        const all = store.readAll(A);
        const ids = (events: typeof all) => events.map((e) => e.id);
        expect(ids(filterEvents(all, { deviceId: D1 }))).toEqual(['e1', 'e3', 'e4']);
        expect(ids(filterEvents(all, { domain: 'facebook.com' }))).toEqual(['e1', 'e2']);
        expect(ids(filterEvents(all, { domain: 'book.com' }))).toEqual([]);
        expect(ids(filterEvents(all, { types: ['agent_started'] }))).toEqual(['e4']);
        expect(ids(filterEvents(all, { from: '2026-10-24T10:01:00Z', to: '2026-10-24T10:03:00Z' }))).toEqual(['e2', 'e3']);
    });

    it('rejects an invalid date', () => {
        expect(() => filterEvents([], { from: 'not-a-date' })).toThrow(/not a valid date/);
    });

    it('exports CSV with quoting and spreadsheet formula protection', () => {
        block('e1', 'a,b"c.example.com');
        block('e2', '=cmd|calc.example.com');
        started('e3');
        const csv = eventsToCsv(store.readAll(A));
        const lines = csv.trimEnd().split('\n');
        expect(lines[0]).toBe(CSV_COLUMNS.join(','));
        expect(csv).toContain('"a,b""c.example.com"');
        expect(csv).toContain("'=cmd|calc.example.com");
        expect(lines.find((l) => l.includes(',agent_started,'))).toMatch(/,agent_started,dev-1,,,/);
    });

    it('reports verified integrity, counts and top domains', () => {
        block('e1', 'facebook.com', { count: 2 });
        block('e2', 'twitter.com', { user: 'alice' });
        block('e3', 'facebook.com', { count: 3 });
        started('e4');
        const cp = createCheckpoint(store, A, signer, null);
        expect(publicKeyIdOf(signer.publicKeyPem)).toBe(signer.keyId);
        const report = buildReport(store, A, { checkpoints: [cp], publicKeys: keys, now: () => new Date('2026-10-24T12:00:00Z') });
        expect(report.integrity).toBe('verified');
        expect(report.generatedAt).toBe('2026-10-24T12:00:00.000Z');
        expect(report.totalEvents).toBe(4);
        expect(report.blockedAttempts).toBe(6);
        expect(report.byType).toEqual({ dns_blocked: 3, agent_started: 1 });
        expect(report.topDomains).toEqual([
            { domain: 'facebook.com', attempts: 5 },
            { domain: 'twitter.com', attempts: 1 },
        ]);
        expect(report.unattributedBlocks).toBe(2);
        expect(report.caveats.some((c) => /no verified OS user/.test(c))).toBe(true);
        expect(formatReportText(report)).toContain('Integrity: VERIFIED');
    });

    it('is partial when events are newer than the last checkpoint', () => {
        block('e1', 'a.example.com');
        block('e2', 'b.example.com');
        const cp = createCheckpoint(store, A, signer, null);
        block('e3', 'c.example.com');
        const report = buildReport(store, A, { checkpoints: [cp], publicKeys: keys });
        expect(report.integrity).toBe('partial');
        expect(report.checkpoints).toMatchObject({ supplied: true, valid: true, unanchoredEvents: 1 });
        expect(report.caveats.some((c) => /newer than the last checkpoint/.test(c))).toBe(true);
    });

    it('is partial, with a caveat, when no checkpoints are supplied', () => {
        block('e1', 'a.example.com');
        const report = buildReport(store, A);
        expect(report.integrity).toBe('partial');
        expect(report.checkpoints.supplied).toBe(false);
        expect(report.caveats.some((c) => /No checkpoints/.test(c))).toBe(true);
    });

    it('fails when an event was edited', () => {
        block('e1', 'a.example.com');
        block('e2', 'b.example.com');
        block('e3', 'c.example.com');
        const cp = createCheckpoint(store, A, signer, null);
        withRaw((db) => {
            db.exec('DROP TRIGGER events_no_update');
            db.prepare("UPDATE events SET payload = ? WHERE id = 'e2'").run(JSON.stringify({ domain: 'edited.example.com' }));
        });
        const report = buildReport(store, A, { checkpoints: [cp], publicKeys: keys });
        expect(report.integrity).toBe('failed');
        expect(report.chain.valid).toBe(false);
        expect(formatReportText(report)).toContain('Integrity: FAILED');
    });

    it('fails when the newest events were deleted', () => {
        block('e1', 'a.example.com');
        block('e2', 'b.example.com');
        block('e3', 'c.example.com');
        const cp = createCheckpoint(store, A, signer, null);
        withRaw((db) => {
            db.exec('DROP TRIGGER events_no_delete');
            db.exec('DELETE FROM events WHERE sequence_number > 2');
        });
        const report = buildReport(store, A, { checkpoints: [cp], publicKeys: keys });
        expect(report.integrity).toBe('failed');
        expect(report.checkpoints).toMatchObject({ supplied: true, valid: false });
        expect(report.checkpoints.supplied && report.checkpoints.error).toMatch(/deleted/);
    });

    it('treats an empty log as partial, not verified', () => {
        const report = buildReport(store, A);
        expect(report.totalEvents).toBe(0);
        expect(report.chain.valid).toBe(true);
        expect(report.integrity).toBe('partial');
    });
});
