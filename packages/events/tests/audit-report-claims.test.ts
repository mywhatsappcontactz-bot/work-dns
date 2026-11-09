import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { CompanyId, DeviceId } from '@work-dns/shared-types';
import { SqliteEventStore } from '../src/sqlite-store.js';
import { CSV_COLUMNS, buildReport, eventsToCsv, formatReportText } from '../src/audit-report.js';

const A = 'comp-a' as CompanyId;
const D = 'dev-1' as DeviceId;

describe('report: a named user is a claim', () => {
    let dir: string;
    let store: SqliteEventStore;

    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-claims-'));
        store = new SqliteEventStore(path.join(dir, 'audit.db'));
    });

    afterEach(() => {
        store.close();
        fs.rmSync(dir, { recursive: true, force: true });
    });

    const block = (id: string, domain: string, user: string, count = 1) =>
        store.append({
            id,
            type: 'dns_blocked',
            companyId: A,
            deviceId: D,
            payload: {
                domain,
                loggedOsUser: user,
                policyVersion: 1,
                reasonCode: 'DEFAULT_DENY_UNLISTED_DOMAIN',
                count,
                ...(user === 'unknown' ? {} : { loggedOsUserSource: 'device_reported' }),
            },
        });

    it('counts named entries separately and warns that the name is not proof of who made the request', () => {
        block('e1', 'a.example.com', 'berlin', 5);
        block('e2', 'b.example.com', 'berlin');
        block('e3', 'c.example.com', 'unknown');
        const report = buildReport(store, A);
        expect(report.claimedUserBlocks).toBe(2);
        expect(report.unattributedBlocks).toBe(1);
        expect(report.blockedAttempts).toBe(7);
        const claim = report.caveats.find((c) => /name a console user as reported by the device/.test(c));
        expect(claim).toBeDefined();
        expect(claim).toMatch(/not which program made the request/);
        expect(claim).toMatch(/cannot verify/);
        expect(report.caveats.some((c) => /no verified OS user/.test(c))).toBe(true);
        expect(formatReportText(report)).toContain('not which program made the request');
    });

    it('adds no claim caveat when nobody is named', () => {
        block('e1', 'a.example.com', 'unknown');
        const report = buildReport(store, A);
        expect(report.claimedUserBlocks).toBe(0);
        expect(report.caveats.some((c) => /console user/.test(c))).toBe(false);
    });

    it('exports the claim marker right after the user in CSV', () => {
        block('e1', 'a.example.com', 'berlin');
        block('e2', 'b.example.com', 'unknown');
        expect(CSV_COLUMNS).toContain('loggedOsUserSource');
        const lines = eventsToCsv(store.readAll(A)).trimEnd().split('\n');
        const header = lines[0]!.split(',');
        const at = header.indexOf('loggedOsUser');
        expect(header[at + 1]).toBe('loggedOsUserSource');
        const named = lines[1]!.split(',');
        expect(named[at]).toBe('berlin');
        expect(named[at + 1]).toBe('device_reported');
        const unnamed = lines[2]!.split(',');
        expect(unnamed[at]).toBe('unknown');
        expect(unnamed[at + 1]).toBe('');
    });
});
