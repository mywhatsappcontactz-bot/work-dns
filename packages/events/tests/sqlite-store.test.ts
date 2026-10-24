import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { CompanyId, DeviceId } from '@work-dns/shared-types';
import { SqliteEventStore } from '../src/sqlite-store.js';
import { GENESIS_HASH } from '../src/hash-chain.js';

const A = 'comp-a' as CompanyId;
const B = 'comp-b' as CompanyId;
const DEV = 'dev-1' as DeviceId;

const blocked = (domain: string) => ({ domain, loggedOsUser: 'berlin', policyVersion: 1, reasonCode: 'DEFAULT_DENY' });

const RAW_INSERT =
    'INSERT INTO events (company_id, sequence_number, id, type, schema_version, device_id, occurred_at, payload, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';

describe('SqliteEventStore', () => {
    let dir: string;
    let file: string;
    let tick: number;
    let stores: SqliteEventStore[];

    const open = (): SqliteEventStore => {
        const store = new SqliteEventStore(file, { now: () => new Date(Date.UTC(2026, 9, 24, 10, 0, tick++)) });
        stores.push(store);
        return store;
    };

    function withRaw<T>(fn: (db: DatabaseSync) => T): T {
        const db = new DatabaseSync(file);
        try {
            return fn(db);
        } finally {
            db.close();
        }
    }

    const add = (store: SqliteEventStore, id: string, company: CompanyId = A) =>
        store.append({ id, type: 'dns_blocked', companyId: company, deviceId: DEV, payload: blocked(`${id}.example.com`) });

    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-audit-'));
        file = path.join(dir, 'audit.db');
        tick = 0;
        stores = [];
    });

    afterEach(() => {
        for (const store of stores) {
            try {
                store.close();
            } catch {
                /* already closed by the test */
            }
        }
        fs.rmSync(dir, { recursive: true, force: true });
    });

    it('assigns contiguous sequence numbers, links hashes and stamps server time', () => {
        const store = open();
        const e1 = add(store, 'e1');
        const e2 = add(store, 'e2');
        expect(e1.sequenceNumber).toBe(1);
        expect(e1.prevHash).toBe(GENESIS_HASH);
        expect(e2.sequenceNumber).toBe(2);
        expect(e2.prevHash).toBe(e1.hash);
        expect(e1.occurredAt).toBe('2026-10-24T10:00:00.000Z');
        expect(store.readAll(A)).toEqual([e1, e2]);
        expect(store.verify(A, { expectedLength: 2, expectedHeadHash: e2.hash }).valid).toBe(true);
    });

    it('keeps a separate chain per company', () => {
        const store = open();
        add(store, 'a1', A);
        add(store, 'b1', B);
        add(store, 'a2', A);
        expect(store.head(A)?.sequenceNumber).toBe(2);
        expect(store.head(B)?.sequenceNumber).toBe(1);
        expect(store.verify(A).valid).toBe(true);
        expect(store.verify(B).valid).toBe(true);
    });

    it('continues the chain after the store is closed and reopened', () => {
        const first = open();
        add(first, 'e1');
        first.close();
        const second = open();
        const e2 = add(second, 'e2');
        expect(e2.sequenceNumber).toBe(2);
        expect(second.verify(A, { expectedLength: 2 }).valid).toBe(true);
    });

    it('creates the database file readable only by its owner', () => {
        open();
        expect(fs.statSync(file).mode & 0o777).toBe(0o600);
    });

    it('rejects a duplicate id without using up a sequence number', () => {
        const store = open();
        add(store, 'dup');
        expect(() => add(store, 'dup')).toThrow();
        expect(store.head(A)?.sequenceNumber).toBe(1);
        expect(add(store, 'ok').sequenceNumber).toBe(2);
        expect(store.verify(A, { expectedLength: 2 }).valid).toBe(true);
    });

    it('refuses an update from a direct SQL session', () => {
        add(open(), 'e1');
        expect(() => withRaw((db) => db.exec("UPDATE events SET payload = '{}' WHERE id = 'e1'"))).toThrow(/append-only/);
    });

    it('refuses a delete from a direct SQL session', () => {
        add(open(), 'e1');
        expect(() => withRaw((db) => db.exec("DELETE FROM events WHERE id = 'e1'"))).toThrow(/append-only/);
    });

    it('refuses a raw insert that skips a sequence number', () => {
        const store = open();
        add(store, 'e1');
        expect(() =>
            withRaw((db) => db.prepare(RAW_INSERT).run('comp-a', 5, 'x', 'dns_blocked', 1, null, '2026-10-24T10:00:00.000Z', '{}', 'f'.repeat(64), 'e'.repeat(64)))
        ).toThrow(/sequence/);
    });

    it('refuses a raw insert with the wrong prev_hash', () => {
        const store = open();
        add(store, 'e1');
        expect(() =>
            withRaw((db) => db.prepare(RAW_INSERT).run('comp-a', 2, 'x', 'dns_blocked', 1, null, '2026-10-24T10:00:00.000Z', '{}', 'f'.repeat(64), 'e'.repeat(64)))
        ).toThrow(/prev_hash/);
    });

    it('KNOWN LIMIT: with the triggers dropped an edit succeeds, but verify() finds it', () => {
        const store = open();
        add(store, 'e1');
        add(store, 'e2');
        add(store, 'e3');
        const edited = JSON.stringify(blocked('edited.example.com'));
        withRaw((db) => {
            db.exec('DROP TRIGGER events_no_update');
            db.prepare("UPDATE events SET payload = ? WHERE id = 'e2'").run(edited);
        });
        const result = store.verify(A);
        expect(result.valid).toBe(false);
        expect(result.brokenIndex).toBe(1);
    });

    it('KNOWN LIMIT: deleting the newest events is caught only with an expected length or head hash', () => {
        const store = open();
        add(store, 'e1');
        add(store, 'e2');
        add(store, 'e3');
        const e4 = add(store, 'e4');
        withRaw((db) => {
            db.exec('DROP TRIGGER events_no_delete');
            db.exec('DELETE FROM events WHERE sequence_number > 2');
        });
        expect(store.verify(A).valid).toBe(true); // the hole that signed checkpoints close
        expect(store.verify(A, { expectedLength: 4 }).valid).toBe(false);
        expect(store.verify(A, { expectedHeadHash: e4.hash }).valid).toBe(false);
    });
});
