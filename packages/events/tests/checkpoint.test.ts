import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { CompanyId, DeviceId } from '@work-dns/shared-types';
import { SqliteEventStore } from '../src/sqlite-store.js';
import { GENESIS_HASH } from '../src/hash-chain.js';
import {
    Ed25519Signer,
    createCheckpoint,
    verifyCheckpoints,
    appendCheckpointToFile,
    readCheckpointFile,
} from '../src/checkpoint.js';
import type { Checkpoint } from '../src/checkpoint.js';

const A = 'comp-a' as CompanyId;
const DEV = 'dev-1' as DeviceId;
const blocked = (domain: string) => ({ domain, loggedOsUser: 'berlin', policyVersion: 1, reasonCode: 'DEFAULT_DENY' });

describe('signed checkpoints', () => {
    let dir: string;
    let tick: number;
    let stores: SqliteEventStore[];
    let signer: Ed25519Signer;
    let keys: Record<string, string>;
    const clock = () => new Date(Date.UTC(2026, 9, 24, 12, 0, tick++));

    const open = (name = 'audit.db'): SqliteEventStore => {
        const store = new SqliteEventStore(path.join(dir, name), { now: clock });
        stores.push(store);
        return store;
    };

    function withRaw(name: string, fn: (db: DatabaseSync) => void): void {
        const db = new DatabaseSync(path.join(dir, name));
        try {
            fn(db);
        } finally {
            db.close();
        }
    }

    const add = (store: SqliteEventStore, id: string, domain = `${id}.example.com`) =>
        store.append({ id, type: 'dns_blocked', companyId: A, deviceId: DEV, payload: blocked(domain) });

    const fill = (store: SqliteEventStore, count: number, prefix = 'e') => {
        for (let i = 1; i <= count; i += 1) add(store, `${prefix}${i}`);
    };

    const checkpoint = (store: SqliteEventStore, previous: Checkpoint | null = null, who: Ed25519Signer = signer) =>
        createCheckpoint(store, A, who, previous, clock);

    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-ckpt-'));
        tick = 0;
        stores = [];
        signer = new Ed25519Signer();
        keys = { [signer.keyId]: signer.publicKeyPem };
    });

    afterEach(() => {
        for (const store of stores) {
            try {
                store.close();
            } catch {
                /* already closed */
            }
        }
        fs.rmSync(dir, { recursive: true, force: true });
    });

    it('signs a checkpoint that verifies', () => {
        const store = open();
        fill(store, 4);
        const cp = checkpoint(store);
        expect(cp.sequenceNumber).toBe(4);
        expect(cp.headHash).toBe(store.head(A)?.hash);
        expect(cp.prevCheckpointHash).toBe(GENESIS_HASH);
        expect(verifyCheckpoints(store, A, [cp], keys)).toEqual({
            valid: true,
            checkpointsChecked: 1,
            anchoredThroughSequence: 4,
            unanchoredEvents: 0,
        });
    });

    it('links a second checkpoint to the first', () => {
        const store = open();
        fill(store, 2);
        const cp1 = checkpoint(store);
        add(store, 'e3');
        add(store, 'e4');
        const cp2 = checkpoint(store, cp1);
        expect(cp2.prevCheckpointHash).toBe(cp1.checkpointHash);
        const result = verifyCheckpoints(store, A, [cp1, cp2], keys);
        expect(result.valid).toBe(true);
        expect(result.checkpointsChecked).toBe(2);
        expect(result.anchoredThroughSequence).toBe(4);
    });

    it('reports events newer than the last checkpoint as unanchored', () => {
        const store = open();
        fill(store, 3);
        const cp = checkpoint(store);
        add(store, 'e4');
        add(store, 'e5');
        const result = verifyCheckpoints(store, A, [cp], keys);
        expect(result.valid).toBe(true);
        expect(result.anchoredThroughSequence).toBe(3);
        expect(result.unanchoredEvents).toBe(2);
    });

    it('refuses to checkpoint an empty chain', () => {
        expect(() => checkpoint(open())).toThrow(/empty/);
    });

    it('detects deleted newest events', () => {
        const store = open();
        fill(store, 4);
        const cp = checkpoint(store);
        withRaw('audit.db', (db) => {
            db.exec('DROP TRIGGER events_no_delete');
            db.exec('DELETE FROM events WHERE sequence_number > 2');
        });
        const result = verifyCheckpoints(store, A, [cp], keys);
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/deleted/);
    });

    it('detects an edited event', () => {
        const store = open();
        fill(store, 4);
        const cp = checkpoint(store);
        withRaw('audit.db', (db) => {
            db.exec('DROP TRIGGER events_no_update');
            db.prepare("UPDATE events SET payload = ? WHERE id = 'e2'").run(JSON.stringify(blocked('edited.example.com')));
        });
        const result = verifyCheckpoints(store, A, [cp], keys);
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/event chain failed verification/);
    });

    it('detects a fully rewritten chain that is internally consistent', () => {
        const real = open('real.db');
        fill(real, 4);
        const cp = checkpoint(real);
        const forged = open('forged.db');
        for (let i = 1; i <= 5; i += 1) add(forged, `f${i}`, `attacker${i}.example.com`);
        const result = verifyCheckpoints(forged, A, [cp], keys);
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/rewritten/);
    });

    it('detects a modified checkpoint and an invalid signature', () => {
        const store = open();
        fill(store, 3);
        const cp = checkpoint(store);
        const changed = verifyCheckpoints(store, A, [{ ...cp, headHash: 'a'.repeat(64) }], keys);
        expect(changed.valid).toBe(false);
        expect(changed.error).toMatch(/modified/);
        const badSig = verifyCheckpoints(store, A, [{ ...cp, signature: '00'.repeat(64) }], keys);
        expect(badSig.valid).toBe(false);
        expect(badSig.error).toMatch(/invalid signature/);
    });

    it('rejects a checkpoint signed with an unknown key', () => {
        const store = open();
        fill(store, 3);
        const attacker = new Ed25519Signer();
        const cp = checkpoint(store, null, attacker);
        const result = verifyCheckpoints(store, A, [cp], keys);
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/unknown key/);
    });

    it('detects a removed middle checkpoint', () => {
        const store = open();
        fill(store, 2);
        const cp1 = checkpoint(store);
        add(store, 'e3');
        const cp2 = checkpoint(store, cp1);
        add(store, 'e4');
        const cp3 = checkpoint(store, cp2);
        const result = verifyCheckpoints(store, A, [cp1, cp3], keys);
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/does not link/);
    });

    it('KNOWN LIMIT: removing the newest checkpoint is not detected without an outside copy', () => {
        const store = open();
        fill(store, 2);
        const cp1 = checkpoint(store);
        add(store, 'e3');
        const cp2 = checkpoint(store, cp1);
        add(store, 'e4');
        checkpoint(store, cp2); // cp3 is "lost"
        const result = verifyCheckpoints(store, A, [cp1, cp2], keys);
        expect(result.valid).toBe(true);
        expect(result.unanchoredEvents).toBe(1);
    });

    it('refuses to sign a chain that contradicts the previous checkpoint', () => {
        const real = open('real.db');
        fill(real, 4);
        const cp = checkpoint(real);
        const forged = open('forged.db');
        for (let i = 1; i <= 5; i += 1) add(forged, `f${i}`, `attacker${i}.example.com`);
        expect(() => checkpoint(forged, cp)).toThrow(/contradicts/);
    });

    it('stores checkpoints in an owner-only file and rejects a malformed line', () => {
        const store = open();
        fill(store, 2);
        const cp1 = checkpoint(store);
        add(store, 'e3');
        const cp2 = checkpoint(store, cp1);
        const file = path.join(dir, 'checkpoints.jsonl');
        expect(readCheckpointFile(file)).toEqual([]);
        appendCheckpointToFile(file, cp1);
        appendCheckpointToFile(file, cp2);
        expect(readCheckpointFile(file)).toEqual([cp1, cp2]);
        expect(fs.statSync(file).mode & 0o777).toBe(0o600);
        fs.appendFileSync(file, 'not json\n');
        expect(() => readCheckpointFile(file)).toThrow(/line 3/);
    });

    it('treats a non-empty chain with no checkpoints as a failure, and an empty one as fine', () => {
        const store = open();
        expect(verifyCheckpoints(store, A, [], keys).valid).toBe(true);
        fill(store, 2);
        const result = verifyCheckpoints(store, A, [], keys);
        expect(result.valid).toBe(false);
        expect(result.error).toMatch(/no checkpoints/);
    });
});
