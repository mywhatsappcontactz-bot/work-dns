import * as fs from 'node:fs';
import { DatabaseSync, type StatementSync } from 'node:sqlite';
import type { CompanyId, DeviceId, EventEnvelope, EventType } from '@work-dns/shared-types';
import { canonicalJson } from './canonical-json.js';
import { GENESIS_HASH, createEventEnvelope, verifyEventChain } from './hash-chain.js';
import type { ChainVerificationResult } from './hash-chain.js';

export interface AppendEventInput<T extends object> {
  id: string;
  type: EventType;
  companyId: CompanyId;
  deviceId?: DeviceId | null;
  schemaVersion?: number;
  payload: T;
}

export interface StoreVerifyOptions {
  expectedLength?: number;
  expectedHeadHash?: string;
}

/** What any audit store (this SQLite one now, PostgreSQL later) must provide. */
export interface AuditEventStore {
  append<T extends object>(input: AppendEventInput<T>): EventEnvelope<T>;
  readAll(companyId: CompanyId): EventEnvelope[];
  head(companyId: CompanyId): { sequenceNumber: number; hash: string } | null;
  verify(companyId: CompanyId, options?: StoreVerifyOptions): ChainVerificationResult;
}

export interface SqliteEventStoreOptions {
  /** Clock for the server-assigned occurredAt (injectable for tests). */
  now?: () => Date;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS events (
  company_id      TEXT    NOT NULL,
  sequence_number INTEGER NOT NULL,
  id              TEXT    NOT NULL UNIQUE,
  type            TEXT    NOT NULL,
  schema_version  INTEGER NOT NULL,
  device_id       TEXT,
  occurred_at     TEXT    NOT NULL,
  payload         TEXT    NOT NULL,
  prev_hash       TEXT    NOT NULL,
  hash            TEXT    NOT NULL,
  PRIMARY KEY (company_id, sequence_number)
) STRICT;
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only: update refused'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only: delete refused'); END;
CREATE TRIGGER IF NOT EXISTS events_chain_check BEFORE INSERT ON events
BEGIN
  SELECT RAISE(ABORT, 'sequence gap or regression')
  WHERE NEW.sequence_number != COALESCE((SELECT MAX(sequence_number) FROM events WHERE company_id = NEW.company_id), 0) + 1;
  SELECT RAISE(ABORT, 'prev_hash does not match the chain head')
  WHERE NEW.prev_hash != COALESCE((SELECT hash FROM events WHERE company_id = NEW.company_id AND sequence_number = NEW.sequence_number - 1), '${GENESIS_HASH}');
END;
`;

interface EventRow {
  company_id: string;
  sequence_number: number;
  id: string;
  type: string;
  schema_version: number;
  device_id: string | null;
  occurred_at: string;
  payload: string;
  prev_hash: string;
  hash: string;
}

function rowToEvent(row: EventRow): EventEnvelope {
  return {
    id: row.id,
    sequenceNumber: row.sequence_number,
    type: row.type as EventType,
    schemaVersion: row.schema_version,
    companyId: row.company_id as CompanyId,
    deviceId: row.device_id === null ? null : (row.device_id as DeviceId),
    occurredAt: row.occurred_at,
    payload: JSON.parse(row.payload) as Record<string, unknown>,
    prevHash: row.prev_hash,
    hash: row.hash,
  };
}

/**
 * Local append-only event store. Sequence numbers and hashes are assigned here, inside one
 * transaction, never by the caller (docs/api-tasks.md section 2). Triggers refuse updates, deletes,
 * sequence gaps and wrong prev_hash values. They stop mistakes and casual edits; anyone who can
 * write to the file can drop them, so integrity rests on verify() plus checkpoints kept elsewhere.
 */
export class SqliteEventStore implements AuditEventStore {
  private readonly db: DatabaseSync;
  private readonly now: () => Date;
  private readonly lastStmt: StatementSync;
  private readonly insertStmt: StatementSync;
  private readonly allStmt: StatementSync;

  constructor(filePath: string, options: SqliteEventStoreOptions = {}) {
    this.now = options.now ?? (() => new Date());
    if (filePath !== ':memory:') {
      fs.closeSync(fs.openSync(filePath, 'a', 0o600)); // owner-only file, created before SQLite opens it
    }
    this.db = new DatabaseSync(filePath);
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = 5000;');
    this.db.exec(SCHEMA);
    this.lastStmt = this.db.prepare(
      'SELECT sequence_number, hash FROM events WHERE company_id = ? ORDER BY sequence_number DESC LIMIT 1'
    );
    this.insertStmt = this.db.prepare(
      'INSERT INTO events (company_id, sequence_number, id, type, schema_version, device_id, occurred_at, payload, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    );
    this.allStmt = this.db.prepare('SELECT * FROM events WHERE company_id = ? ORDER BY sequence_number ASC');
  }

  public append<T extends object>(input: AppendEventInput<T>): EventEnvelope<T> {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const last = this.lastStmt.get(input.companyId) as unknown as { sequence_number: number; hash: string } | undefined;
      const event = createEventEnvelope<T>({
        id: input.id,
        sequenceNumber: (last?.sequence_number ?? 0) + 1,
        type: input.type,
        schemaVersion: input.schemaVersion ?? 1,
        companyId: input.companyId,
        deviceId: input.deviceId ?? null,
        occurredAt: this.now().toISOString(),
        payload: input.payload,
        prevHash: last?.hash ?? GENESIS_HASH,
      });
      this.insertStmt.run(
        event.companyId,
        event.sequenceNumber,
        event.id,
        event.type,
        event.schemaVersion,
        event.deviceId,
        event.occurredAt,
        canonicalJson(event.payload),
        event.prevHash,
        event.hash
      );
      this.db.exec('COMMIT');
      return event;
    } catch (err) {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        /* the original error is rethrown below */
      }
      throw err;
    }
  }

  public readAll(companyId: CompanyId): EventEnvelope[] {
    return (this.allStmt.all(companyId) as unknown as EventRow[]).map(rowToEvent);
  }

  public head(companyId: CompanyId): { sequenceNumber: number; hash: string } | null {
    const last = this.lastStmt.get(companyId) as unknown as { sequence_number: number; hash: string } | undefined;
    return last ? { sequenceNumber: last.sequence_number, hash: last.hash } : null;
  }

  public verify(companyId: CompanyId, options: StoreVerifyOptions = {}): ChainVerificationResult {
    return verifyEventChain(this.readAll(companyId), { expectedCompanyId: companyId, ...options });
  }

  public close(): void {
    this.db.close();
  }
}
