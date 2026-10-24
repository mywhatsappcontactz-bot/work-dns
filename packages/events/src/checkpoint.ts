import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as nodeSign, verify as nodeVerify, type KeyObject } from 'node:crypto';
import * as fs from 'node:fs';
import type { CompanyId } from '@work-dns/shared-types';
import { canonicalJson } from './canonical-json.js';
import { GENESIS_HASH, verifyEventChain } from './hash-chain.js';
import type { AuditEventStore } from './sqlite-store.js';

const CHECKPOINT_VERSION = 1;

export type CheckpointSource = Pick<AuditEventStore, 'readAll'>;

export interface CheckpointBody {
  version: number;
  companyId: CompanyId;
  /** Number of events covered, which is also the sequence number of the head event. */
  sequenceNumber: number;
  headHash: string;
  createdAt: string;
  /** checkpointHash of the previous checkpoint, or GENESIS_HASH for the first. */
  prevCheckpointHash: string;
  keyId: string;
}

export interface Checkpoint extends CheckpointBody {
  /** SHA-256 of the canonical body. */
  checkpointHash: string;
  /** Ed25519 signature over the canonical body, hex. */
  signature: string;
}

export interface CheckpointSigner {
  readonly keyId: string;
  sign(data: Buffer): Buffer;
}

export interface CheckpointVerification {
  valid: boolean;
  error?: string;
  checkpointsChecked: number;
  anchoredThroughSequence: number;
  /** Events newer than the last checkpoint: they are not yet protected against deletion. */
  unanchoredEvents: number;
}

function keyIdOf(publicKey: KeyObject): string {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('hex').slice(0, 16);
}

/** Ed25519 signer. In production the private key must live outside the log writer's reach (for example KMS). */
export class Ed25519Signer implements CheckpointSigner {
  public readonly keyId: string;
  public readonly publicKeyPem: string;
  private readonly privateKey: KeyObject;

  constructor(privateKeyPem?: string) {
    this.privateKey = privateKeyPem === undefined ? generateKeyPairSync('ed25519').privateKey : createPrivateKey(privateKeyPem);
    const publicKey = createPublicKey(this.privateKey);
    this.publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    this.keyId = keyIdOf(publicKey);
  }

  public exportPrivateKeyPem(): string {
    return this.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  }

  public sign(data: Buffer): Buffer {
    return nodeSign(null, data, this.privateKey);
  }
}

function bodyOf(c: Checkpoint): CheckpointBody {
  return {
    version: c.version,
    companyId: c.companyId,
    sequenceNumber: c.sequenceNumber,
    headHash: c.headHash,
    createdAt: c.createdAt,
    prevCheckpointHash: c.prevCheckpointHash,
    keyId: c.keyId,
  };
}

function bodyBytes(body: CheckpointBody): Buffer {
  return Buffer.from(canonicalJson(body), 'utf8');
}

function hashOfBody(body: CheckpointBody): string {
  return createHash('sha256').update(bodyBytes(body)).digest('hex');
}

function signatureValid(publicKeyPem: string, data: Buffer, signatureHex: string): boolean {
  try {
    return nodeVerify(null, data, createPublicKey(publicKeyPem), Buffer.from(signatureHex, 'hex'));
  } catch {
    return false;
  }
}

/**
 * Signs the current head of a company's chain. Refuses when the chain fails verification or
 * contradicts the previous checkpoint, so a rewritten chain can never be signed over the original.
 */
export function createCheckpoint(
  source: CheckpointSource,
  companyId: CompanyId,
  signer: CheckpointSigner,
  previous: Checkpoint | null,
  now: () => Date = () => new Date()
): Checkpoint {
  const events = source.readAll(companyId);
  if (events.length === 0) {
    throw new Error('cannot checkpoint an empty chain');
  }
  const chain = verifyEventChain(events, { expectedCompanyId: companyId });
  if (!chain.valid) {
    throw new Error(`refusing to sign a chain that fails verification: ${chain.error ?? 'unknown error'}`);
  }
  if (previous !== null) {
    if (previous.companyId !== companyId) {
      throw new Error('previous checkpoint belongs to another company');
    }
    const anchor = events[previous.sequenceNumber - 1];
    if (anchor === undefined || anchor.hash !== previous.headHash) {
      throw new Error('refusing to sign: the chain contradicts the previous checkpoint (events were deleted or rewritten)');
    }
  }
  const last = events[events.length - 1]!;
  const body: CheckpointBody = {
    version: CHECKPOINT_VERSION,
    companyId,
    sequenceNumber: last.sequenceNumber,
    headHash: last.hash,
    createdAt: now().toISOString(),
    prevCheckpointHash: previous === null ? GENESIS_HASH : previous.checkpointHash,
    keyId: signer.keyId,
  };
  return { ...body, checkpointHash: hashOfBody(body), signature: signer.sign(bodyBytes(body)).toString('hex') };
}

/**
 * Checks the whole store against a list of checkpoints. publicKeys maps keyId to a PEM public key.
 * Limit: deleting the newest checkpoints is invisible here. Keep the latest checkpoint somewhere the log writer cannot edit.
 */
export function verifyCheckpoints(
  source: CheckpointSource,
  companyId: CompanyId,
  checkpoints: Checkpoint[],
  publicKeys: Record<string, string>
): CheckpointVerification {
  const events = source.readAll(companyId);
  const fail = (error: string, checked: number, anchored: number): CheckpointVerification => ({
    valid: false,
    error,
    checkpointsChecked: checked,
    anchoredThroughSequence: anchored,
    unanchoredEvents: Math.max(0, events.length - anchored),
  });

  const chain = verifyEventChain(events, { expectedCompanyId: companyId });
  if (!chain.valid) {
    return fail(`event chain failed verification: ${chain.error ?? 'unknown error'}`, 0, 0);
  }
  if (checkpoints.length === 0) {
    return events.length === 0
      ? { valid: true, checkpointsChecked: 0, anchoredThroughSequence: 0, unanchoredEvents: 0 }
      : fail('no checkpoints: nothing anchors this chain', 0, 0);
  }

  let prevHash = GENESIS_HASH;
  let prevSeq = 0;
  let checked = 0;
  for (const cp of checkpoints) {
    const label = `checkpoint ${checked + 1}`;
    if (cp.companyId !== companyId) return fail(`${label} belongs to another company`, checked, prevSeq);
    if (cp.version !== CHECKPOINT_VERSION) return fail(`${label} has an unsupported version`, checked, prevSeq);
    const pem = publicKeys[cp.keyId];
    if (pem === undefined) return fail(`${label} was signed with an unknown key ${cp.keyId}`, checked, prevSeq);
    let keyMatches = false;
    try {
      keyMatches = keyIdOf(createPublicKey(pem)) === cp.keyId;
    } catch {
      keyMatches = false;
    }
    if (!keyMatches) return fail(`the public key registered for ${cp.keyId} does not match that id`, checked, prevSeq);
    const body = bodyOf(cp);
    if (hashOfBody(body) !== cp.checkpointHash) return fail(`${label} was modified (hash mismatch)`, checked, prevSeq);
    if (!signatureValid(pem, bodyBytes(body), cp.signature)) return fail(`${label} has an invalid signature`, checked, prevSeq);
    if (cp.prevCheckpointHash !== prevHash) {
      return fail(`${label} does not link to the previous checkpoint (one was removed or reordered)`, checked, prevSeq);
    }
    if (cp.sequenceNumber < prevSeq) return fail(`${label} goes backwards`, checked, prevSeq);
    if (cp.sequenceNumber > events.length) {
      return fail(`${label} anchors ${cp.sequenceNumber} events but the store has ${events.length}: events were deleted`, checked, prevSeq);
    }
    const anchor = events[cp.sequenceNumber - 1];
    if (anchor === undefined || anchor.hash !== cp.headHash) {
      return fail(`event ${cp.sequenceNumber} does not match ${label}: the chain was rewritten`, checked, prevSeq);
    }
    prevHash = cp.checkpointHash;
    prevSeq = cp.sequenceNumber;
    checked += 1;
  }
  return { valid: true, checkpointsChecked: checked, anchoredThroughSequence: prevSeq, unanchoredEvents: events.length - prevSeq };
}

/** Appends one checkpoint as a JSON line. The file is created owner-only and synced to disk. */
export function appendCheckpointToFile(file: string, checkpoint: Checkpoint): void {
  const fd = fs.openSync(file, 'a', 0o600);
  try {
    fs.writeSync(fd, `${JSON.stringify(checkpoint)}\n`);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

function isCheckpoint(value: unknown): value is Checkpoint {
  if (typeof value !== 'object' || value === null) return false;
  const c = value as Record<string, unknown>;
  return (
    typeof c.version === 'number' &&
    typeof c.companyId === 'string' &&
    typeof c.sequenceNumber === 'number' &&
    Number.isInteger(c.sequenceNumber) &&
    typeof c.headHash === 'string' &&
    typeof c.createdAt === 'string' &&
    typeof c.prevCheckpointHash === 'string' &&
    typeof c.keyId === 'string' &&
    typeof c.checkpointHash === 'string' &&
    typeof c.signature === 'string'
  );
}

/** Reads a checkpoint file. A missing file means no checkpoints; a malformed line is an error. */
export function readCheckpointFile(file: string): Checkpoint[] {
  let raw: string;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw err;
  }
  const checkpoints: Checkpoint[] = [];
  raw.split('\n').forEach((line, index) => {
    if (line.trim() === '') return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      throw new Error(`checkpoint file ${file} line ${index + 1} is not valid JSON`);
    }
    if (!isCheckpoint(parsed)) {
      throw new Error(`checkpoint file ${file} line ${index + 1} is not a checkpoint`);
    }
    checkpoints.push(parsed);
  });
  return checkpoints;
}
