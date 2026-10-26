import type { AuditEventStore } from '@work-dns/events';
import type { EventType } from '@work-dns/shared-types';
import type { AuthenticatedDeviceContext } from './auth.js';

export const MAX_EVENTS_PER_BATCH = 50;

const ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const DEVICE_NAME_PATTERN = /^[A-Za-z0-9._:-]{1,64}$/;
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
const MAX_FUTURE_MS = 5 * 60_000;
const MAX_AGE_MS = 30 * 24 * 60 * 60_000;
const MAX_NUMBER = 1_000_000_000;

type FieldSpec =
  | { kind: 'text'; required: boolean; max: number }
  | { kind: 'iso'; required: boolean }
  | { kind: 'int'; required: boolean }
  | { kind: 'number'; required: boolean }
  | { kind: 'bool'; required: boolean }
  | { kind: 'enum'; required: boolean; values: readonly string[] }
  | { kind: 'textList'; required: boolean };

const TEXT = (max = 200, required = true): FieldSpec => ({ kind: 'text', required, max });
const ISO = (required = true): FieldSpec => ({ kind: 'iso', required });
const INT = (required = true): FieldSpec => ({ kind: 'int', required });
const NUM = (required = true): FieldSpec => ({ kind: 'number', required });
const BOOL = (): FieldSpec => ({ kind: 'bool', required: true });
const ENUM = (...values: string[]): FieldSpec => ({ kind: 'enum', required: true, values });
const LIST = (): FieldSpec => ({ kind: 'textList', required: true });

/** The only event types a device may submit, with the exact payload each allows. */
const SPECS = new Map<string, Record<string, FieldSpec>>([
  ['agent_started', { agentVersion: TEXT(64), os: TEXT(64), loggedOsUser: TEXT(64), policyVersion: INT() }],
  ['agent_stopped', { reason: ENUM('signal', 'crash_recovered', 'error', 'unknown'), dnsRestored: BOOL() }],
  ['enforcement_applied', { networkDevices: LIST(), method: TEXT(64) }],
  ['enforcement_reset', { detectedAt: ISO(), reappliedAt: ISO(false), windowSeconds: NUM(false) }],
  ['enforcement_restored', { networkDevices: LIST(), trigger: ENUM('shutdown', 'crash_recovery', 'manual', 'startup_failure'), success: BOOL() }],
  ['fail_open_entered', { reason: ENUM('gateway_unreachable'), maxMinutes: NUM() }],
  ['fail_open_exited', { durationSeconds: NUM(), cause: ENUM('gateway_recovered', 'time_limit_reached') }],
  ['offline_query', { domain: TEXT(253), action: ENUM('FAIL_OPEN_ALLOWED', 'OFFLINE_BLOCKED', 'AUTH_REJECTED'), reason: TEXT(200), occurrences: INT() }],
]);

export const ALLOWED_AGENT_EVENT_TYPES: readonly string[] = [...SPECS.keys()];

export interface ValidatedAgentEvent {
  clientId: string;
  type: EventType;
  deviceReportedAt: string;
  payload: Record<string, unknown>;
}

export type BatchValidation =
  | { ok: true; events: ValidatedAgentEvent[] }
  | { ok: false; error: string; index?: number };

export type AgentEventOutcome =
  | { ok: true; accepted: number; duplicates: number }
  | { ok: false; error: string; index?: number };

/** Validates a batch and stores it for the authenticated device. Identity comes from the context only. */
export type AgentEventIngest = (context: AuthenticatedDeviceContext, body: unknown) => AgentEventOutcome;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function fail(error: string, index?: number): { ok: false; error: string; index?: number } {
  return index === undefined ? { ok: false, error } : { ok: false, error, index };
}

function checkField(spec: FieldSpec, value: unknown): string | null {
  switch (spec.kind) {
    case 'text':
      return typeof value === 'string' && value.length > 0 && value.length <= spec.max && !CONTROL_CHARS.test(value)
        ? null
        : `must be text of 1 to ${spec.max} characters without control characters`;
    case 'iso':
      return typeof value === 'string' && ISO_UTC.test(value) && !Number.isNaN(Date.parse(value))
        ? null
        : 'must be a UTC ISO 8601 date such as 2026-10-24T12:00:00.000Z';
    case 'int':
      return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= MAX_NUMBER
        ? null
        : 'must be a non-negative integer';
    case 'number':
      return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= MAX_NUMBER
        ? null
        : 'must be a non-negative number';
    case 'bool':
      return typeof value === 'boolean' ? null : 'must be true or false';
    case 'enum':
      return typeof value === 'string' && spec.values.includes(value) ? null : `must be one of: ${spec.values.join(', ')}`;
    case 'textList':
      return Array.isArray(value) &&
        value.length >= 1 &&
        value.length <= 16 &&
        value.every((item: unknown) => typeof item === 'string' && DEVICE_NAME_PATTERN.test(item))
        ? null
        : 'must be 1 to 16 short names';
  }
}

function checkDeviceTime(value: unknown, now: Date): string | null {
  const shape = checkField({ kind: 'iso', required: true }, value);
  if (shape !== null) return `deviceReportedAt ${shape}`;
  const at = Date.parse(value as string);
  if (at > now.getTime() + MAX_FUTURE_MS) return 'deviceReportedAt is more than 5 minutes in the future';
  if (at < now.getTime() - MAX_AGE_MS) return 'deviceReportedAt is more than 30 days old';
  return null;
}

/** Checks a whole batch before anything is stored. One bad event rejects the batch. */
export function validateAgentEventBatch(body: unknown, now: Date): BatchValidation {
  if (!isPlainObject(body)) return fail('body must be a JSON object');
  const topKeys = Object.keys(body);
  if (topKeys.length !== 1 || topKeys[0] !== 'events') return fail('body must contain only "events"');
  const list: unknown = body.events;
  if (!Array.isArray(list) || list.length === 0) return fail('"events" must be a non-empty array');
  if (list.length > MAX_EVENTS_PER_BATCH) return fail(`at most ${MAX_EVENTS_PER_BATCH} events per request`);

  const seen = new Set<string>();
  const events: ValidatedAgentEvent[] = [];
  for (let i = 0; i < list.length; i += 1) {
    const item: unknown = list[i];
    if (!isPlainObject(item)) return fail('event must be an object', i);
    if (Object.keys(item).sort().join(',') !== 'deviceReportedAt,id,payload,type') {
      return fail('event must have exactly: id, type, deviceReportedAt, payload', i);
    }
    const { id, type, deviceReportedAt, payload } = item;
    if (typeof id !== 'string' || !ID_PATTERN.test(id)) return fail('id must be 1 to 64 characters from A-Z a-z 0-9 _ -', i);
    if (seen.has(id)) return fail('duplicate id in batch', i);
    seen.add(id);
    const spec = typeof type === 'string' ? SPECS.get(type) : undefined;
    if (typeof type !== 'string' || spec === undefined) {
      return fail(`type "${String(type).slice(0, 40)}" cannot be submitted by a device`, i);
    }
    const timeError = checkDeviceTime(deviceReportedAt, now);
    if (timeError !== null) return fail(timeError, i);
    if (!isPlainObject(payload)) return fail('payload must be an object', i);

    const clean: Record<string, unknown> = {};
    for (const key of Object.keys(payload)) {
      const fieldSpec = Object.prototype.hasOwnProperty.call(spec, key) ? spec[key] : undefined;
      if (fieldSpec === undefined) return fail(`unknown payload field "${key.slice(0, 40)}" for ${type}`, i);
      const problem = checkField(fieldSpec, payload[key]);
      if (problem !== null) return fail(`payload.${key} ${problem}`, i);
      clean[key] = payload[key];
    }
    for (const [key, fieldSpec] of Object.entries(spec)) {
      if (fieldSpec.required && !Object.prototype.hasOwnProperty.call(clean, key)) {
        return fail(`payload.${key} is required for ${type}`, i);
      }
    }
    events.push({ clientId: id, type: type as EventType, deviceReportedAt: deviceReportedAt as string, payload: clean });
  }
  return { ok: true, events };
}

/**
 * Stores validated device events. The stored id is deviceId:clientId, so devices cannot collide with
 * or pre-claim each other's ids, and a retried batch is skipped, not duplicated. Entries are marked
 * source "device_reported": they are the device's claims, not something the gateway observed.
 * Limit: the store is synchronous, so a batch briefly blocks the event loop (at most 50 appends).
 */
export function createAgentEventIngest(
  store: Pick<AuditEventStore, 'append' | 'hasEvent'>,
  options: { now?: () => Date } = {}
): AgentEventIngest {
  const now = options.now ?? (() => new Date());
  return (context, body) => {
    const checked = validateAgentEventBatch(body, now());
    if (!checked.ok) return checked;
    let accepted = 0;
    let duplicates = 0;
    for (const event of checked.events) {
      const storedId = `${context.deviceId}:${event.clientId}`;
      if (store.hasEvent(storedId)) {
        duplicates += 1;
        continue;
      }
      store.append({
        id: storedId,
        type: event.type,
        companyId: context.companyId,
        deviceId: context.deviceId,
        payload: { ...event.payload, source: 'device_reported', deviceReportedAt: event.deviceReportedAt },
      });
      accepted += 1;
    }
    return { ok: true, accepted, duplicates };
  };
}
