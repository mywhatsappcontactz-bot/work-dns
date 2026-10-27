import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { AgentOutbox } from '../src/outbox.js';

describe('AgentOutbox', () => {
    let dir: string;
    let file: string;
    let quarantine: string;

    beforeEach(() => {
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wd-outbox-'));
        file = path.join(dir, 'outbox.jsonl');
        quarantine = path.join(dir, 'quarantine.jsonl');
        vi.spyOn(console, 'error').mockImplementation(() => {});
    });

    afterEach(() => {
        vi.restoreAllMocks();
        fs.rmSync(dir, { recursive: true, force: true });
    });

    const open = (maxEvents?: number) =>
        new AgentOutbox({ filePath: file, quarantinePath: quarantine, ...(maxEvents === undefined ? {} : { maxEvents }) });

    it('keeps events on disk (owner-only) and reloads them in order', () => {
        const outbox = open();
        const a = outbox.add('agent_started', { n: 1 });
        const b = outbox.add('enforcement_reset', { n: 2 });
        expect(fs.statSync(file).mode & 0o777).toBe(0o600);
        const reopened = open();
        expect(reopened.peek(10).map((e) => e.id)).toEqual([a, b]);
        expect(reopened.peek(10)[1]).toMatchObject({ type: 'enforcement_reset', payload: { n: 2 } });
    });

    it('peek returns copies, and acknowledge removes events from memory and disk', () => {
        const outbox = open();
        const ids = [1, 2, 3].map((n) => outbox.add('agent_started', { n }));
        const copy = outbox.peek(2);
        copy[0]!.payload.n = 999;
        expect(outbox.peek(1)[0]!.payload.n).toBe(1);
        outbox.acknowledge([ids[0]!, ids[1]!]);
        expect(outbox.count()).toBe(1);
        expect(open().peek(10).map((e) => e.id)).toEqual([ids[2]]);
    });

    it('drops the oldest events beyond its cap and counts them', () => {
        const outbox = open(3);
        for (let n = 1; n <= 5; n += 1) outbox.add('agent_started', { n });
        expect(outbox.count()).toBe(3);
        expect(outbox.getDroppedCount()).toBe(2);
        expect(outbox.peek(10).map((e) => e.payload.n)).toEqual([3, 4, 5]);
        expect(open(3).peek(10).map((e) => e.payload.n)).toEqual([3, 4, 5]);
    });

    it('quarantine moves an event aside without losing it', () => {
        const outbox = open();
        const keep = outbox.add('agent_started', { n: 1 });
        const bad = outbox.add('agent_stopped', { n: 2 });
        expect(outbox.quarantine(bad, 'gateway said no')).toBe(true);
        expect(outbox.count()).toBe(1);
        expect(outbox.getQuarantinedCount()).toBe(1);
        const record = JSON.parse(fs.readFileSync(quarantine, 'utf8').trim()) as { reason: string; event: { id: string } };
        expect(record.reason).toBe('gateway said no');
        expect(record.event.id).toBe(bad);
        expect(open().peek(10).map((e) => e.id)).toEqual([keep]);
        expect(outbox.quarantine('missing', 'x')).toBe(false);
    });

    it('moves unreadable lines to quarantine instead of discarding them, and skips duplicate ids', () => {
        const good = JSON.stringify({ id: 'a1', type: 'agent_started', deviceReportedAt: '2026-10-24T10:00:00.000Z', payload: {} });
        fs.writeFileSync(file, `${good}\nthis is not json\n${good}\n`, { mode: 0o600 });
        const outbox = open();
        expect(outbox.count()).toBe(1);
        expect(outbox.getQuarantinedCount()).toBe(1);
        expect(fs.readFileSync(quarantine, 'utf8')).toContain('this is not json');
        open(); // a second start must not quarantine the same line again
        expect(fs.readFileSync(quarantine, 'utf8').trim().split('\n')).toHaveLength(1);
    });

    it('refuses a symlinked directory and creates its own directory owner-only', () => {
        const real = path.join(dir, 'real');
        fs.mkdirSync(real);
        fs.symlinkSync(real, path.join(dir, 'link'));
        expect(() => new AgentOutbox({ filePath: path.join(dir, 'link', 'o.jsonl') })).toThrow(/symlink/);
        const nested = path.join(dir, 'nested');
        new AgentOutbox({ filePath: path.join(nested, 'o.jsonl') });
        expect(fs.statSync(nested).mode & 0o777).toBe(0o700);
    });

    it('rejects an invalid cap', () => {
        expect(() => open(0)).toThrow(RangeError);
    });
});
