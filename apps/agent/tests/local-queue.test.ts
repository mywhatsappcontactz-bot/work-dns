import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { LocalEventQueue, QueuedOfflineEvent } from '../src/local-queue.js';

const event = (domain: string, actionTaken: QueuedOfflineEvent['actionTaken'] = 'FAIL_OPEN_ALLOWED') => ({
  domain,
  actionTaken,
  reason: 'test',
});

describe('LocalEventQueue', () => {
  let base: string;
  let file: string;
  let now: number;
  let errorSpy: ReturnType<typeof vi.spyOn>;

  const make = (extra: { maxQueueSize?: number; dedupeWindowMs?: number } = {}): LocalEventQueue =>
    new LocalEventQueue({ filePath: file, now: () => now, ...extra });

  beforeEach(() => {
    base = fs.mkdtempSync(path.join(os.tmpdir(), 'work-dns-queue-'));
    file = path.join(base, 'queue.jsonl');
    now = 1_000_000;
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    errorSpy.mockRestore();
    fs.rmSync(base, { recursive: true, force: true });
  });

  it('persists events with 0600 permissions and reloads them', () => {
    const q = make();
    q.enqueue(event('a.com'));
    q.enqueue(event('b.com', 'OFFLINE_BLOCKED'));
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);

    const reloaded = make();
    expect(reloaded.getItems().map((e) => [e.domain, e.actionTaken])).toEqual([
      ['a.com', 'FAIL_OPEN_ALLOWED'],
      ['b.com', 'OFFLINE_BLOCKED'],
    ]);
    expect(reloaded.getItems()[0]!.id).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('deduplicates repeats inside the window and records a new event after it', () => {
    const q = make({ dedupeWindowMs: 60_000 });
    q.enqueue(event('a.com'));
    q.enqueue(event('a.com'));
    q.enqueue(event('a.com'));
    expect(q.getCount()).toBe(1);
    expect(q.getItems()[0]!.occurrences).toBe(3);

    q.enqueue(event('a.com', 'OFFLINE_BLOCKED')); // different action: separate event
    expect(q.getCount()).toBe(2);

    now += 61_000;
    q.enqueue(event('a.com'));
    expect(q.getCount()).toBe(3);
  });

  it('is bounded: drops the oldest events, counts and logs them', () => {
    const q = make({ maxQueueSize: 3 });
    for (let i = 0; i < 5; i++) {
      q.enqueue(event(`d${i}.com`));
    }
    expect(q.getItems().map((e) => e.domain)).toEqual(['d2.com', 'd3.com', 'd4.com']);
    expect(q.getDroppedCount()).toBe(2);
    expect(errorSpy).toHaveBeenCalled();
  });

  it('flush removes only delivered events and keeps ones added while sending', async () => {
    const q = make();
    q.enqueue(event('a.com'));
    q.enqueue(event('b.com'));

    const delivered: string[] = [];
    const count = await q.flush(async (batch) => {
      delivered.push(...batch.map((e) => e.domain));
      q.enqueue(event('added-during-send.com'));
    });

    expect(count).toBe(2);
    expect(delivered.slice(0, 2)).toEqual(['a.com', 'b.com']);
    expect(q.getItems().map((e) => e.domain)).toEqual([]); // loop continued and delivered the late event too
    expect(delivered).toContain('added-during-send.com');
  });

  it('keeps every event and propagates the error when the transmitter fails', async () => {
    const q = make();
    q.enqueue(event('a.com'));
    q.enqueue(event('b.com'));
    await expect(
      q.flush(async () => {
        throw new Error('server down');
      })
    ).rejects.toThrow('server down');
    expect(q.getCount()).toBe(2);
    expect(make().getCount()).toBe(2); // still on disk
  });

  it('delivers in batches of the requested size', async () => {
    const q = make();
    for (let i = 0; i < 5; i++) {
      q.enqueue(event(`d${i}.com`));
    }
    const sizes: number[] = [];
    await q.flush(async (batch) => {
      sizes.push(batch.length);
    }, 2);
    expect(sizes).toEqual([2, 2, 1]);
    expect(q.getCount()).toBe(0);
    expect(fs.readFileSync(file, 'utf8')).toBe('');
  });

  it('does not run two flushes at once', async () => {
    const q = make();
    q.enqueue(event('a.com'));
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const transmitter = vi.fn(() => gate);
    const first = q.flush(transmitter);
    expect(await q.flush(transmitter)).toBe(0);
    expect(transmitter).toHaveBeenCalledTimes(1);
    release();
    await first;
  });

  it('keeps valid events, preserves the original file and logs when lines are corrupt', () => {
    const good = {
      id: '11111111-1111-1111-1111-111111111111',
      domain: 'ok.com',
      timestamp: new Date(now).toISOString(),
      actionTaken: 'FAIL_OPEN_ALLOWED',
      reason: 'x',
      occurrences: 1,
    };
    fs.writeFileSync(file, `${JSON.stringify(good)}\n{not json\n{"domain":5}\n`, { mode: 0o600 });

    const q = make();
    expect(q.getItems().map((e) => e.domain)).toEqual(['ok.com']);
    expect(errorSpy).toHaveBeenCalledTimes(1);
    const preserved = fs.readdirSync(base).filter((name) => name.includes('.corrupt-'));
    expect(preserved).toHaveLength(1);
    expect(fs.readFileSync(path.join(base, preserved[0]!), 'utf8')).toContain('{not json');
    expect(fs.readFileSync(file, 'utf8').trim().split('\n')).toHaveLength(1);
  });

  it('counts and logs persistence failures instead of throwing, keeping events in memory', () => {
    const q = make();
    q.enqueue(event('a.com'));
    fs.rmSync(base, { recursive: true, force: true }); // directory vanishes: appends now fail
    expect(() => q.enqueue(event('b.com'))).not.toThrow();
    expect(q.getPersistFailureCount()).toBe(1);
    expect(q.getCount()).toBe(2);
    expect(errorSpy).toHaveBeenCalled();
    fs.mkdirSync(base, { recursive: true });
  });

  it('clear() empties memory and disk and leaves no temp files', () => {
    const q = make();
    q.enqueue(event('a.com'));
    q.clear();
    expect(q.getCount()).toBe(0);
    expect(fs.readFileSync(file, 'utf8')).toBe('');
    expect(fs.readdirSync(base)).toEqual(['queue.jsonl']);
  });

  it('validates options', () => {
    expect(() => new LocalEventQueue({ filePath: file, maxQueueSize: 0 })).toThrow(/maxQueueSize/);
  });
});
