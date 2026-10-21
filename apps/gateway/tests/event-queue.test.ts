import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { GatewayEventQueue, BlockedAttemptRecord } from '../src/event-queue.js';

function attempt(overrides: Partial<{ companyId: string; deviceId: string; domain: string }> = {}) {
  return {
    companyId: 'comp-1',
    deviceId: 'dev-1',
    domain: 'facebook.com',
    loggedOsUser: 'unknown',
    policyVersion: 1,
    reasonCode: 'DEFAULT_DENY',
    ...overrides,
  };
}

describe('GatewayEventQueue', () => {
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    errorSpy.mockRestore();
    warnSpy.mockRestore();
    vi.useRealTimers();
  });

  it('delivers queued records to the sink with all fields, in order', async () => {
    const sink = vi.fn().mockResolvedValue(undefined);
    const q = new GatewayEventQueue({ sink });
    q.enqueueBlockedAttempt(attempt({ domain: 'a.com' }));
    q.enqueueBlockedAttempt({ ...attempt({ domain: 'b.com' }), clientIp: '10.0.0.5' });
    await q.flushNow();

    expect(sink).toHaveBeenCalledTimes(1);
    const batch = sink.mock.calls[0]![0] as BlockedAttemptRecord[];
    expect(batch.map((r) => r.domain)).toEqual(['a.com', 'b.com']);
    expect(batch[0]).toMatchObject({ companyId: 'comp-1', deviceId: 'dev-1', count: 1, policyVersion: 1 });
    expect(batch[0]!.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(batch[0]!.clientIp).toBeUndefined();
    expect(batch[1]!.clientIp).toBe('10.0.0.5');
    expect(q.getQueuedCount()).toBe(0);
  });

  it('coalesces repeated attempts while queued and counts them', async () => {
    const sink = vi.fn().mockResolvedValue(undefined);
    const q = new GatewayEventQueue({ sink });
    q.enqueueBlockedAttempt(attempt());
    q.enqueueBlockedAttempt(attempt());
    q.enqueueBlockedAttempt(attempt());
    expect(q.getQueuedCount()).toBe(1);
    await q.flushNow();
    expect((sink.mock.calls[0]![0] as BlockedAttemptRecord[])[0]!.count).toBe(3);
  });

  it('does not coalesce different devices, companies or domains', () => {
    const q = new GatewayEventQueue({ sink: vi.fn().mockResolvedValue(undefined) });
    q.enqueueBlockedAttempt(attempt());
    q.enqueueBlockedAttempt(attempt({ deviceId: 'dev-2' }));
    q.enqueueBlockedAttempt(attempt({ companyId: 'comp-2' }));
    q.enqueueBlockedAttempt(attempt({ domain: 'other.com' }));
    expect(q.getQueuedCount()).toBe(4);
  });

  it('starts a new record after a flush instead of mutating a delivered one', async () => {
    const sink = vi.fn().mockResolvedValue(undefined);
    const q = new GatewayEventQueue({ sink });
    q.enqueueBlockedAttempt(attempt());
    await q.flushNow();
    q.enqueueBlockedAttempt(attempt());
    await q.flushNow();
    expect(sink).toHaveBeenCalledTimes(2);
    expect((sink.mock.calls[1]![0] as BlockedAttemptRecord[])[0]!.count).toBe(1);
  });

  it('keeps events, logs the error and retries when the sink fails', async () => {
    const sink = vi
      .fn()
      .mockRejectedValueOnce(new Error('backend down'))
      .mockResolvedValue(undefined);
    const q = new GatewayEventQueue({ sink });
    q.enqueueBlockedAttempt(attempt({ domain: 'a.com' }));
    q.enqueueBlockedAttempt(attempt({ domain: 'b.com' }));

    await q.flushNow();
    expect(q.getQueuedCount()).toBe(2);
    expect(q.getConsecutiveFailures()).toBe(1);
    expect(errorSpy).toHaveBeenCalledTimes(1);
    expect(String(errorSpy.mock.calls[0]![0])).toContain('backend down');

    await q.flushNow();
    expect(q.getQueuedCount()).toBe(0);
    expect(q.getConsecutiveFailures()).toBe(0);
    const firstIds = (sink.mock.calls[0]![0] as BlockedAttemptRecord[]).map((r) => r.id);
    const retryIds = (sink.mock.calls[1]![0] as BlockedAttemptRecord[]).map((r) => r.id);
    expect(retryIds).toEqual(firstIds);
  });

  it('retains events and warns once when no sink is configured', async () => {
    const q = new GatewayEventQueue();
    q.enqueueBlockedAttempt(attempt({ domain: 'a.com' }));
    q.enqueueBlockedAttempt(attempt({ domain: 'b.com' }));
    await q.flushNow();
    expect(q.getQueuedCount()).toBe(2);
    expect(warnSpy).toHaveBeenCalledTimes(1);
  });

  it('is bounded: drops beyond maxQueueSize, counts drops and logs', () => {
    const q = new GatewayEventQueue({ maxQueueSize: 3 });
    for (let i = 0; i < 5; i++) {
      q.enqueueBlockedAttempt(attempt({ domain: `d${i}.com` }));
    }
    expect(q.getQueuedCount()).toBe(3);
    expect(q.getDroppedCount()).toBe(2);
    expect(errorSpy).toHaveBeenCalledTimes(1);
  });

  it('never delivers more than maxBatchSize per call and drains on stop()', async () => {
    const delivered: BlockedAttemptRecord[] = [];
    const sink = vi.fn(async (records: BlockedAttemptRecord[]) => {
      expect(records.length).toBeLessThanOrEqual(2);
      delivered.push(...records);
    });
    const q = new GatewayEventQueue({ sink, maxBatchSize: 2 });
    for (let i = 0; i < 5; i++) {
      q.enqueueBlockedAttempt(attempt({ domain: `d${i}.com` }));
    }
    await q.stop();
    expect(delivered.map((r) => r.domain).sort()).toEqual(['d0.com', 'd1.com', 'd2.com', 'd3.com', 'd4.com']);
    expect(q.getQueuedCount()).toBe(0);
  });

  it('stop() gives up after repeated sink failures without losing the queued events', async () => {
    const sink = vi.fn().mockRejectedValue(new Error('backend down'));
    const q = new GatewayEventQueue({ sink });
    q.enqueueBlockedAttempt(attempt({ domain: 'a.com' }));
    q.enqueueBlockedAttempt(attempt({ domain: 'b.com' }));
    await q.stop();
    expect(sink.mock.calls.length).toBeGreaterThanOrEqual(1);
    expect(sink.mock.calls.length).toBeLessThanOrEqual(3);
    expect(q.getQueuedCount()).toBe(2);
  });

  it('does not run two flushes concurrently', async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const sink = vi.fn(() => gate);
    const q = new GatewayEventQueue({ sink });
    q.enqueueBlockedAttempt(attempt());

    const first = q.flushNow();
    await q.flushNow();
    expect(sink).toHaveBeenCalledTimes(1);
    release();
    await first;
  });

  it('flushes periodically after start() and stops the timer on stop()', async () => {
    vi.useFakeTimers();
    const sink = vi.fn().mockResolvedValue(undefined);
    const q = new GatewayEventQueue({ sink, flushIntervalMs: 1000 });
    q.start();
    q.enqueueBlockedAttempt(attempt());
    expect(sink).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1000);
    expect(sink).toHaveBeenCalledTimes(1);

    await q.stop();
    q.enqueueBlockedAttempt(attempt({ domain: 'later.com' }));
    await vi.advanceTimersByTimeAsync(5000);
    expect(sink).toHaveBeenCalledTimes(1);
  });
});
