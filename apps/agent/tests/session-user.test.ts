import { describe, it, expect, afterEach, vi } from 'vitest';
import { SessionUserResolver, UNKNOWN_USER, sanitizeUserName } from '../src/session-user.js';
import type { LoginctlRunner, SessionUserResolverOptions } from '../src/session-user.js';

const session = (overrides: Record<string, string> = {}): string =>
    Object.entries({ Name: 'berlin', Remote: 'no', Type: 'wayland', Class: 'user', Active: 'yes', State: 'active', ...overrides })
        .map(([key, value]) => `${key}=${value}`)
        .join('\n') + '\n';

interface Script {
    seat: string | Error;
    session: string | Error;
}

function setup(script: Partial<Script> = {}, options: Partial<SessionUserResolverOptions> = {}) {
    const state: Script = { seat: '3\n', session: session(), ...script };
    const calls: string[][] = [];
    const logs: string[] = [];
    const run: LoginctlRunner = async (file, args) => {
        calls.push([file, ...args]);
        if (file !== 'loginctl') throw new Error('unexpected program');
        if (args[0] === 'show-seat') {
            if (state.seat instanceof Error) throw state.seat;
            return state.seat;
        }
        if (args[0] === 'show-session') {
            if (state.session instanceof Error) throw state.session;
            return state.session;
        }
        throw new Error('unexpected arguments');
    };
    const resolver = new SessionUserResolver({
        run,
        log: (_level, message) => {
            logs.push(message);
        },
        ...options,
    });
    return { resolver, state, calls, logs };
}

describe('SessionUserResolver', () => {
    afterEach(() => {
        vi.useRealTimers();
    });

    it('is unknown before the first lookup, then names the console user', async () => {
        const { resolver, calls, logs } = setup();
        expect(resolver.current()).toBe(UNKNOWN_USER);
        expect(await resolver.refresh()).toBe('berlin');
        expect(resolver.current()).toBe('berlin');
        expect(calls).toEqual([
            ['loginctl', 'show-seat', 'seat0', '-p', 'ActiveSession', '--value'],
            ['loginctl', 'show-session', '3', '-p', 'Name', '-p', 'Class', '-p', 'State', '-p', 'Remote', '-p', 'Active'],
        ]);
        expect(logs).toEqual([]);
    });

    it('reads properties by name, in any order, ignoring extra lines', async () => {
        const { resolver } = setup({ session: 'Active=yes\nSomething=else\nnot a property line\nState=active\nClass=user\nName=alice\nRemote=no\n' });
        expect(await resolver.refresh()).toBe('alice');
    });

    it('says unknown, quietly, when nobody is logged in at the console', async () => {
        const { resolver, calls, logs } = setup({ seat: '\n' });
        expect(await resolver.refresh()).toBe(UNKNOWN_USER);
        expect(calls).toHaveLength(1);
        expect(logs).toEqual([]);
    });

    it('says unknown, quietly, for sessions that are not a local active user', async () => {
        const overrides = [{ Class: 'greeter' }, { Class: 'manager' }, { Remote: 'yes' }, { Active: 'no' }, { State: 'closing' }, { State: 'online' }];
        for (const override of overrides) {
            const { resolver, logs } = setup({ session: session(override) });
            expect(await resolver.refresh(), JSON.stringify(override)).toBe(UNKNOWN_USER);
            expect(logs).toEqual([]);
        }
    });

    it('says unknown, and logs once, for a user name that does not look like a username', async () => {
        for (const name of ['bad name', '-flag', 'semi;colon', 'x'.repeat(65), '']) {
            const { resolver, logs } = setup({ session: session({ Name: name }) });
            expect(await resolver.refresh(), name).toBe(UNKNOWN_USER);
            expect(await resolver.refresh(), name).toBe(UNKNOWN_USER);
            expect(logs, name).toEqual(['the active login session has an unexpected user name; recording the user as unknown']);
        }
    });

    it('says unknown when the name is missing from the output', async () => {
        const { resolver } = setup({ session: 'Class=user\nRemote=no\nActive=yes\nState=active\n' });
        expect(await resolver.refresh()).toBe(UNKNOWN_USER);
    });

    it('never passes an unexpected session id to a command', async () => {
        const { resolver, calls, logs } = setup({ seat: '3; reboot\n' });
        expect(await resolver.refresh()).toBe(UNKNOWN_USER);
        expect(calls).toHaveLength(1);
        expect(logs).toEqual(['logind returned an unexpected session id; recording the user as unknown']);
    });

    it('drops back to unknown when a later lookup fails, logs once per streak, and recovers', async () => {
        const { resolver, state, logs } = setup();
        expect(await resolver.refresh()).toBe('berlin');
        state.seat = new Error('loginctl missing');
        expect(await resolver.refresh()).toBe(UNKNOWN_USER);
        expect(await resolver.refresh()).toBe(UNKNOWN_USER);
        expect(logs).toHaveLength(1);
        state.seat = '3\n';
        expect(await resolver.refresh()).toBe('berlin');
        state.seat = new Error('loginctl missing again');
        await resolver.refresh();
        expect(logs).toHaveLength(2);
    });

    it('shares one lookup between concurrent refreshes', async () => {
        let release: () => void = () => {};
        const gate = new Promise<void>((resolve) => {
            release = resolve;
        });
        const calls: string[][] = [];
        const run: LoginctlRunner = async (file, args) => {
            calls.push([file, ...args]);
            if (args[0] === 'show-seat') {
                await gate;
                return '3\n';
            }
            return session();
        };
        const resolver = new SessionUserResolver({ run, log: () => {} });
        const first = resolver.refresh();
        const second = resolver.refresh();
        expect(second).toBe(first);
        release();
        expect(await first).toBe('berlin');
        expect(calls.filter((call) => call[1] === 'show-seat')).toHaveLength(1);
    });

    it('refreshes on a timer after start() and stops on stop()', async () => {
        vi.useFakeTimers();
        const { resolver, calls } = setup({}, { refreshIntervalMs: 1000 });
        resolver.start();
        await vi.advanceTimersByTimeAsync(0);
        expect(calls).toHaveLength(2);
        expect(resolver.current()).toBe('berlin');
        await vi.advanceTimersByTimeAsync(1000);
        expect(calls).toHaveLength(4);
        resolver.stop();
        await vi.advanceTimersByTimeAsync(5000);
        expect(calls).toHaveLength(4);
    });

    it('rejects an invalid refresh interval or seat name', () => {
        expect(() => new SessionUserResolver({ refreshIntervalMs: 0 })).toThrow(RangeError);
        expect(() => new SessionUserResolver({ seat: 'seat0; reboot' })).toThrow(RangeError);
    });
});

describe('sanitizeUserName', () => {
    it('keeps plain usernames and replaces everything else with unknown', () => {
        for (const good of ['berlin', 'alice.smith', 'svc_backup', 'user@example', 'A1-b2']) {
            expect(sanitizeUserName(good)).toBe(good);
        }
        for (const bad of ['', ' ', 'two words', '-rf', 'a;b', 'x'.repeat(65), 'tab\tname', 'new\nline', 'nul\u0000', 42, null, undefined]) {
            expect(sanitizeUserName(bad), String(bad)).toBe(UNKNOWN_USER);
        }
    });
});
