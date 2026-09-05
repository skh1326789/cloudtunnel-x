import { KvSettings } from '#types/settings';
import { HttpStatus, respond, safeError } from '@common';
import { getDataset } from '@kv';
import { connect } from 'cloudflare:sockets';

const CLOUDFLARE_IPV4_RANGES = [
    '173.245.48.0/20',
    '103.21.244.0/22',
    '103.22.200.0/22',
    '103.31.4.0/22',
    '141.101.64.0/18',
    '108.162.192.0/18',
    '190.93.240.0/20',
    '188.114.96.0/20',
    '197.234.240.0/22',
    '198.41.128.0/17',
    '162.158.0.0/15',
    '104.16.0.0/13',
    '104.24.0.0/14',
    '172.64.0.0/13',
    '131.0.72.0/22'
];

const SCANNER_STATE_KEY = 'cleanIpScannerState';
const SCAN_ATTEMPTS = 3;
const CONNECT_TIMEOUT_MS = 3500;
const CANDIDATE_LIMIT = 48;
const BEST_IP_LIMIT = 10;
const TEST_HOST = 'speed.cloudflare.com';
const TEST_PATH = '/__down?bytes=5000';

interface ScanResult {
    ip: string;
    ok: boolean;
    successCount: number;
    avgLatencyMs: number | null;
}

interface ScannerState {
    lastRunAt?: string;
    nextRunAt?: string;
    results?: ScanResult[];
    message?: string;
}

export async function handleCleanIpScan(request: Request, env: Env): Promise<Response> {
    if (request.method !== 'POST') {
        return respond(false, HttpStatus.METHOD_NOT_ALLOWED, 'Method not allowed.');
    }

    try {
        const result = await scanAndApplyCleanIPs(env, true);
        return respond(true, HttpStatus.OK, result.message, result);
    } catch (error) {
        return respond(false, HttpStatus.INTERNAL_SERVER_ERROR, safeError(error));
    }
}

export async function runScheduledCleanIpScan(env: Env): Promise<void> {
    try {
        await scanAndApplyCleanIPs(env, false);
    } catch (error) {
        console.error('Scheduled Clean IP scan failed:', error);
    }
}

async function scanAndApplyCleanIPs(env: Env, force: boolean) {
    const { settings } = await getDataset(env);
    const now = Date.now();
    const intervalHours = Number(settings.cleanIpScanIntervalHours || 0);
    const previousState = await getScannerState(env);

    if (!force) {
        if (!settings.cleanIpAutoScan || intervalHours < 1) return {
            message: 'Clean IP auto scan is disabled.',
            skipped: true
        };

        const nextRunAt = previousState.nextRunAt ? Date.parse(previousState.nextRunAt) : 0;
        if (nextRunAt && nextRunAt > now) return {
            message: 'Clean IP scan interval has not elapsed.',
            skipped: true,
            nextRunAt: previousState.nextRunAt
        };
    }

    const candidates = buildCandidates(now).slice(0, CANDIDATE_LIMIT);
    const results = await Promise.all(candidates.map(scanCandidate));
    const best = rankResults(results).slice(0, BEST_IP_LIMIT);

    if (!best.length) {
        const failedState = buildScannerState(now, intervalHours, results, 'No healthy Clean IP candidates found.');
        await saveScannerState(env, failedState);
        return { ...failedState, skipped: false, cleanIPs: settings.cleanIPs };
    }

    const updatedSettings: KvSettings = {
        ...settings,
        cleanIPs: best.map(result => result.ip),
        cleanIpAutoScan: settings.cleanIpAutoScan,
        cleanIpScanIntervalHours: intervalHours,
        cleanIpLastScanAt: new Date(now).toISOString(),
        cleanIpScanResults: best
    };

    await env.sb.put('proxySettings', JSON.stringify(updatedSettings));

    const successState = buildScannerState(now, intervalHours, best, `Updated Clean IPs with ${best.length} healthy candidates.`);
    await saveScannerState(env, successState);

    return {
        ...successState,
        skipped: false,
        cleanIPs: updatedSettings.cleanIPs
    };
}

function rankResults(results: ScanResult[]): ScanResult[] {
    return results
        .filter(result => result.ok && result.avgLatencyMs !== null)
        .sort((a, b) => {
            if (b.successCount !== a.successCount) return b.successCount - a.successCount;
            return (a.avgLatencyMs || Infinity) - (b.avgLatencyMs || Infinity);
        });
}

function buildScannerState(now: number, intervalHours: number, results: ScanResult[], message: string): ScannerState {
    const nextRunAt = intervalHours > 0
        ? new Date(now + intervalHours * 60 * 60 * 1000).toISOString()
        : undefined;

    return {
        lastRunAt: new Date(now).toISOString(),
        nextRunAt,
        results,
        message
    };
}

async function getScannerState(env: Env): Promise<ScannerState> {
    return await env.sb.get(SCANNER_STATE_KEY, { type: 'json' }) || {};
}

async function saveScannerState(env: Env, state: ScannerState): Promise<void> {
    await env.sb.put(SCANNER_STATE_KEY, JSON.stringify(state));
}

function buildCandidates(seed: number): string[] {
    const candidates = new Set<string>();

    CLOUDFLARE_IPV4_RANGES.forEach((range, rangeIndex) => {
        const [base, prefix] = range.split('/');
        const baseInt = ipv4ToInt(base);
        const hostCount = 2 ** (32 - Number(prefix));
        const usable = Math.max(hostCount - 2, 1);

        for (let i = 0; i < 4; i++) {
            const offset = 1 + Math.abs(hashNumber(`${seed}:${rangeIndex}:${i}`)) % usable;
            candidates.add(intToIpv4(baseInt + offset));
        }
    });

    return [...candidates];
}

async function scanCandidate(ip: string): Promise<ScanResult> {
    const attempts = await Promise.all(Array.from({ length: SCAN_ATTEMPTS }, () => checkCloudflareIP(ip)));
    const successes = attempts.filter(attempt => attempt.ok);
    const avgLatencyMs = successes.length
        ? Math.round(successes.reduce((sum, attempt) => sum + attempt.elapsedMs, 0) / successes.length)
        : null;

    return {
        ip,
        ok: successes.length > 0,
        successCount: successes.length,
        avgLatencyMs
    };
}

async function checkCloudflareIP(ip: string): Promise<{ ok: boolean; elapsedMs: number }> {
    const start = Date.now();
    const timeout = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('timeout')), CONNECT_TIMEOUT_MS)
    );

    try {
        const socket = connect({ hostname: ip, port: 443 });
        const writer = socket.writable.getWriter();
        const req = `GET ${TEST_PATH} HTTP/1.1\r\nHost: ${TEST_HOST}\r\nConnection: close\r\n\r\n`;

        await writer.write(new TextEncoder().encode(req));
        writer.releaseLock();

        const reader = socket.readable.getReader();
        const { value, done } = await Promise.race([reader.read(), timeout]);
        reader.releaseLock();
        await socket.close().catch(() => { });

        if (done || !value) return { ok: false, elapsedMs: Date.now() - start };

        const response = new TextDecoder().decode(value);
        return {
            ok: /^HTTP\/1\.[01] \d{3}/.test(response) && /cf-ray:/i.test(response),
            elapsedMs: Date.now() - start
        };
    } catch {
        return { ok: false, elapsedMs: Date.now() - start };
    }
}

function ipv4ToInt(ip: string): number {
    return ip.split('.').reduce((sum, octet) => (sum << 8) + Number(octet), 0) >>> 0;
}

function intToIpv4(value: number): string {
    return [
        (value >>> 24) & 255,
        (value >>> 16) & 255,
        (value >>> 8) & 255,
        value & 255
    ].join('.');
}

function hashNumber(value: string): number {
    let hash = 2166136261;
    for (let i = 0; i < value.length; i++) {
        hash ^= value.charCodeAt(i);
        hash = Math.imul(hash, 16777619);
    }

    return hash >>> 0;
}
