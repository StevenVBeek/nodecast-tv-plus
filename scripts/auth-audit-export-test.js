'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const Database = require('better-sqlite3');
const express = require('express');
const service = require('../server/services/authAudit');
const { createRouter } = require('../server/routes/authLog');

const projectRoot = path.join(__dirname, '..');
const HOSTILE_UA = 'Mozilla/5.0 =HYPERLINK("http://198.51.100.1") <img src=x onerror=alert(1)>';

function fixture() {
    const database = new Database(':memory:');
    let time = Date.parse('2026-11-26T12:00:00Z');
    const audit = service.createAuthAudit({
        getDb: () => database,
        getSettings: async () => ({ authLogRetentionDays: 90, authLogMaxEntries: 50000 }),
        now: () => time,
        logger: null
    });
    return { database, audit, advance(ms) { time += ms; }, at: () => time };
}

const failure = (username, ip, reason = 'unknown_account') => ({ event: 'sign_in', outcome: 'failure', reason,
    username, method: 'password', context: { ip, peerIp: '192.168.2.222', forwardedFor: [ip, '192.168.2.222'],
        host: 'tv.example.test', userAgent: HOSTILE_UA } });
const success = (id, username, ip) => ({ event: 'sign_in', outcome: 'success', method: 'password',
    user: { id, username }, context: { ip, userAgent: 'curl/8.5.0' } });

function seed(f) {
    f.audit.record(failure('ghost', '203.0.113.7'));
    f.advance(1000);
    f.audit.record(success(1, 'admin', '192.168.1.81'));
    f.advance(1000);
    f.audit.record({ event: 'sign_out', outcome: 'success', user: { id: 1, username: 'admin' },
        context: { ip: '192.168.1.81' } });
    f.advance(1000);
    f.audit.record(failure('Jörg', '203.0.113.8', 'invalid_password'));
}

function testMatchesViewerFilters() {
    const f = fixture();
    try {
        seed(f);
        const cases = [{}, { account: 'ADMIN' }, { account: 'jö' }, { ip: '203.0.113.' }, { outcome: 'failure' },
            { event: 'sign_out' }, { method: 'password' }, { from: new Date(f.at() - 1500).toISOString() },
            { to: new Date(f.at() - 2500).toISOString() }, { outcome: 'bogus', event: 'bogus' }];
        for (const filters of cases) {
            const viewer = f.audit.query({ ...filters, pageSize: 100 });
            const exported = f.audit.exportEntries(filters);
            assert.deepEqual(exported.entries, viewer.entries, `Export must match the viewer for ${JSON.stringify(filters)}`);
            assert.equal(exported.total, viewer.total);
            assert.equal(exported.count, viewer.entries.length);
            assert.equal(exported.truncated, false);
        }
        // Paging parameters do not limit an export.
        assert.equal(f.audit.exportEntries({ page: '2', pageSize: '1' }).count, 4);
    } finally { f.database.close(); }
}

function testFormatAndTimestamps() {
    const f = fixture();
    try {
        seed(f);
        const exported = f.audit.exportEntries({ from: String(f.at() - 10000), account: '  gh‮ost ', outcome: 'nope' });
        assert.equal(exported.schemaVersion, service.EXPORT_SCHEMA_VERSION);
        assert.equal(exported.exportedAt, new Date(f.at()).toISOString());
        assert.match(exported.notice, /personal data/i);
        assert.equal(exported.order, 'newest_first');
        assert.equal(exported.limit, service.MAX_EXPORT_ENTRIES);
        assert.deepEqual(exported.filters, {
            from: new Date(f.at() - 10000).toISOString(), to: null, account: 'gh ost', ip: null,
            outcome: null, event: null, method: null
        }, 'Applied filters are reported normalized, and ignored values as null.');
        const iso = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
        const all = f.audit.exportEntries();
        for (const entry of all.entries) {
            for (const key of ['at', 'firstAt', 'lastAt']) assert.match(entry[key], iso, `${key} is an ISO 8601 UTC time`);
        }
        const times = all.entries.map(entry => Date.parse(entry.at));
        assert.deepEqual(times, [...times].sort((a, b) => b - a), 'Newest entries come first.');
        // Only the viewer's public fields are exported, never storage internals.
        const viewerKeys = Object.keys(f.audit.query().entries[0]).sort();
        for (const entry of all.entries) assert.deepEqual(Object.keys(entry).sort(), viewerKeys);
        const text = JSON.stringify(all);
        for (const internal of ['summary_key', 'category', 'reason_counts', 'activity_counts', 'created_at']) {
            assert.equal(text.includes(internal), false, `${internal} must not be exported.`);
        }
        // Untrusted text is kept as data; JSON encoding keeps it inert.
        assert.equal(all.entries.find(entry => entry.username === 'ghost').userAgent, HOSTILE_UA);
        assert.deepEqual(JSON.parse(text), all);
    } finally { f.database.close(); }
}

function testSummaryRowsKeepTheirCounts() {
    const f = fixture();
    try {
        // Exceed the per-source limit so failures are grouped.
        for (let index = 0; index < service.FAILURE_SOURCE_LIMIT + 7; index++) {
            f.audit.record(failure(`attempt-${index}`, '203.0.113.50', index % 2 ? 'invalid_password' : 'unknown_account'));
            f.advance(100);
        }
        for (let index = 0; index < service.ACTIVITY_ACCOUNT_LIMIT + 3; index++) {
            f.audit.record(success(9, 'busy', '192.168.1.9'));
            f.advance(100);
        }
        assert.equal(f.audit.flushPending(), true);
        const exported = f.audit.exportEntries();
        const grouped = exported.entries.find(entry => entry.event === 'failure_summary');
        assert.equal(grouped.occurrences, 7);
        assert.deepEqual(grouped.reasonCounts, { unknown_account: 3, invalid_password: 4 });
        assert.ok(Date.parse(grouped.firstAt) < Date.parse(grouped.lastAt));
        assert.equal(grouped.ip, null, 'Failure summaries carry no individual address.');
        assert.equal(grouped.username, null);
        assert.match(grouped.reasonText, /^7 additional ordinary failures were grouped\.$/);
        const activity = exported.entries.find(entry => entry.event === 'activity_summary');
        assert.equal(activity.occurrences, 3);
        assert.equal(activity.summaryEvent, 'sign_in');
        assert.equal(activity.username, 'busy');
        assert.equal(f.audit.exportEntries({ event: 'failure_summary' }).count, 1);
        assert.equal(f.audit.exportEntries({ account: 'busy', event: 'activity_summary' }).count, 1);
        assert.equal(f.audit.exportEntries({ ip: '203.0.113.50', event: 'failure_summary' }).count, 0,
            'IP filters do not match summaries, as in the viewer.');
    } finally { f.database.close(); }
}

function testExportDoesNotWrite() {
    const f = fixture();
    try {
        for (let index = 0; index < service.FAILURE_SOURCE_LIMIT + 3; index++) {
            f.audit.record(failure(`attempt-${index}`, '203.0.113.60'));
        }
        const before = f.database.prepare('SELECT COUNT(*) n, MAX(id) id FROM auth_events').get();
        const changes = f.database.prepare('SELECT total_changes() n').get().n;
        const exported = f.audit.exportEntries();
        assert.equal(exported.count, service.FAILURE_SOURCE_LIMIT, 'Pending summary counts are not flushed by an export.');
        assert.deepEqual(f.database.prepare('SELECT COUNT(*) n, MAX(id) id FROM auth_events').get(), before);
        assert.equal(f.database.prepare('SELECT total_changes() n').get().n, changes);
    } finally { f.database.close(); }
}

function testExportIsBounded() {
    const f = fixture();
    try {
        f.audit.query();
        const insert = f.database.prepare(`INSERT INTO auth_events (created_at,event,outcome,reason,username,category)
            VALUES (?,'sign_in','failure','unknown_account',?, 'ordinary')`);
        const base = Date.parse('2026-11-01T00:00:00Z');
        const extra = 5;
        f.database.transaction(() => {
            for (let index = 0; index < service.MAX_EXPORT_ENTRIES + extra; index++) insert.run(base + index * 1000, `user-${index}`);
        })();
        const exported = f.audit.exportEntries();
        assert.equal(exported.total, service.MAX_EXPORT_ENTRIES + extra);
        assert.equal(exported.count, service.MAX_EXPORT_ENTRIES);
        assert.equal(exported.entries.length, service.MAX_EXPORT_ENTRIES);
        assert.equal(exported.truncated, true);
        assert.equal(exported.entries[0].username, `user-${service.MAX_EXPORT_ENTRIES + extra - 1}`, 'The newest entries are kept.');
        assert.equal(exported.entries.at(-1).username, `user-${extra}`, 'The oldest matches are left out.');
        // A narrower range fits again.
        const narrowed = f.audit.exportEntries({ to: new Date(base + (extra - 1) * 1000).toISOString() });
        assert.equal(narrowed.count, extra);
        assert.equal(narrowed.truncated, false);
    } finally { f.database.close(); }
}

// ---------------------------------------------------------------------------
// Route tests: the real router with stubbed authentication
// ---------------------------------------------------------------------------

async function withRouter({ admin = true, audit }, callback) {
    const app = express();
    const authService = {
        requireAuth: (req, res, next) => {
            if (req.get('x-test-user') === 'none') return res.status(401).json({ error: 'Authentication required' });
            req.user = { id: Number(req.get('x-test-user') || 1), role: admin ? 'admin' : 'viewer' };
            next();
        },
        requireAdmin: (req, res, next) => (req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admin access required' }))
    };
    app.use('/api/auth-log', createRouter({ authService, audit }));
    const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    try {
        await callback(`http://127.0.0.1:${server.address().port}/api/auth-log`);
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
}

async function testExportRoute() {
    const f = fixture();
    try {
        seed(f);
        const calls = [];
        const audit = { query: f.audit.query, exportEntries: filters => { calls.push(filters); return f.audit.exportEntries(filters); } };
        await withRouter({ audit }, async base => {
            const response = await fetch(`${base}/export?account=ghost&page=3&pageSize=1&ip=203.&outcome=failure`
                + '&event=sign_in&method=password&from=2026-11-01T00:00:00Z&to=2026-12-01T00:00:00Z');
            assert.equal(response.status, 200);
            assert.match(response.headers.get('content-type'), /^application\/json/);
            assert.equal(response.headers.get('cache-control'), 'no-store');
            assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
            assert.equal(response.headers.get('content-disposition'),
                'attachment; filename="nodecast-sign-in-activity-2026-11-26T12-00-03Z.json"');
            const text = await response.text();
            const body = JSON.parse(text);
            assert.equal(text, `${JSON.stringify(body, null, 2)}\n`, 'The file is sent in its final, readable form.');
            assert.equal(body.count, 1);
            assert.equal(body.entries[0].username, 'ghost');
            assert.deepEqual(calls.at(-1), { from: '2026-11-01T00:00:00Z', to: '2026-12-01T00:00:00Z', account: 'ghost',
                ip: '203.', outcome: 'failure', event: 'sign_in', method: 'password' }, 'Paging parameters are not passed.');

            // Repeated parameters arrive as arrays and are ignored, as in the viewer.
            await fetch(`${base}/export?account=a&account=b`);
            assert.equal(calls.at(-1).account, undefined);
            // The list endpoint still works next to the export route.
            assert.equal((await fetch(`${base}?pageSize=1`)).status, 200);
        });

        // Exports are limited per administrator on top of the shared read limit.
        await withRouter({ audit }, async base => {
            for (let attempt = 0; attempt < 10; attempt++) {
                assert.equal((await fetch(`${base}/export`, { headers: { 'x-test-user': '5' } })).status, 200);
            }
            const limited = await fetch(`${base}/export`, { headers: { 'x-test-user': '5' } });
            assert.equal(limited.status, 429);
            assert.equal((await limited.json()).error, 'Too many exports. Try again shortly.');
            assert.equal((await fetch(`${base}/export`, { headers: { 'x-test-user': '6' } })).status, 200,
                'Another administrator has their own allowance.');
            assert.equal((await fetch(base, { headers: { 'x-test-user': '5' } })).status, 200,
                'The export limit does not block browsing.');
        });

        await withRouter({ admin: false, audit }, async base => {
            const response = await fetch(`${base}/export`);
            assert.equal(response.status, 403);
            assert.equal(response.headers.get('content-disposition'), null);
            assert.equal((await fetch(`${base}/export`, { headers: { 'x-test-user': 'none' } })).status, 401);
        });

        const failing = { query: f.audit.query, exportEntries: () => { throw new Error('secret storage path /data/content.db'); } };
        const originalError = console.error;
        console.error = () => {};
        try {
            await withRouter({ audit: failing }, async base => {
                const response = await fetch(`${base}/export`);
                assert.equal(response.status, 500);
                assert.equal(response.headers.get('content-disposition'), null);
                assert.deepEqual(await response.json(), { error: 'The sign-in log could not be exported.' });
            });
        } finally { console.error = originalError; }
    } finally { f.database.close(); }
}

// ---------------------------------------------------------------------------
// Integration test: real server, real authentication
// ---------------------------------------------------------------------------

class CookieJar {
    constructor() { this.cookies = new Map(); }
    absorb(response) {
        for (const header of response.headers.getSetCookie()) {
            const pair = header.split(';', 1)[0];
            const separator = pair.indexOf('=');
            const value = pair.slice(separator + 1);
            if (value) this.cookies.set(pair.slice(0, separator), value);
            else this.cookies.delete(pair.slice(0, separator));
        }
    }
    header() { return [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; '); }
}

function getFreePort() {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.unref();
        server.on('error', reject);
        server.listen(0, '127.0.0.1', () => {
            const { port } = server.address();
            server.close(() => resolve(port));
        });
    });
}

async function startServer(dataDirectory) {
    const port = await getFreePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    let output = '';
    const child = spawn(process.execPath, ['server/index.js'], {
        cwd: projectRoot,
        env: {
            ...process.env,
            NODE_ENV: 'test',
            NODECAST_DATA_DIR: dataDirectory,
            NODECAST_DISABLE_BACKGROUND_JOBS: 'true',
            PORT: String(port),
            JWT_SECRET: crypto.randomBytes(48).toString('hex'),
            SESSION_SECRET: crypto.randomBytes(48).toString('hex'),
            TOTP_ENCRYPTION_KEY: crypto.randomBytes(48).toString('hex'),
            OIDC_ISSUER_URL: '',
            OIDC_CLIENT_ID: '',
            OIDC_CLIENT_SECRET: '',
            DISABLE_LOCAL_AUTH: '',
            TRUST_PROXY: ''
        },
        stdio: ['ignore', 'pipe', 'pipe']
    });
    child.stdout.on('data', chunk => { output += chunk.toString(); });
    child.stderr.on('data', chunk => { output += chunk.toString(); });
    const deadline = Date.now() + 30000;
    while (Date.now() < deadline) {
        if (child.exitCode !== null) break;
        try {
            if (await require('./helpers/applicationReadiness').isApplicationReady(baseUrl)) return { baseUrl, child };
        } catch {
            // The server may still be starting.
        }
        await new Promise(resolve => setTimeout(resolve, 200));
    }
    console.error(output);
    child.kill('SIGKILL');
    throw new Error('Server did not become ready.');
}

async function stopServer(child) {
    if (!child || child.exitCode !== null) return;
    child.kill('SIGTERM');
    await Promise.race([
        new Promise(resolve => child.once('exit', resolve)),
        new Promise(resolve => setTimeout(resolve, 5000))
    ]);
    if (child.exitCode === null) child.kill('SIGKILL');
}

async function request(baseUrl, route, { method = 'GET', body, jar = new CookieJar(), headers = {} } = {}) {
    const allHeaders = { ...headers };
    if (body !== undefined) allHeaders['Content-Type'] = 'application/json';
    if (jar.header()) allHeaders.Cookie = jar.header();
    const response = await fetch(`${baseUrl}${route}`, {
        method, headers: allHeaders, body: body === undefined ? undefined : JSON.stringify(body)
    });
    jar.absorb(response);
    const text = await response.text();
    let payload = null;
    try { payload = text ? JSON.parse(text) : null; } catch { payload = text; }
    return { response, payload, jar };
}

async function testServerExport() {
    const dataDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'nodecast-auth-export-'));
    const adminPassword = `Admin-${crypto.randomBytes(8).toString('hex')}`;
    const viewerPassword = `Viewer-${crypto.randomBytes(8).toString('hex')}`;
    const wrongPassword = `Wrong-${crypto.randomBytes(8).toString('hex')}`;
    let server;
    try {
        server = await startServer(dataDirectory);
        const { baseUrl } = server;
        const admin = new CookieJar();
        assert.equal((await request(baseUrl, '/api/auth/setup', { method: 'POST', jar: admin,
            body: { username: 'admin', password: adminPassword, passwordConfirmation: adminPassword } })).response.status, 201);
        await request(baseUrl, '/api/auth/login', { method: 'POST',
            body: { username: '=cmd|"/c calc"!A1', password: wrongPassword }, headers: { 'User-Agent': HOSTILE_UA } });
        assert.equal((await request(baseUrl, '/api/auth/login', { method: 'POST', jar: admin,
            body: { username: 'admin', password: adminPassword } })).response.status, 200);
        assert.equal((await request(baseUrl, '/api/auth/users', { method: 'POST', jar: admin,
            body: { username: 'viewer', password: viewerPassword, passwordConfirmation: viewerPassword, role: 'viewer' } }))
            .response.status, 201);
        const viewer = new CookieJar();
        assert.equal((await request(baseUrl, '/api/auth/login', { method: 'POST', jar: viewer,
            body: { username: 'viewer', password: viewerPassword } })).response.status, 200);

        const exported = await request(baseUrl, '/api/auth-log/export?outcome=failure', { jar: admin });
        assert.equal(exported.response.status, 200, JSON.stringify(exported.payload));
        assert.equal(exported.response.headers.get('cache-control'), 'no-store');
        assert.match(exported.response.headers.get('content-disposition'),
            /^attachment; filename="nodecast-sign-in-activity-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z\.json"$/);
        assert.equal(exported.payload.count, 1);
        assert.equal(exported.payload.entries[0].username, '=cmd|"/c calc"!A1');
        assert.equal(exported.payload.entries[0].reason, 'unknown_account');
        assert.equal(exported.payload.entries[0].userAgent, HOSTILE_UA);
        const all = await request(baseUrl, '/api/auth-log/export', { jar: admin });
        const viewerPage = await request(baseUrl, '/api/auth-log?pageSize=100', { jar: admin });
        assert.deepEqual(all.payload.entries, viewerPage.payload.entries, 'The export holds exactly what the viewer shows.');
        const text = JSON.stringify(all.payload);
        for (const secret of [adminPassword, viewerPassword, wrongPassword]) {
            assert.equal(text.includes(secret), false, 'An export must not contain passwords.');
        }

        const denied = await request(baseUrl, '/api/auth-log/export', { jar: viewer });
        assert.equal(denied.response.status, 403);
        assert.equal(denied.response.headers.get('content-disposition'), null);
        assert.equal((await request(baseUrl, '/api/auth-log/export')).response.status, 401);
    } finally {
        await stopServer(server?.child);
        await fs.rm(dataDirectory, { recursive: true, force: true }).catch(() => {});
    }
}

async function run() {
    testMatchesViewerFilters();
    testFormatAndTimestamps();
    testSummaryRowsKeepTheirCounts();
    testExportDoesNotWrite();
    testExportIsBounded();
    await testExportRoute();
    await testServerExport();
    console.log('Sign-in activity export tests passed.');
}

run().catch(error => {
    console.error(error);
    process.exit(1);
});
