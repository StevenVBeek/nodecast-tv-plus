const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const OTPAuth = require('otpauth');
const { SoftwareAuthenticator } = require('../tests/fixtures/software-authenticator');

const projectRoot = path.join(__dirname, '..');

class CookieJar {
    constructor() {
        this.cookies = new Map();
    }

    absorb(response) {
        for (const header of response.headers.getSetCookie()) {
            const pair = header.split(';', 1)[0];
            const separator = pair.indexOf('=');
            const name = pair.slice(0, separator);
            const value = pair.slice(separator + 1);
            if (value) this.cookies.set(name, value);
            else this.cookies.delete(name);
        }
    }

    header() {
        return [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; ');
    }
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

async function waitForServer(baseUrl, child, timeoutMs = 30000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (child.exitCode !== null) throw new Error(`Server exited with code ${child.exitCode}.`);
        try {
            if (await require('./helpers/applicationReadiness').isApplicationReady(baseUrl)) return;
        } catch {
            // The server may still be starting.
        }
        await new Promise(resolve => setTimeout(resolve, 200));
    }
    throw new Error('Server did not become ready.');
}

async function startServer(dataDirectory, secrets, { secondFactorsAvailable = true } = {}) {
    const port = await getFreePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    const origin = `http://localhost:${port}`;
    let output = '';
    const child = spawn(process.execPath, ['server/index.js'], {
        cwd: projectRoot,
        env: {
            ...process.env,
            NODE_ENV: 'test',
            NODECAST_DATA_DIR: dataDirectory,
            NODECAST_DISABLE_BACKGROUND_JOBS: 'true',
            PORT: String(port),
            APP_ORIGIN: secondFactorsAvailable ? origin : '',
            JWT_SECRET: secrets.jwt,
            SESSION_SECRET: secrets.session,
            TOTP_ENCRYPTION_KEY: secondFactorsAvailable ? secrets.totp : '',
            OIDC_ISSUER_URL: '',
            OIDC_CLIENT_ID: '',
            OIDC_CLIENT_SECRET: '',
            OIDC_AUTH_URL: '',
            OIDC_TOKEN_URL: '',
            OIDC_USERINFO_URL: '',
            DISABLE_LOCAL_AUTH: '',
            OIDC_AUTO_REDIRECT: ''
        },
        stdio: ['ignore', 'pipe', 'pipe']
    });
    child.stdout.on('data', chunk => { output += chunk.toString(); });
    child.stderr.on('data', chunk => { output += chunk.toString(); });
    await waitForServer(baseUrl, child);
    return { baseUrl, origin, child, getOutput: () => output };
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

async function request(baseUrl, route, { method = 'GET', body, jar = new CookieJar(), headers: extraHeaders = {} } = {}) {
    const headers = { ...extraHeaders };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (jar.header()) headers.Cookie = jar.header();
    const response = await fetch(`${baseUrl}${route}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body)
    });
    jar.absorb(response);
    const text = await response.text();
    const isJson = response.headers.get('content-type')?.includes('application/json');
    const payload = text && isJson ? JSON.parse(text) : (text || null);
    return { response, payload, jar };
}

function totp(secret, timestamp = Date.now()) {
    return new OTPAuth.TOTP({
        issuer: 'NodeCast TV Plus',
        label: 'test',
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: OTPAuth.Secret.fromBase32(secret)
    }).generate({ timestamp });
}

async function signIn(baseUrl, username, password) {
    const login = await request(baseUrl, '/api/auth/login', {
        method: 'POST',
        body: { username, password }
    });
    assert.equal(login.response.status, 200);
    assert.equal(login.payload.requiresTwoFactor, undefined);
    return login.jar;
}

async function sessionPending(baseUrl, jar, headers = {}) {
    const me = await request(baseUrl, '/api/auth/me', { jar, headers });
    assert.equal(me.response.status, 200);
    assert.equal(typeof me.payload.mfaOnboardingPending, 'boolean');
    // The application's startup check must report the same state wherever
    // the session status endpoint exists.
    const session = await request(baseUrl, '/api/auth/session', { jar, headers });
    if (session.payload && typeof session.payload === 'object' && 'authenticated' in session.payload) {
        assert.equal(session.payload.authenticated, true);
        assert.equal(session.payload.user.mfaOnboardingPending, me.payload.mfaOnboardingPending);
    }
    return me.payload.mfaOnboardingPending;
}

async function completePrompt(baseUrl, jar, body = {}) {
    const completed = await request(baseUrl, '/api/auth/me/mfa-onboarding', { method: 'PUT', jar, body });
    assert.equal(completed.response.status, 200);
    assert.deepEqual(completed.payload, { mfaOnboardingPending: false });
}

async function createUser(baseUrl, adminJar, username, role) {
    const password = crypto.randomBytes(24).toString('base64url');
    const created = await request(baseUrl, '/api/auth/users', {
        method: 'POST',
        jar: adminJar,
        body: { username, password, passwordConfirmation: password, role }
    });
    assert.equal(created.response.status, 201);
    assert.equal('mfaOnboardingPending' in created.payload, false, 'Administrators must not see another account\'s onboarding state.');
    return { id: created.payload.id, username, password };
}

async function readDatabase(dataDirectory) {
    return JSON.parse(await fs.readFile(path.join(dataDirectory, 'db.json'), 'utf8'));
}

async function testNewAccounts(secrets) {
    const dataDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'nodecast-mfa-onboarding-'));
    let server;
    try {
        server = await startServer(dataDirectory, secrets);
        const { baseUrl } = server;

        // The initial administrator keeps the setup-page onboarding from the
        // first-run flow and never receives a second, server-driven prompt.
        const adminPassword = crypto.randomBytes(24).toString('base64url');
        const setup = await request(baseUrl, '/api/auth/setup', {
            method: 'POST',
            body: { username: 'FirstAdmin', password: adminPassword, passwordConfirmation: adminPassword }
        });
        assert.equal(setup.response.status, 201);
        assert.deepEqual(setup.payload.onboarding, { mfaEnrollmentRecommended: true });
        const adminJar = setup.jar;
        assert.equal(await sessionPending(baseUrl, adminJar), false);

        const viewer = await createUser(baseUrl, adminJar, 'NewViewer', 'viewer');
        const secondAdmin = await createUser(baseUrl, adminJar, 'NewAdmin', 'admin');
        const bystander = await createUser(baseUrl, adminJar, 'Bystander', 'viewer');
        const enroller = await createUser(baseUrl, adminJar, 'Enroller', 'viewer');
        const passkeyUser = await createUser(baseUrl, adminJar, 'PasskeyUser', 'viewer');

        const listed = await request(baseUrl, '/api/auth/users', { jar: adminJar });
        assert.equal(listed.response.status, 200);
        assert.equal(JSON.stringify(listed.payload).includes('mfaOnboardingPending'), false,
            'The user list must not reveal which accounts still have the prompt.');

        // New local viewer and administrator accounts receive the prompt, and
        // it survives a refresh until a choice is recorded.
        const viewerJar = await signIn(baseUrl, viewer.username, viewer.password);
        assert.equal(await sessionPending(baseUrl, viewerJar), true);
        assert.equal(await sessionPending(baseUrl, viewerJar), true, 'Refreshing before choosing shows the prompt again.');
        const me = await request(baseUrl, '/api/auth/me', { jar: viewerJar });
        assert.equal(me.payload.mfaOnboardingPending, true);
        const secondAdminJar = await signIn(baseUrl, secondAdmin.username, secondAdmin.password);
        assert.equal(await sessionPending(baseUrl, secondAdminJar), true);

        // Requests from another origin or without a session cannot change it.
        const crossSite = await request(baseUrl, '/api/auth/me/mfa-onboarding', {
            method: 'PUT',
            jar: viewerJar,
            body: {},
            headers: { Origin: 'https://attacker.example' }
        });
        assert.equal(crossSite.response.status, 403);
        const anonymous = await request(baseUrl, '/api/auth/me/mfa-onboarding', { method: 'PUT', body: {} });
        assert.equal(anonymous.response.status, 401);
        assert.equal(await sessionPending(baseUrl, viewerJar), true);

        // A choice is stored per account: it holds across refresh, a second
        // device and later sign-ins, and does not affect other accounts even
        // when the request names one of them.
        await completePrompt(baseUrl, viewerJar, { id: bystander.id, userId: bystander.id });
        assert.equal(await sessionPending(baseUrl, viewerJar), false);
        const otherDevice = await signIn(baseUrl, viewer.username, viewer.password);
        assert.equal(await sessionPending(baseUrl, otherDevice), false);
        await completePrompt(baseUrl, otherDevice);
        assert.equal(await sessionPending(baseUrl, secondAdminJar), true);
        const bystanderJar = await signIn(baseUrl, bystander.username, bystander.password);
        assert.equal(await sessionPending(baseUrl, bystanderJar), true);

        await completePrompt(baseUrl, secondAdminJar);
        const secondAdminLater = await signIn(baseUrl, secondAdmin.username, secondAdmin.password);
        assert.equal(await sessionPending(baseUrl, secondAdminLater), false);

        // Enrolling in MFA also completes onboarding, so disabling MFA later
        // never brings the prompt back.
        const enrollerJar = await signIn(baseUrl, enroller.username, enroller.password);
        assert.equal(await sessionPending(baseUrl, enrollerJar), true);
        const started = await request(baseUrl, '/api/auth/2fa/enroll', {
            method: 'POST',
            jar: enrollerJar,
            body: { password: enroller.password }
        });
        assert.equal(started.response.status, 200);
        // An interrupted enrollment leaves the choice open on the server; the
        // page records Continue before it opens enrollment.
        assert.equal(await sessionPending(baseUrl, enrollerJar), true);
        const enrollmentCode = totp(started.payload.manualSecret);
        const confirmed = await request(baseUrl, '/api/auth/2fa/confirm', {
            method: 'POST',
            jar: enrollerJar,
            body: { code: enrollmentCode }
        });
        assert.equal(confirmed.response.status, 200);
        assert.equal(await sessionPending(baseUrl, enrollerJar), false);
        const disabled = await request(baseUrl, '/api/auth/2fa/disable', {
            method: 'POST',
            jar: enrollerJar,
            body: {
                password: enroller.password,
                credentialType: 'recovery',
                credential: confirmed.payload.recoveryCodes[0]
            }
        });
        assert.equal(disabled.response.status, 200);
        assert.equal(await sessionPending(baseUrl, enrollerJar), false);

        // Adding a passkey completes onboarding in the same way.
        const passkeyJar = await signIn(baseUrl, passkeyUser.username, passkeyUser.password);
        assert.equal(await sessionPending(baseUrl, passkeyJar), true);
        const registrationOptions = await request(baseUrl, '/api/auth/passkeys/registration/options', {
            method: 'POST',
            jar: passkeyJar,
            body: { password: passkeyUser.password }
        });
        assert.equal(registrationOptions.response.status, 200, JSON.stringify(registrationOptions.payload));
        const authenticator = new SoftwareAuthenticator({ rpId: 'localhost', origin: server.origin });
        const registered = await request(baseUrl, '/api/auth/passkeys/registration/verify', {
            method: 'POST',
            jar: passkeyJar,
            body: { response: authenticator.register(registrationOptions.payload.options), name: 'Test passkey' }
        });
        assert.equal(registered.response.status, 201, JSON.stringify(registered.payload));
        assert.equal(await sessionPending(baseUrl, passkeyJar), false);

        const stored = await readDatabase(dataDirectory);
        const storedState = Object.fromEntries(stored.users.map(user => [user.username, user.mfaOnboardingPending === true]));
        assert.deepEqual(storedState, {
            FirstAdmin: false,
            NewViewer: false,
            NewAdmin: false,
            Bystander: true,
            Enroller: false,
            PasskeyUser: false
        });
    } catch (error) {
        if (server) console.error(server.getOutput());
        throw error;
    } finally {
        if (server) await stopServer(server.child);
        await fs.rm(dataDirectory, { recursive: true, force: true });
    }
}

async function testExistingInstallation(secrets) {
    const dataDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'nodecast-mfa-onboarding-upgrade-'));
    const passwords = {
        LegacyAdmin: crypto.randomBytes(24).toString('base64url'),
        LegacyViewer: crypto.randomBytes(24).toString('base64url'),
        MarkedViewer: crypto.randomBytes(24).toString('base64url')
    };
    const createdAt = '2025-01-01T00:00:00.000Z';
    // A database written before the onboarding marker existed, plus an SSO
    // account and a local account that do carry the marker.
    const database = {
        sources: [],
        hiddenItems: [],
        favorites: [],
        users: [
            { id: 1, username: 'LegacyAdmin', passwordHash: await bcrypt.hash(passwords.LegacyAdmin, 4), role: 'admin', oidcId: null, email: null, createdAt },
            { id: 2, username: 'LegacyViewer', passwordHash: await bcrypt.hash(passwords.LegacyViewer, 4), role: 'viewer', oidcId: null, email: null, createdAt },
            { id: 3, username: 'SsoViewer', passwordHash: null, role: 'viewer', oidcId: 'sso-subject-3', email: 'sso@example.test', createdAt, mfaOnboardingPending: true },
            { id: 4, username: 'MarkedViewer', passwordHash: await bcrypt.hash(passwords.MarkedViewer, 4), role: 'viewer', oidcId: null, email: null, createdAt, mfaOnboardingPending: true },
            // A marked account that already has a passkey, and no authenticator app.
            {
                id: 5, username: 'PasskeyOnly', passwordHash: await bcrypt.hash(crypto.randomBytes(24).toString('base64url'), 4),
                role: 'viewer', oidcId: null, email: null, createdAt, mfaOnboardingPending: true,
                passkeys: [{ credentialId: 'stored-passkey', name: 'Stored passkey', createdAt }]
            }
        ],
        nextId: 6
    };
    await fs.writeFile(path.join(dataDirectory, 'db.json'), JSON.stringify(database, null, 2));

    let server;
    try {
        for (const phase of ['upgrade', 'restart']) {
            server = await startServer(dataDirectory, secrets);
            const { baseUrl } = server;
            assert.equal(await sessionPending(baseUrl, await signIn(baseUrl, 'LegacyAdmin', passwords.LegacyAdmin)), false,
                `${phase}: existing administrators are not onboarded after an upgrade.`);
            assert.equal(await sessionPending(baseUrl, await signIn(baseUrl, 'LegacyViewer', passwords.LegacyViewer)), false,
                `${phase}: existing viewers are not onboarded after an upgrade.`);
            const ssoToken = jwt.sign({ id: 3, username: 'SsoViewer', role: 'viewer' }, secrets.jwt, { expiresIn: '1h' });
            assert.equal(await sessionPending(baseUrl, new CookieJar(), { Authorization: `Bearer ${ssoToken}` }), false,
                `${phase}: SSO accounts rely on their identity provider.`);
            assert.equal(await sessionPending(baseUrl, await signIn(baseUrl, 'MarkedViewer', passwords.MarkedViewer)), true,
                `${phase}: a marked local account is still offered the prompt.`);
            const passkeyToken = jwt.sign({ id: 5, username: 'PasskeyOnly', role: 'viewer' }, secrets.jwt, { expiresIn: '1h' });
            assert.equal(await sessionPending(baseUrl, new CookieJar(), { Authorization: `Bearer ${passkeyToken}` }), false,
                `${phase}: an account with only a passkey already has MFA.`);
            await stopServer(server.child);
            server = null;
        }

        const afterRestarts = await readDatabase(dataDirectory);
        assert.deepEqual(
            afterRestarts.users.map(user => [user.username, user.mfaOnboardingPending === true]),
            [['LegacyAdmin', false], ['LegacyViewer', false], ['SsoViewer', true], ['MarkedViewer', true], ['PasskeyOnly', true]],
            'Starting the server does not add or remove onboarding markers.'
        );

        // Without a TOTP encryption key or a passkey origin no method can be
        // added, so the prompt is not shown until it can lead somewhere.
        server = await startServer(dataDirectory, secrets, { secondFactorsAvailable: false });
        assert.equal(await sessionPending(server.baseUrl, await signIn(server.baseUrl, 'MarkedViewer', passwords.MarkedViewer)), false);
    } catch (error) {
        if (server) console.error(server.getOutput());
        throw error;
    } finally {
        if (server) await stopServer(server.child);
        await fs.rm(dataDirectory, { recursive: true, force: true });
    }
}

async function run() {
    const secrets = {
        jwt: crypto.randomBytes(48).toString('hex'),
        session: crypto.randomBytes(48).toString('hex'),
        totp: crypto.randomBytes(48).toString('hex')
    };
    await testNewAccounts(secrets);
    await testExistingInstallation(secrets);
    console.log('MFA onboarding test passed.');
}

run().catch(error => {
    console.error(error);
    process.exit(1);
});
