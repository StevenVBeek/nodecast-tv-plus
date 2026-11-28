'use strict';

const express = require('express');
const { rateLimit } = require('express-rate-limit');
const auth = require('../auth');
const authAudit = require('../services/authAudit');

function createRouter({ authService = auth, audit = authAudit } = {}) {
    const router = express.Router();
    const limitReads = rateLimit({
        limit: 120,
        windowMs: 60 * 1000,
        keyGenerator: req => String(req.user.id),
        standardHeaders: 'draft-7',
        legacyHeaders: false,
        message: { error: 'Too many log requests. Try again shortly.' }
    });

    // An export reads up to MAX_EXPORT_ENTRIES rows, so it has its own,
    // tighter limit on top of the shared read limit.
    const limitExports = rateLimit({
        limit: 10,
        windowMs: 60 * 1000,
        keyGenerator: req => String(req.user.id),
        standardHeaders: 'draft-7',
        legacyHeaders: false,
        message: { error: 'Too many exports. Try again shortly.' }
    });

    router.use(authService.requireAuth, authService.requireAdmin, limitReads);
    router.use((req, res, next) => {
        res.set('Cache-Control', 'no-store');
        next();
    });

    const text = value => (typeof value === 'string' ? value : undefined);
    const filtersFrom = query => ({
        from: text(query.from),
        to: text(query.to),
        account: text(query.account),
        ip: text(query.ip),
        outcome: text(query.outcome),
        event: text(query.event),
        method: text(query.method)
    });

    /**
     * Authentication audit entries, newest first.
     * GET /api/auth-log?from=&to=&account=&ip=&outcome=&event=&method=&page=&pageSize=
     */
    router.get('/', (req, res) => {
        try {
            res.json(audit.query({
                ...filtersFrom(req.query),
                page: text(req.query.page),
                pageSize: text(req.query.pageSize)
            }));
        } catch (error) {
            console.error('[AuthAudit] Could not read authentication events:', error.message);
            res.status(500).json({ error: 'The sign-in log could not be loaded.' });
        }
    });

    /**
     * Download the entries matching the same filters as a JSON file.
     * GET /api/auth-log/export?from=&to=&account=&ip=&outcome=&event=&method=
     */
    router.get('/export', limitExports, (req, res) => {
        try {
            const result = audit.exportEntries(filtersFrom(req.query));
            const stamp = result.exportedAt.replace(/\.\d+Z$/, 'Z').replace(/:/g, '-');
            res.set({
                'Content-Disposition': `attachment; filename="nodecast-sign-in-activity-${stamp}.json"`,
                'X-Content-Type-Options': 'nosniff'
            });
            // The browser saves this text unchanged, so the file matches the response byte for byte.
            res.type('json').send(`${JSON.stringify(result, null, 2)}\n`);
        } catch (error) {
            console.error('[AuthAudit] Could not export authentication events:', error.message);
            res.status(500).json({ error: 'The sign-in log could not be exported.' });
        }
    });

    return router;
}

module.exports = createRouter();
module.exports.createRouter = createRouter;
