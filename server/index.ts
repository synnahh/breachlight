import path from 'node:path';
import fs from 'node:fs';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { config, hibpConfigured } from './config.js';
import { logger } from './logger.js';
import { api } from './routes.js';
import { baselineReady } from './providers/index.js';

const app = express();

// ── Security middleware ──────────────────────────────────────────────────
app.disable('x-powered-by');
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'self'"],
        'style-src': ["'self'", "'unsafe-inline'"], // Vite injects styles
        'connect-src': ["'self'"],
        'img-src': ["'self'", 'data:'],
        'object-src': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
      },
    },
    crossOriginResourcePolicy: { policy: 'same-site' },
    referrerPolicy: { policy: 'no-referrer' },
  }),
);

// Local-only tool: allow the Vite dev origin, nothing else.
const allowedOrigins = new Set([
  `http://localhost:${config.webPort}`,
  `http://127.0.0.1:${config.webPort}`,
]);
app.use(
  cors({
    origin(origin, cb) {
      if (!origin || allowedOrigins.has(origin)) return cb(null, true);
      cb(new Error('Origin not allowed'));
    },
  }),
);

app.use(express.json({ limit: '32kb' }));

app.use(
  '/api',
  rateLimit({
    windowMs: 60_000,
    limit: 120,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { ok: false, error: 'Too many requests — slow down.' },
  }),
);

// ── Request logging (no bodies, no query strings with sensitive data) ────
app.use((req, _res, next) => {
  logger.info('request', { method: req.method, path: req.path });
  next();
});

app.use('/api', api);

// ── Serve built frontend in production ───────────────────────────────────
const webDist = path.resolve(process.cwd(), 'dist/web');
if (fs.existsSync(webDist)) {
  app.use(express.static(webDist));
  app.get('*', (_req, res) => res.sendFile(path.join(webDist, 'index.html')));
}

// ── Error handler ───────────────────────────────────────────────────────
app.use(
  (
    e: Error,
    _req: express.Request,
    res: express.Response,
    _next: express.NextFunction,
  ) => {
    logger.error('unhandled error', { message: e.message });
    res.status(500).json({ ok: false, error: 'Internal error.' });
  },
);

app.listen(config.port, () => {
  logger.info('Breachlight API listening', {
    port: config.port,
    baselineReady: baselineReady(),
    hibpConfigured: hibpConfigured(),
    demoProvider: config.demoProviderEnabled,
  });
});
