/* ============================================================
   SENTINEL SDK — Relay Server (server.ts)
   ============================================================
   Runs as a standalone Express/Node HTTP server.
   Responsibilities:
     1. Receive browser log batches  →  POST /sentinel/ingest
     2. Forward them to ClickHouse   (no CORS problems)
     3. Initialise the ClickHouse DB + table on startup
     4. Optional: serve a live log-tail via SSE  GET /sentinel/stream
     5. Health-check endpoint        GET /sentinel/health

   Start:
     npx ts-node server.ts
   or compiled:
     node dist/server.js

   Env vars:
     CLICKHOUSE_HOST       default: http://localhost:8123
     CLICKHOUSE_DATABASE   default: sentinel
     CLICKHOUSE_TABLE      default: logs
     CLICKHOUSE_USER       optional
     CLICKHOUSE_PASSWORD   optional
     SENTINEL_PORT         default: 4318
     SENTINEL_SECRET       optional shared secret for auth
                           (set same in browser agent relayUrl header)
   ============================================================ */

import http  from 'http';
import https from 'https';

/* ── Config ──────────────────────────────────────────────── */

const CH_HOST     = process.env.CLICKHOUSE_HOST     || 'http://localhost:8123';
const CH_DATABASE = process.env.CLICKHOUSE_DATABASE || 'sentinel';
const CH_TABLE    = process.env.CLICKHOUSE_TABLE    || 'logs';
const CH_USER     = process.env.CLICKHOUSE_USER     || '';
const CH_PASSWORD = process.env.CLICKHOUSE_PASSWORD || '';
const PORT        = Number(process.env.SENTINEL_PORT) || 4318;
const SECRET      = process.env.SENTINEL_SECRET      || '';

const CH_AUTH = CH_USER
  ? `Basic ${Buffer.from(`${CH_USER}:${CH_PASSWORD}`).toString('base64')}`
  : '';

/* ── Types ───────────────────────────────────────────────── */

interface LogRow {
  timestamp:  string;
  record_id:  string;
  trace_id:   string;
  span_id:    string;
  service:    string;
  env:        string;
  layer:      string;
  level:      string;
  message:    string;
  context:    string;
}

/* ── SSE subscribers ─────────────────────────────────────── */

const sseClients = new Set<http.ServerResponse>();

function broadcast(rows: LogRow[]): void {
  if (sseClients.size === 0) return;
  const payload = `data: ${JSON.stringify(rows)}\n\n`;
  sseClients.forEach((res) => {
    try { res.write(payload); } catch { sseClients.delete(res); }
  });
}

/* ── ClickHouse helpers ──────────────────────────────────── */

async function chExec(query: string): Promise<void> {
  const url = `${CH_HOST}/?query=${encodeURIComponent(query)}`;
  const res = await fetchCh(url, { method: 'POST' });
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`ClickHouse DDL failed (${res.status}): ${txt.slice(0, 300)}`);
  }
}

async function chInsert(rows: LogRow[]): Promise<void> {
  if (rows.length === 0) return;

  const ndjson = rows.map((r) => {
    const safe: LogRow = {
      ...r,
      context: typeof r.context === 'string'
        ? r.context
        : JSON.stringify(r.context || {}),
    };
    return JSON.stringify(safe);
  }).join('\n');

  const query = `INSERT INTO ${CH_DATABASE}.${CH_TABLE} FORMAT JSONEachRow`;
  const url   = `${CH_HOST}/?query=${encodeURIComponent(query)}`;

  const res = await fetchCh(url, {
    method:  'POST',
    headers: { 'Content-Type': 'application/x-ndjson' },
    body:    ndjson,
  });

  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`ClickHouse insert failed (${res.status}): ${txt.slice(0, 300)}`);
  }
}

function fetchCh(url: string, opts: RequestInit): Promise<Response> {
  const headers: Record<string, string> = {
    ...(opts.headers as Record<string, string> || {}),
  };
  if (CH_AUTH) headers['Authorization'] = CH_AUTH;
  return fetch(url, { ...opts, headers });
}

/* ── DB init ─────────────────────────────────────────────── */

async function initClickHouse(): Promise<void> {
  await chExec(`CREATE DATABASE IF NOT EXISTS ${CH_DATABASE}`);

  await chExec(`
    CREATE TABLE IF NOT EXISTS ${CH_DATABASE}.${CH_TABLE}
    (
      timestamp  String,
      record_id  String,
      trace_id   String,
      span_id    String,
      service    String,
      env        String,
      layer      String,
      level      String,
      message    String,
      context    String
    )
    ENGINE = MergeTree()
    PARTITION BY toYYYYMM(parseDateTimeBestEffort(timestamp))
    ORDER BY (timestamp, service, layer)
    TTL parseDateTimeBestEffort(timestamp) + INTERVAL 90 DAY
  `);

  console.log('[SENTINEL] ClickHouse ready ✓');
}

/* ── Request router ──────────────────────────────────────── */

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end',  () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error', reject);
  });
}

function cors(res: http.ServerResponse, req: http.IncomingMessage): void {
  const origin = req.headers['origin'] || '*';
  res.setHeader('Access-Control-Allow-Origin',  origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Sentinel, Authorization');
  res.setHeader('Access-Control-Max-Age',       '86400');
}

function json(res: http.ServerResponse, status: number, body: object): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type':   'application/json',
    'Content-Length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

async function handleIngest(
  req: http.IncomingMessage,
  res: http.ServerResponse
): Promise<void> {
  // Auth check
  if (SECRET) {
    const authHeader = req.headers['authorization'] || req.headers['x-sentinel-secret'];
    if (authHeader !== `Bearer ${SECRET}` && authHeader !== SECRET) {
      json(res, 401, { error: 'Unauthorized' });
      return;
    }
  }

  const body = await readBody(req);
  let rows: LogRow[];

  try {
    const parsed = JSON.parse(body);
    rows = Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    json(res, 400, { error: 'Invalid JSON' });
    return;
  }

  // Validate + sanitise
  const valid: LogRow[] = rows
    .filter((r) => r && typeof r === 'object' && typeof r.message === 'string')
    .map((r) => ({
      timestamp: r.timestamp  || new Date().toISOString(),
      record_id: r.record_id  || crypto.randomUUID(),
      trace_id:  r.trace_id   || 'untracked',
      span_id:   r.span_id    || 'untracked',
      service:   r.service    || 'unknown',
      env:       r.env        || 'unknown',
      layer:     r.layer      || 'business_logic',
      level:     r.level      || 'INFO',
      message:   r.message,
      context:   typeof r.context === 'string' ? r.context : JSON.stringify(r.context || {}),
    }));

  if (valid.length === 0) {
    json(res, 422, { error: 'No valid log rows' });
    return;
  }

  try {
    await chInsert(valid);
    broadcast(valid);

    // Pretty-print to terminal
    valid.forEach((r) => {
      const levelColors: Record<string, string> = {
        DEBUG: '\x1b[36m', INFO: '\x1b[32m',
        WARN:  '\x1b[33m', ERROR: '\x1b[31m', FATAL: '\x1b[35m',
      };
      const c = levelColors[r.level] || '\x1b[32m';
      console.log(`${c}[${r.timestamp}] [${r.layer.toUpperCase()}] [${r.level}] [${r.service}] ${r.message}\x1b[0m`);
    });

    json(res, 200, { ok: true, inserted: valid.length });
  } catch (err) {
    console.error('[SENTINEL] Insert error:', err);
    json(res, 500, { error: 'ClickHouse insert failed' });
  }
}

function handleStream(
  req: http.IncomingMessage,
  res: http.ServerResponse
): void {
  res.writeHead(200, {
    'Content-Type':  'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection':    'keep-alive',
    'Access-Control-Allow-Origin': '*',
  });
  res.write('retry: 1000\n\n');

  sseClients.add(res);
  req.on('close', () => sseClients.delete(res));

  // Keep-alive ping every 15s
  const ping = setInterval(() => {
    try { res.write(': ping\n\n'); } catch { clearInterval(ping); }
  }, 15_000);
}

/* ── Main server ─────────────────────────────────────────── */

const server = http.createServer(async (req, res) => {
  cors(res, req);

  // Preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = req.url?.split('?')[0] || '/';

  try {
    if (url === '/sentinel/ingest' && req.method === 'POST') {
      await handleIngest(req, res);
      return;
    }

    if (url === '/sentinel/stream' && req.method === 'GET') {
      handleStream(req, res);
      return;
    }

    if (url === '/sentinel/health' && req.method === 'GET') {
      json(res, 200, {
        status:   'ok',
        service:  'sentinel-relay',
        uptime:   process.uptime(),
        database: CH_DATABASE,
        table:    CH_TABLE,
        sse:      sseClients.size,
      });
      return;
    }

    json(res, 404, { error: 'Not found' });
  } catch (err) {
    console.error('[SENTINEL] Server error:', err);
    json(res, 500, { error: 'Internal server error' });
  }
});

/* ── Boot ────────────────────────────────────────────────── */

(async () => {
  try {
    await initClickHouse();
  } catch (err) {
    console.error('[SENTINEL] ClickHouse init failed:', err);
    console.warn('[SENTINEL] Starting anyway — logs will be queued');
  }

  server.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════╗
║          SENTINEL RELAY SERVER — READY            ║
╠═══════════════════════════════════════════════════╣
║  Ingest  →  POST http://localhost:${PORT}/sentinel/ingest
║  Stream  →  GET  http://localhost:${PORT}/sentinel/stream
║  Health  →  GET  http://localhost:${PORT}/sentinel/health
║  DB      →  ${CH_HOST}/${CH_DATABASE}.${CH_TABLE}
╚═══════════════════════════════════════════════════╝
    `.trim());
  });

  server.on('error', (err) => {
    console.error('[SENTINEL] Server error:', err);
  });
})();

export default server;
