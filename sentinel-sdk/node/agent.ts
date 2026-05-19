/* ============================================================
   SENTINEL SDK — Node Agent  v3.3
   Zero-config observability for Node.js backends.

   What's in here:
     • ClickHouseWriter  — batched writes, disk-buffer fallback
     • ActiveSessionTracker — sliding-window concurrent user count
     • DiskBuffer        — survive ClickHouse outages
     • OtlpExporter      — optional OpenTelemetry export
     • SentinelNode      — main class, auto-instruments everything
     • Browser ingest    — POST /sentinel/ingest built-in, browser
                           logs land in the same ClickHouse table
     • Health server     — /health  /ready  /_sessions  /sentinel/ingest
     • initSentinel()    — async factory, call once at startup

   Zero-config usage (no code changes in your app):
     NODE_OPTIONS="--require sentinel-sdk/register" node dist/index.js

   Manual usage:
     import { initSentinel } from 'sentinel-sdk/node-agent';
     const sentinel = await initSentinel();
     app.use(sentinel.middleware());

   All config via environment variables — see SentinelNodeConfig below.
   ============================================================ */

import http  from 'http';
import https from 'https';
import fs    from 'fs';
import path  from 'path';
import os    from 'os';
import tls   from 'tls';
import crypto from 'crypto';

/* ── Tiny local helpers (no core/types dependency assumed) ───────────────── */

function _gen8Hex():  string { return crypto.randomBytes(8).toString('hex'); }
function _gen16Hex(): string { return crypto.randomBytes(16).toString('hex'); }
function _genUUID():  string {
  try { return crypto.randomUUID(); } catch {
    const b = crypto.randomBytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    return [...b].map((x, i) =>
      ([4,6,8,10].includes(i) ? '-' : '') + x.toString(16).padStart(2, '0')
    ).join('');
  }
}

/* ── Log layers & levels ─────────────────────────────────────────────────── */

export const LogLayer = {
  PRESENTATION:   'presentation',
  API_GATEWAY:    'api_gateway',
  BUSINESS_LOGIC: 'business_logic',
  DATA_ACCESS:    'data_access',
  SERVICE:        'service',
  SECURITY:       'security',
  OBSERVABILITY:  'observability',
  INFRASTRUCTURE: 'infrastructure',
  DOMAIN:         'domain',
} as const;
export type LogLayer = typeof LogLayer[keyof typeof LogLayer];

export const LogLevel = {
  DEBUG: 'DEBUG',
  INFO:  'INFO',
  WARN:  'WARN',
  ERROR: 'ERROR',
  FATAL: 'FATAL',
} as const;
export type LogLevel = typeof LogLevel[keyof typeof LogLevel];

const _LEVEL_ORDER: Record<LogLevel, number> = {
  DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3, FATAL: 4,
};

/* ── PII masking ─────────────────────────────────────────────────────────── */

const _PII_PATTERNS: Array<[RegExp, string]> = [
  [/\b(?:\d[ -]?){13,16}\b/g,                                                         '[CARD]'],
  [/\b[A-Za-z0-9+/]{20,}\.[A-Za-z0-9+/]{20,}\.[A-Za-z0-9+/_-]{20,}\b/g,             '[JWT]'],
  [/Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,                                                'Bearer [TOKEN]'],
  [/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,                         '[EMAIL]'],
  [/(password|passwd|pwd|secret|token|api_?key|auth)["\'\s:=]+[^\s"\'`,;}{)\]]+/gi,   '$1=[REDACTED]'],
  [/\b\d{3}-\d{2}-\d{4}\b/g,                                                          '[SSN]'],
];
const _REDACT_KEYS = /password|passwd|pwd|secret|token|api_?key|auth|credential|private|authorization/i;

export function maskPII(v: string): string {
  if (typeof v !== 'string') return v;
  for (const [re, rep] of _PII_PATTERNS) v = v.replace(re, rep);
  return v;
}

export function maskContext(obj: any, depth = 0): any {
  if (depth > 5 || obj == null) return obj;
  if (typeof obj === 'string') return maskPII(obj);
  if (Array.isArray(obj)) return obj.map((v) => maskContext(v, depth + 1));
  if (typeof obj !== 'object') return obj;
  const out: Record<string, any> = {};
  for (const [k, v] of Object.entries(obj)) {
    out[k] = _REDACT_KEYS.test(k) ? '[REDACTED]' : maskContext(v, depth + 1);
  }
  return out;
}

/* ── Layer inference ─────────────────────────────────────────────────────── */

const _LAYER_PATTERNS: Array<[RegExp, LogLayer]> = [
  [/auth|jwt|token|oauth|permission|acl|rbac|guard|encrypt|decrypt|password|credential|session|csrf|cors/i, LogLayer.SECURITY],
  [/repo|repository|dao|database|db|query|migration|schema|cache|redis|mongo|postgres|sql|neo4j|orm|store|persist/i, LogLayer.DATA_ACCESS],
  [/controller|router|route|middleware|gateway|proxy|handler|endpoint|api|rest|graphql|grpc|webhook|interceptor/i, LogLayer.API_GATEWAY],
  [/service|saga|aggregate|domain|policy|rule|event|command|workflow|process|pricing|discount|fraud|risk/i, LogLayer.DOMAIN],
  [/infra|worker|job|cron|queue|kafka|rabbit|bull|pubsub|container|health|monitor|metric|cpu|memory|disk|celery/i, LogLayer.INFRASTRUCTURE],
  [/trace|span|log|alert|metric|telemetry|observer|slo|sla|alarm/i, LogLayer.OBSERVABILITY],
  [/component|page|ui|render|form|modal|widget|screen|layout|theme|template/i, LogLayer.PRESENTATION],
];

function inferLayer(name: string): LogLayer {
  for (const [re, layer] of _LAYER_PATTERNS) if (re.test(name)) return layer;
  return LogLayer.BUSINESS_LOGIC;
}

/* ── W3C traceparent ─────────────────────────────────────────────────────── */

export function buildTraceparent(traceId: string, spanId: string, sampled = true): string {
  const tid = (traceId || '').padEnd(32, '0').slice(0, 32);
  const sid = (spanId  || '').padEnd(16, '0').slice(0, 16);
  return `00-${tid}-${sid}-${sampled ? '01' : '00'}`;
}

export function parseTraceparent(header: string): { traceId: string; spanId: string; sampled: boolean } | null {
  if (!header) return null;
  const p = header.split('-');
  if (p.length !== 4 || p[0] !== '00') return null;
  if (!/^[0-9a-f]{32}$/.test(p[1]) || !/^[0-9a-f]{16}$/.test(p[2])) return null;
  return { traceId: p[1], spanId: p[2], sampled: p[3] === '01' };
}

/* ── LogRecord ───────────────────────────────────────────────────────────── */

export class LogRecord {
  timestamp:  string;
  record_id:  string;
  trace_id:   string;
  span_id:    string;
  service:    string;
  env:        string;
  host:       string;
  version:    string;
  request_id: string;
  session_id: string;
  user_id:    string;
  tenant_id:  string;
  layer:      string;
  level:      string;
  message:    string;
  context:    Record<string, any>;
  isAudit:    boolean;

  constructor(p: {
    message:     string;
    layer?:      string;
    level?:      string;
    service?:    string;
    trace_id?:   string;
    span_id?:    string;
    request_id?: string;
    session_id?: string;
    user_id?:    string;
    tenant_id?:  string;
    context?:    Record<string, any>;
    isAudit?:    boolean;
  }) {
    this.timestamp  = new Date().toISOString();
    this.record_id  = _genUUID();
    this.trace_id   = p.trace_id   || 'untracked';
    this.span_id    = p.span_id    || _gen8Hex();
    this.service    = p.service    || 'node-service';
    this.env        = process.env.ENV || process.env.NODE_ENV || 'development';
    this.host       = os.hostname();
    this.version    = process.env.SERVICE_VERSION || process.env.APP_VERSION || process.env.npm_package_version || '0.0.0';
    this.request_id = p.request_id || '';
    this.session_id = p.session_id || '';
    this.user_id    = p.user_id    || '';
    this.tenant_id  = p.tenant_id  || '';
    this.layer      = p.layer      || LogLayer.BUSINESS_LOGIC;
    this.level      = p.level      || LogLevel.INFO;
    this.message    = p.message;
    this.context    = p.context    || {};
    this.isAudit    = p.isAudit    || false;
  }

  to_dict(): Record<string, any> {
    return {
      timestamp:  this.timestamp,
      record_id:  this.record_id,
      trace_id:   this.trace_id,
      span_id:    this.span_id,
      service:    this.service,
      env:        this.env,
      host:       this.host,
      version:    this.version,
      request_id: this.request_id,
      session_id: this.session_id,
      user_id:    this.user_id,
      tenant_id:  this.tenant_id,
      layer:      this.layer,
      level:      this.level,
      message:    this.message,
      context:    JSON.stringify(this.context || {}),
    };
  }

  toString(): string {
    const colors: Record<string, string> = {
      DEBUG: '\x1b[36m', INFO: '\x1b[32m', WARN: '\x1b[33m', ERROR: '\x1b[31m', FATAL: '\x1b[35m',
    };
    const c = colors[this.level] || '\x1b[32m';
    return `${c}[${this.timestamp}] [${this.layer.toUpperCase()}] [${this.level}] ${this.message}\x1b[0m`;
  }
}

/* ── Config ──────────────────────────────────────────────────────────────── */

export interface SentinelNodeConfig {
  serviceName?:         string;
  clickhouseHost?:      string;
  clickhouseDatabase?:  string;
  clickhouseTable?:     string;
  clickhouseUser?:      string;
  clickhousePassword?:  string;
  batchSize?:           number;
  flushInterval?:       number;
  slowQueryMs?:         number;
  slowHttpMs?:          number;
  debug?:               boolean;
  autoInstrument?:      boolean;
  samplingRate?:        number;
  certCheckHosts?:      string[];
  certCheckIntervalMs?: number;
  otlpEndpoint?:        string;
  healthPort?:          number;
  logLevel?:            LogLevel;
  diskBufferDir?:       string;
  diskBufferMaxMb?:     number;
  auditLogPath?:        string;
  enabled?:             boolean;
  sessionTtlMs?:        number;
  adminToken?:          string;
  /** Mount POST /sentinel/ingest on the health server to receive browser logs */
  browserIngest?:       boolean;
  /** Allowed origins for the browser ingest endpoint. Empty = allow all. */
  allowedOrigins?:      string[];
}

/* ── Active session tracker ──────────────────────────────────────────────── */

export interface SessionEntry {
  sessionId:  string;
  userId?:    string;
  ip?:        string;
  userAgent?: string;
  firstSeen:  number;
  lastSeen:   number;
  reqCount:   number;
}

export interface ActiveSessionSummary {
  totalActiveSessions: number;
  totalUniqueUsers:    number;
  totalAnonymous:      number;
  sessions:            SessionEntry[];
}

class ActiveSessionTracker {
  private sessions = new Map<string, SessionEntry>();
  private ttlMs:    number;

  constructor(ttlMs: number) {
    this.ttlMs = ttlMs;
    setInterval(() => this._evict(), 60_000).unref();
  }

  touch(p: { sessionId: string; userId?: string; ip?: string; userAgent?: string }): void {
    const now      = Date.now();
    const existing = this.sessions.get(p.sessionId);
    if (existing) {
      existing.lastSeen = now;
      existing.reqCount++;
      if (p.userId && !existing.userId) existing.userId = p.userId;
    } else {
      this.sessions.set(p.sessionId, {
        sessionId: p.sessionId, userId: p.userId,
        ip: p.ip, userAgent: p.userAgent,
        firstSeen: now, lastSeen: now, reqCount: 1,
      });
    }
  }

  summary(): ActiveSessionSummary {
    this._evict();
    const all   = Array.from(this.sessions.values());
    const users = new Set(all.map((s) => s.userId).filter(Boolean));
    return {
      totalActiveSessions: all.length,
      totalUniqueUsers:    users.size,
      totalAnonymous:      all.filter((s) => !s.userId).length,
      sessions:            all,
    };
  }

  count(): number { this._evict(); return this.sessions.size; }

  private _evict(): void {
    const cutoff = Date.now() - this.ttlMs;
    for (const [k, e] of this.sessions) if (e.lastSeen < cutoff) this.sessions.delete(k);
  }
}

/* ── Disk buffer ─────────────────────────────────────────────────────────── */

class DiskBuffer {
  private file:     string;
  private maxBytes: number;

  constructor(dir: string, maxMb: number) {
    this.maxBytes = maxMb * 1024 * 1024;
    this.file     = path.join(dir, 'sentinel-buffer.ndjson');
    try { fs.mkdirSync(dir, { recursive: true }); } catch { /* exists */ }
  }

  write(records: LogRecord[]): void {
    try {
      const rows  = records.map((r) => JSON.stringify(r.to_dict())).join('\n') + '\n';
      const bytes = Buffer.byteLength(rows, 'utf-8');
      if (this._size() + bytes > this.maxBytes) this._rotate();
      fs.appendFileSync(this.file, rows, 'utf-8');
    } catch { /* never crash */ }
  }

  drain(): string[] {
    try {
      if (!fs.existsSync(this.file)) return [];
      const lines = fs.readFileSync(this.file, 'utf-8').split('\n').filter(Boolean);
      fs.unlinkSync(this.file);
      return lines;
    } catch { return []; }
  }

  private _size(): number {
    try { return fs.statSync(this.file).size; } catch { return 0; }
  }

  private _rotate(): void {
    try {
      const lines = fs.readFileSync(this.file, 'utf-8').split('\n').filter(Boolean);
      fs.writeFileSync(this.file, lines.slice(Math.floor(lines.length / 2)).join('\n') + '\n', 'utf-8');
    } catch { /* ignore */ }
  }
}

/* ── ClickHouse writer ───────────────────────────────────────────────────── */

class ClickHouseWriter {
  private host:       string;
  private database:   string;
  private table:      string;
  private authHeader: string | undefined;
  private queue:      LogRecord[] = [];
  private batchSize:  number;
  private debug:      boolean;
  private ready       = false;
  private diskBuf:    DiskBuffer;
  private auditPath:  string;

  constructor(cfg: Required<SentinelNodeConfig>) {
    this.host      = cfg.clickhouseHost;
    this.database  = cfg.clickhouseDatabase;
    this.table     = cfg.clickhouseTable;
    this.batchSize = cfg.batchSize;
    this.debug     = cfg.debug;
    this.auditPath = cfg.auditLogPath;
    this.diskBuf   = new DiskBuffer(cfg.diskBufferDir, cfg.diskBufferMaxMb);
    if (cfg.clickhouseUser) {
      this.authHeader = `Basic ${Buffer.from(`${cfg.clickhouseUser}:${cfg.clickhousePassword}`).toString('base64')}`;
    }
  }

  async init(): Promise<void> {
    // Create DB
    await this._exec(`CREATE DATABASE IF NOT EXISTS ${this.database}`);

    // Create table — includes session_id + user_id columns for per-user tracking
    await this._exec(`
      CREATE TABLE IF NOT EXISTS ${this.database}.${this.table}
      (
        timestamp  String,
        record_id  String,
        trace_id   String,
        span_id    String,
        service    String,
        env        String,
        host       String,
        version    String,
        request_id String,
        session_id String,
        user_id    String,
        tenant_id  String,
        layer      String,
        level      String,
        message    String,
        context    String
      )
      ENGINE = MergeTree()
      PARTITION BY toYYYYMM(parseDateTimeBestEffort(timestamp))
      ORDER BY (timestamp, service, layer, session_id)
      TTL parseDateTimeBestEffort(timestamp) + INTERVAL 90 DAY
    `);

    this.ready = true;
    this._startFlushLoop();
    void this._drainDiskBuffer();
  }

  enqueue(record: LogRecord): void {
    if (record.isAudit) this._appendAudit(record);
    this.queue.push(record);
    if (this.queue.length >= this.batchSize) void this._flush();
  }

  flush(): void {
    // Sync fallback for process exit
    if (this.queue.length === 0) return;
    this.diskBuf.write(this.queue.splice(0));
  }

  private _startFlushLoop(): void {
    setInterval(() => void this._flush(), 2000).unref();
    const onExit = () => this.flush();
    process.once('exit',    onExit);
    process.once('SIGINT',  () => { onExit(); process.exit(0); });
    process.once('SIGTERM', () => { onExit(); process.exit(0); });
  }

  private async _flush(): Promise<void> {
    if (!this.ready || this.queue.length === 0) return;
    const batch = this.queue.splice(0);
    const rows  = batch.map((r) => JSON.stringify(r.to_dict())).join('\n');
    const query = `INSERT INTO ${this.database}.${this.table} FORMAT JSONEachRow`;
    try {
      const res = await fetch(
        `${this.host}/?query=${encodeURIComponent(query)}`,
        {
          method:  'POST',
          headers: {
            'Content-Type': 'application/x-ndjson',
            ...(this.authHeader ? { Authorization: this.authHeader } : {}),
          },
          body: rows,
        },
      );
      if (!res.ok) {
        if (this.debug) console.error('[SENTINEL] ClickHouse error:', res.status, (await res.text()).slice(0, 200));
        this.diskBuf.write(batch);
      }
    } catch (err) {
      if (this.debug) console.error('[SENTINEL] flush error:', err);
      this.diskBuf.write(batch);
    }
  }

  private async _drainDiskBuffer(): Promise<void> {
    const lines = this.diskBuf.drain();
    if (lines.length === 0) return;
    const query = `INSERT INTO ${this.database}.${this.table} FORMAT JSONEachRow`;
    try {
      await fetch(
        `${this.host}/?query=${encodeURIComponent(query)}`,
        {
          method:  'POST',
          headers: {
            'Content-Type': 'application/x-ndjson',
            ...(this.authHeader ? { Authorization: this.authHeader } : {}),
          },
          body: lines.join('\n'),
        },
      );
    } catch {
      // Reconstruct and re-buffer; will retry on next startup
      const records = lines
        .map((l) => { try { return JSON.parse(l); } catch { return null; } })
        .filter(Boolean);
      if (records.length > 0) {
        // Write raw lines back rather than re-parsing into LogRecord objects
        try { fs.appendFileSync(this.diskBuf['file'], lines.join('\n') + '\n', 'utf-8'); } catch { /* ignore */ }
      }
    }
  }

  private _appendAudit(record: LogRecord): void {
    try {
      fs.mkdirSync(path.dirname(this.auditPath), { recursive: true });
      fs.appendFileSync(this.auditPath, JSON.stringify(record.to_dict()) + '\n', 'utf-8');
    } catch { /* never crash */ }
  }

  private async _exec(query: string): Promise<void> {
    const res = await fetch(
      `${this.host}/?query=${encodeURIComponent(query)}`,
      {
        method:  'POST',
        headers: this.authHeader ? { Authorization: this.authHeader } : {},
      },
    );
    if (!res.ok) {
      throw new Error(`ClickHouse DDL failed (${res.status}): ${(await res.text()).slice(0, 300)}`);
    }
  }
}

/* ── OTLP exporter ───────────────────────────────────────────────────────── */

const _SEVERITY: Record<LogLevel, number> = {
  DEBUG: 5, INFO: 9, WARN: 13, ERROR: 17, FATAL: 21,
};

class OtlpExporter {
  private endpoint: string;
  private queue:    LogRecord[] = [];
  private debug:    boolean;

  constructor(endpoint: string, debug = false) {
    this.endpoint = endpoint.replace(/\/$/, '') + '/v1/logs';
    this.debug    = debug;
    setInterval(() => void this._flush(), 2000).unref();
  }

  enqueue(r: LogRecord): void {
    this.queue.push(r);
    if (this.queue.length >= 50) void this._flush();
  }

  private async _flush(): Promise<void> {
    if (this.queue.length === 0) return;
    const batch = this.queue.splice(0);
    const first = batch[0];
    const body  = {
      resourceLogs: [{
        resource: { attributes: _kvList({ 'service.name': first.service, 'host.name': first.host }) },
        scopeLogs: [{
          scope: { name: 'sentinel-sdk' },
          logRecords: batch.map((r) => ({
            timeUnixNano:   String(new Date(r.timestamp).getTime() * 1_000_000),
            severityNumber: _SEVERITY[r.level as LogLevel] ?? 9,
            severityText:   r.level,
            traceId:        r.trace_id,
            spanId:         r.span_id,
            body:           { stringValue: r.message },
            attributes:     _kvList({ layer: r.layer, env: r.env, session_id: r.session_id, user_id: r.user_id }),
          })),
        }],
      }],
    };
    try {
      await fetch(this.endpoint, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(body),
      });
    } catch (err) {
      if (this.debug) console.error('[SENTINEL] OTLP flush error:', err);
    }
  }
}

function _kvList(obj: Record<string, any>) {
  return Object.entries(obj).filter(([, v]) => v != null).map(([key, value]) => ({
    key,
    value: typeof value === 'number'  ? { doubleValue: value }
         : typeof value === 'boolean' ? { boolValue:   value }
         : { stringValue: String(value) },
  }));
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */

function _parseEnvLogLevel(): LogLevel {
  const v = (process.env.LOG_LEVEL || '').toUpperCase() as LogLevel;
  return Object.values(LogLevel).includes(v) ? v : LogLevel.DEBUG;
}

function _extractCookieSessionId(cookieHeader: string): string | undefined {
  const NAMES = ['sessionId','session_id','connect.sid','sid','PHPSESSID','ASP.NET_SessionId','JSESSIONID'];
  for (const pair of cookieHeader.split(';')) {
    const [rawKey, ...rest] = pair.split('=');
    const key = rawKey.trim();
    const val = rest.join('=').trim();
    if (NAMES.includes(key) && val) return val;
  }
  return undefined;
}

async function _measureEventLoopLag(): Promise<number> {
  return new Promise((resolve) => {
    const start = Date.now();
    setImmediate(() => resolve(Date.now() - start));
  });
}

async function _fdCount(): Promise<number | undefined> {
  try {
    const { readdir } = await import('fs/promises');
    return (await readdir(`/proc/${process.pid}/fd`)).length;
  } catch {
    try {
      const { execFile }   = await import('child_process');
      const { promisify }  = await import('util');
      const exec           = promisify(execFile);
      const { stdout }     = await exec('lsof', ['-p', String(process.pid), '-F', 'f']);
      return stdout.split('\n').filter((l) => l.startsWith('f') && l !== 'f').length;
    } catch { return undefined; }
  }
}

/* ── CORS helper (for browser ingest) ───────────────────────────────────── */

function _corsHeaders(origin: string | undefined, allowed: string[]): Record<string, string> {
  const allow = allowed.length === 0
    ? (origin || '*')
    : allowed.includes(origin || '') ? origin! : '';
  if (!allow) return {};
  return {
    'Access-Control-Allow-Origin':  allow,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Sentinel',
    'Access-Control-Max-Age':       '86400',
  };
}

/* ── Main class ──────────────────────────────────────────────────────────── */

export class SentinelNode {
  private cfg:           Required<SentinelNodeConfig>;
  private writer:        ClickHouseWriter;
  private otlp?:         OtlpExporter;
  private instrumented   = new WeakSet<object>();
  private traceId        = _gen16Hex();
  private processStart   = Date.now();
  private netBytesIn     = 0;
  private netBytesOut    = 0;
  private _enabled:      boolean;
  private _minLevel:     LogLevel;
  private _healthReady   = false;
  private _sessions:     ActiveSessionTracker;
  private _gcCount       = 0;
  private _gcDurationMs  = 0;

  constructor(config: SentinelNodeConfig = {}) {
    const diskBufferDir = config.diskBufferDir || path.join(os.tmpdir(), 'sentinel');

    this.cfg = {
      serviceName:         config.serviceName         || process.env.SENTINEL_SERVICE_NAME    || 'node-service',
      clickhouseHost:      config.clickhouseHost       || process.env.CLICKHOUSE_HOST           || 'http://localhost:8123',
      clickhouseDatabase:  config.clickhouseDatabase   || process.env.CLICKHOUSE_DATABASE       || 'sentinel',
      clickhouseTable:     config.clickhouseTable      || process.env.CLICKHOUSE_TABLE          || 'logs',
      clickhouseUser:      config.clickhouseUser       || process.env.CLICKHOUSE_USER           || '',
      clickhousePassword:  config.clickhousePassword   || process.env.CLICKHOUSE_PASSWORD       || '',
      batchSize:           config.batchSize            ?? Number(process.env.SENTINEL_BATCH_SIZE     || 50),
      flushInterval:       config.flushInterval        ?? Number(process.env.SENTINEL_FLUSH_INTERVAL_MS || 2000),
      slowQueryMs:         config.slowQueryMs          ?? Number(process.env.SENTINEL_SLOW_QUERY_MS || 200),
      slowHttpMs:          config.slowHttpMs           ?? Number(process.env.SENTINEL_SLOW_HTTP_MS  || 1000),
      debug:               config.debug               ?? process.env.SENTINEL_DEBUG === 'true',
      autoInstrument:      config.autoInstrument       ?? true,
      samplingRate:        config.samplingRate         ?? Number(process.env.SENTINEL_SAMPLING_RATE || 1.0),
      certCheckHosts:      config.certCheckHosts       ?? (process.env.SENTINEL_CERT_HOSTS || '').split(',').map((h) => h.trim()).filter(Boolean),
      certCheckIntervalMs: config.certCheckIntervalMs  ?? Number(process.env.SENTINEL_CERT_CHECK_INTERVAL_MS || 6 * 60 * 60 * 1000),
      otlpEndpoint:        config.otlpEndpoint         || process.env.OTEL_EXPORTER_OTLP_ENDPOINT || '',
      healthPort:          config.healthPort           ?? Number(process.env.SENTINEL_HEALTH_PORT || 9090),
      logLevel:            config.logLevel             || _parseEnvLogLevel(),
      diskBufferDir,
      diskBufferMaxMb:     config.diskBufferMaxMb      ?? Number(process.env.SENTINEL_DISK_BUFFER_MAX_MB || 500),
      auditLogPath:        config.auditLogPath         || process.env.SENTINEL_AUDIT_LOG_PATH || path.join(diskBufferDir, 'sentinel-audit.ndjson'),
      enabled:             config.enabled              ?? process.env.SENTINEL_ENABLED !== 'false',
      sessionTtlMs:        config.sessionTtlMs         ?? Number(process.env.SENTINEL_SESSION_TTL_MS || 5 * 60 * 1000),
      adminToken:          config.adminToken           || process.env.SENTINEL_ADMIN_TOKEN || '',
      browserIngest:       config.browserIngest        ?? process.env.SENTINEL_BROWSER_INGEST === 'true',
      allowedOrigins:      config.allowedOrigins       ?? (process.env.SENTINEL_ALLOWED_ORIGINS || '').split(',').map((o) => o.trim()).filter(Boolean),
    };

    this._enabled  = this.cfg.enabled;
    this._minLevel = this.cfg.logLevel;
    this.writer    = new ClickHouseWriter(this.cfg);
    this._sessions = new ActiveSessionTracker(this.cfg.sessionTtlMs);

    if (this.cfg.otlpEndpoint) {
      this.otlp = new OtlpExporter(this.cfg.otlpEndpoint, this.cfg.debug);
    }

    this._initGcObserver();
  }

  /* ── GC observer ─────────────────────────────────────────────────────── */

  private _initGcObserver(): void {
    try {
      const { PerformanceObserver } = require('perf_hooks');
      const obs = new PerformanceObserver((list: any) => {
        for (const e of list.getEntries()) {
          this._gcCount++;
          this._gcDurationMs += e.duration;
        }
      });
      obs.observe({ entryTypes: ['gc'] });
    } catch { /* not available */ }
  }

  /* ── Public API ───────────────────────────────────────────────────────── */

  async hook(): Promise<this> {
    if (!this._enabled) return this;

    await this.writer.init();

    this._startHealthServer();
    this._patchConsole();
    this._patchHttp();
    this._patchHttpClient();
    this._patchFS();
    this._hookProcess();

    if (this.cfg.autoInstrument) {
      this._patchDatabaseDrivers();
      this._patchQueueDrivers();
    }
    if (this.cfg.certCheckHosts.length > 0) this._startCertMonitor();

    this._healthReady = true;

    this._emit({
      message: `Sentinel Node Agent v3.3 hooked on "${this.cfg.serviceName}"`,
      layer:   LogLayer.INFRASTRUCTURE,
      level:   LogLevel.INFO,
      context: {
        nodeVersion:          process.version,
        pid:                  process.pid,
        processUptimeSeconds: 0,
        cpuCoreCount:         os.cpus().length,
        host:                 os.hostname(),
        version:              this.cfg.clickhouseHost, // just log where we're writing
        browserIngest:        this.cfg.browserIngest,
      },
    });

    return this;
  }

  disable(): void { this._enabled = false; }
  enable():  void { this._enabled = true; }
  setLogLevel(level: LogLevel): void { this._minLevel = level; }
  getActiveSessions(): ActiveSessionSummary { return this._sessions.summary(); }

  instrument<T extends object>(target: T | (new (...a: any[]) => T), layer?: LogLayer): this {
    const proto = typeof target === 'function'
      ? (target as any).prototype
      : Object.getPrototypeOf(target);
    if (!proto || this.instrumented.has(proto)) return this;
    this.instrumented.add(proto);

    const className     = (typeof target === 'function' ? (target as any).name : target.constructor?.name) || 'UnknownClass';
    const resolvedLayer = layer || inferLayer(className);
    const methodNames:  string[] = [];

    let p: object | null = proto;
    while (p && p !== Object.prototype) {
      Object.getOwnPropertyNames(p).forEach((key) => {
        if (key === 'constructor') return;
        const desc = Object.getOwnPropertyDescriptor(p!, key);
        if (!desc || typeof desc.value !== 'function') return;
        methodNames.push(key);
        this._wrapMethod(proto, key, className, resolvedLayer);
      });
      p = Object.getPrototypeOf(p);
    }
    return this;
  }

  log(partial: Partial<LogRecord> & { message: string }): void { this._emit(partial); }

  audit(message: string, context: Record<string, any> = {}): void {
    this._emit({ message, layer: LogLayer.SECURITY, level: LogLevel.INFO, context, isAudit: true });
  }

  /** Express/Fastify/Connect middleware — attach to your app */
  middleware() {
    const self       = this;
    const AUTH_PATHS = /\/(login|logout|auth|token|oauth|signin|signup|refresh|verify)/i;

    return (req: any, res: any, next: Function) => {
      // Skip sentinel's own ingest endpoint from being double-logged
      if (req.url === '/sentinel/ingest' || req.path === '/sentinel/ingest') {
        return next();
      }

      const start     = Date.now();
      const reqId     = _genUUID();
      const bodyBytes = Number(req.headers?.['content-length'] || 0);
      self.netBytesIn += bodyBytes;

      const incomingTp = req.headers?.['traceparent'] as string | undefined;
      let requestTraceId = _gen16Hex();
      let spanId         = _gen8Hex();
      if (incomingTp) {
        const parsed = parseTraceparent(incomingTp);
        if (parsed) { requestTraceId = parsed.traceId; spanId = parsed.spanId; }
      }

      res.setHeader?.('traceparent', buildTraceparent(requestTraceId, spanId));

      const method    = req.method || 'GET';
      const urlPath   = req.url || req.path || '/';
      const origin    = req.headers?.['origin'];
      const userAgent = req.headers?.['user-agent'];
      const userId    = (req.headers?.['x-user-id'] || req.user?.id) as string | undefined;
      const sessionId = (req.headers?.['x-session-id'] as string | undefined)
                     || (req.headers?.['cookie'] ? _extractCookieSessionId(req.headers['cookie']) : undefined)
                     || `anon-${_gen8Hex()}`;

      self._sessions.touch({ sessionId, userId, ip: req.ip || req.socket?.remoteAddress, userAgent });

      self._emit({
        message:  `→ ${method} ${urlPath}`,
        layer:    LogLayer.API_GATEWAY,
        level:    LogLevel.INFO,
        trace_id: requestTraceId,
        context:  maskContext({
          method, path: urlPath, requestId: reqId,
          clientIp: req.ip || req.socket?.remoteAddress,
          userAgent, requestSizeBytes: bodyBytes,
          userId, sessionId, traceId: requestTraceId,
          corsOrigin: origin,
          activeSessions: self._sessions.count(),
        }),
      });

      const origEnd   = res.end.bind(res);
      const origWrite = res.write.bind(res);
      let resBytes    = 0;

      res.write = (...args: any[]) => {
        if (args[0] != null) resBytes += Buffer.isBuffer(args[0]) ? args[0].length : Buffer.byteLength(String(args[0]), args[1] || 'utf-8');
        return origWrite(...args);
      };

      res.end = (...args: any[]) => {
        if (args[0] != null) resBytes += Buffer.isBuffer(args[0]) ? args[0].length : Buffer.byteLength(String(args[0]), args[1] || 'utf-8');

        const durationMs    = Date.now() - start;
        const statusCode    = res.statusCode || 200;
        const isSlow        = durationMs > self.cfg.slowHttpMs;
        const rateLimitHit  = statusCode === 429;
        const corsViolation = statusCode === 403 && !!origin;
        const isAuthPath    = AUTH_PATHS.test(urlPath);
        const isAuthFailure = statusCode === 401 || statusCode === 403;
        const botSignal     = /bot|crawl|spider|scraper|curl|wget|python-requests|go-http/.test((userAgent || '').toLowerCase());
        self.netBytesOut   += resBytes;

        if (isAuthPath || isAuthFailure) {
          self._emit({
            message:  `Auth event: ${method} ${urlPath} → ${statusCode}`,
            layer:    LogLayer.SECURITY,
            level:    isAuthFailure ? LogLevel.WARN : LogLevel.INFO,
            trace_id: requestTraceId,
            isAudit:  true,
            context:  maskContext({
              authResult: statusCode < 400 ? 'success' : 'failure',
              path: urlPath, statusCode, userAgent, userId, sessionId,
              traceId: requestTraceId,
              failureReason: isAuthFailure ? `HTTP ${statusCode}` : undefined,
            }),
          } as any);
        }

        self._emit({
          message:  `← ${method} ${urlPath} ${statusCode} (${durationMs}ms)${isSlow ? ' [SLOW]' : ''}${rateLimitHit ? ' [RATE-LIMITED]' : ''}`,
          layer:    LogLayer.API_GATEWAY,
          level:    statusCode >= 500 ? LogLevel.ERROR : statusCode >= 400 ? LogLevel.WARN : LogLevel.INFO,
          trace_id: requestTraceId,
          context:  maskContext({
            method, path: urlPath, statusCode, durationMs,
            requestId: reqId, userAgent,
            userId, sessionId, traceId: requestTraceId,
            rateLimitHit, corsViolation, botSignal,
            responseSizeBytes: resBytes || undefined,
            activeSessions: self._sessions.count(),
            rateLimitRemaining: Number(res.getHeader?.('X-RateLimit-Remaining') ?? -1) >= 0
              ? Number(res.getHeader?.('X-RateLimit-Remaining')) : undefined,
          }),
        });

        return origEnd(...args);
      };

      next();
    };
  }

  /* ── Browser ingest handler ───────────────────────────────────────────── */

  /**
   * Handles POST /sentinel/ingest — receives browser log batches and writes
   * them directly into the same ClickHouse table as backend logs.
   * Called automatically by the health server when browserIngest=true.
   * You can also call it manually from any framework handler.
   */
  async handleBrowserIngest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const origin = req.headers['origin'] as string | undefined;
    const cors   = _corsHeaders(origin, this.cfg.allowedOrigins);

    // Set CORS headers always
    Object.entries(cors).forEach(([k, v]) => res.setHeader(k, v));

    // Handle preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(204).end();
      return;
    }

    if (req.method !== 'POST') {
      res.writeHead(405).end();
      return;
    }

    try {
      // Read body
      const chunks: Buffer[] = [];
      await new Promise<void>((resolve, reject) => {
        req.on('data',  (c: Buffer) => chunks.push(c));
        req.on('end',   () => resolve());
        req.on('error', reject);
      });

      const raw     = Buffer.concat(chunks).toString('utf-8');
      const records = JSON.parse(raw || '[]') as any[];

      if (!Array.isArray(records)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'body must be an array' }));
        return;
      }

      // Normalise and enqueue each browser record into the same writer
      for (const r of records) {
        // context may arrive as a JSON string (browser serialises it)
        let ctx = r.context || {};
        if (typeof ctx === 'string') {
          try { ctx = JSON.parse(ctx); } catch { ctx = {}; }
        }

        const record = new LogRecord({
          message:    r.message    || '',
          layer:      r.layer      || LogLayer.PRESENTATION,
          level:      r.level      || LogLevel.INFO,
          service:    r.service    || 'browser',
          trace_id:   r.trace_id   || ctx.traceId   || _gen16Hex(),
          span_id:    r.span_id    || ctx.spanId     || _gen8Hex(),
          session_id: ctx.sessionId || '',
          user_id:    ctx.userId    || '',
          tenant_id:  ctx.tenantId  || '',
          context:    ctx,
        });

        this.writer.enqueue(record);  // same writer → same ClickHouse table
      }

      if (this.cfg.debug) {
        console.error(`[SENTINEL ingest] received ${records.length} browser records`);
      }

      res.writeHead(204).end();
    } catch (err) {
      if (this.cfg.debug) console.error('[SENTINEL ingest] error:', err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'ingest failed' }));
    }
  }

  /* ── Health server ────────────────────────────────────────────────────── */

  private _startHealthServer(): void {
    const self = this;

    const srv = http.createServer(async (req, res) => {
      // ── /health ──────────────────────────────────────────────────────────
      if (req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status:  'ok',
          service: self.cfg.serviceName,
          uptime:  Math.round((Date.now() - self.processStart) / 1000),
          pid:     process.pid,
        }));
        return;
      }

      // ── /ready ───────────────────────────────────────────────────────────
      if (req.url === '/ready') {
        res.writeHead(self._healthReady ? 200 : 503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: self._healthReady ? 'ready' : 'not_ready' }));
        return;
      }

      // ── /_sessions ───────────────────────────────────────────────────────
      if (req.url === '/_sessions') {
        if (self.cfg.adminToken) {
          const auth = req.headers['authorization'] || '';
          if (auth !== `Bearer ${self.cfg.adminToken}`) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'unauthorized' }));
            return;
          }
        }
        const summary = self._sessions.summary();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ...summary, timestamp: new Date().toISOString(), service: self.cfg.serviceName }));
        return;
      }

      // ── /sentinel/ingest  (browser logs) ─────────────────────────────────
      if (req.url === '/sentinel/ingest' && self.cfg.browserIngest) {
        await self.handleBrowserIngest(req, res);
        return;
      }

      res.writeHead(404).end();
    });

    srv.listen(this.cfg.healthPort, () => {
      if (this.cfg.debug) {
        console.error(`[SENTINEL] Health:   http://0.0.0.0:${this.cfg.healthPort}/health`);
        console.error(`[SENTINEL] Sessions: http://0.0.0.0:${this.cfg.healthPort}/_sessions`);
        if (this.cfg.browserIngest) {
          console.error(`[SENTINEL] Ingest:   http://0.0.0.0:${this.cfg.healthPort}/sentinel/ingest`);
        }
      }
    });

    srv.unref();
  }

  /* ── Emitter ──────────────────────────────────────────────────────────── */

  private _emit(partial: Partial<LogRecord> & { message: string; isAudit?: boolean }): void {
    if (!this._enabled) return;

    const level   = (partial.level || LogLevel.INFO) as LogLevel;
    const isAudit = partial.isAudit || false;

    if (!isAudit && _LEVEL_ORDER[level] < _LEVEL_ORDER[this._minLevel]) return;
    if (!isAudit && this.cfg.samplingRate < 1.0) {
      if (level === LogLevel.INFO || level === LogLevel.DEBUG) {
        if (Math.random() > this.cfg.samplingRate) return;
      }
    }

    const record = new LogRecord({
      ...partial,
      service:  this.cfg.serviceName,
      trace_id: partial.trace_id || this.traceId,
      isAudit,
      context: {
        ...maskContext(partial.context || {}),
        samplingRate:     this.cfg.samplingRate,
        samplingDecision: 'sampled',
      },
    });

    if (this.cfg.debug) console.error(`[SENTINEL] ${record.toString()}`);

    this.writer.enqueue(record);
    this.otlp?.enqueue(record);
  }

  /* ── Console patch ────────────────────────────────────────────────────── */

  private _patchConsole(): void {
    const self   = this;
    const PREFIX = '[SENTINEL]';
    const colors: Record<string, string> = {
      DEBUG: '\x1b[36m', INFO: '\x1b[32m', WARN: '\x1b[33m', ERROR: '\x1b[31m', FATAL: '\x1b[35m',
    };
    const map: Array<[keyof Console, LogLevel]> = [
      ['log', LogLevel.INFO], ['info', LogLevel.INFO], ['warn', LogLevel.WARN],
      ['error', LogLevel.ERROR], ['debug', LogLevel.DEBUG],
    ];
    map.forEach(([method, level]) => {
      const orig = (console as any)[method].bind(console);
      (console as any)[method] = (...args: any[]) => {
        const msg = args.map((a) => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' ');
        if (msg.includes(PREFIX)) { orig(...args); return; }
        self._emit({ message: maskPII(msg), layer: LogLayer.BUSINESS_LOGIC, level });
        orig(`${PREFIX} ${colors[level]}[${level}]\x1b[0m ${msg}`);
      };
    });
  }

  /* ── HTTP server patch (inbound) ──────────────────────────────────────── */

  private _patchHttp(): void {
    const self       = this;
    const AUTH_PATHS = /\/(login|logout|auth|token|oauth|signin|signup|refresh|verify)/i;

    const wrapListener = (
      listener: ((req: http.IncomingMessage, res: http.ServerResponse) => void) | undefined,
    ) => (req: http.IncomingMessage, res: http.ServerResponse) => {
      // Skip health server port and browser ingest path
      const localPort = (req.socket as any)?.localPort
                     ?? (req.socket as any)?.server?._connectionKey?.split(':').pop();
      if (Number(localPort) === self.cfg.healthPort) { listener?.(req, res); return; }

      const start     = Date.now();
      const reqId     = _genUUID();
      const bodyBytes = Number(req.headers['content-length'] || 0);
      self.netBytesIn += bodyBytes;

      const userId    = req.headers['x-user-id'] as string | undefined;
      const sessionId = (req.headers['x-session-id'] as string | undefined)
                     || (req.headers['cookie'] ? _extractCookieSessionId(req.headers['cookie'] as string) : undefined)
                     || `anon-${_gen8Hex()}`;

      self._sessions.touch({ sessionId, userId, ip: req.socket.remoteAddress, userAgent: req.headers['user-agent'] });

      const incomingTp = req.headers['traceparent'] as string | undefined;
      let traceId = self.traceId;
      let spanId  = _gen8Hex();
      if (incomingTp) {
        const parsed = parseTraceparent(incomingTp);
        if (parsed) { traceId = parsed.traceId; spanId = parsed.spanId; }
      }

      self._emit({
        message:  `→ ${req.method} ${req.url}`,
        layer:    LogLayer.API_GATEWAY,
        level:    LogLevel.INFO,
        trace_id: traceId,
        context:  maskContext({
          method: req.method, path: req.url, requestId: reqId,
          clientIp: req.socket.remoteAddress, userAgent: req.headers['user-agent'],
          requestSizeBytes: bodyBytes,
          userId, sessionId, traceId,
          activeSessions: self._sessions.count(),
        }),
      });

      const origin = req.headers['origin'];
      res.on('finish', () => {
        const durationMs    = Date.now() - start;
        const isSlow        = durationMs > self.cfg.slowHttpMs;
        const rateLimitHit  = res.statusCode === 429;
        const corsViolation = res.statusCode === 403 && !!origin;
        const resBytes      = Number(res.getHeader('content-length') || 0);
        self.netBytesOut   += resBytes;
        const ua            = (req.headers['user-agent'] || '').toLowerCase();
        const botSignal     = /bot|crawl|spider|scraper|curl|wget|python-requests|go-http/.test(ua);
        const isAuthPath    = AUTH_PATHS.test(req.url || '');
        const isAuthFailure = res.statusCode === 401 || res.statusCode === 403;

        if (isAuthPath || isAuthFailure) {
          self._emit({
            message:  `Auth event: ${req.method} ${req.url} → ${res.statusCode}`,
            layer:    LogLayer.SECURITY,
            level:    isAuthFailure ? LogLevel.WARN : LogLevel.INFO,
            trace_id: traceId,
            isAudit:  true,
            context:  maskContext({
              authResult: res.statusCode < 400 ? 'success' : 'failure',
              path: req.url, statusCode: res.statusCode, userAgent: req.headers['user-agent'],
              userId, sessionId, traceId,
              failureReason: isAuthFailure ? `HTTP ${res.statusCode}` : undefined,
            }),
          } as any);
        }

        self._emit({
          message:  `← ${req.method} ${req.url} ${res.statusCode} (${durationMs}ms)${isSlow ? ' [SLOW]' : ''}${rateLimitHit ? ' [RATE-LIMITED]' : ''}`,
          layer:    LogLayer.API_GATEWAY,
          level:    res.statusCode >= 500 ? LogLevel.ERROR : res.statusCode >= 400 ? LogLevel.WARN : LogLevel.INFO,
          trace_id: traceId,
          context:  maskContext({
            method: req.method, path: req.url, statusCode: res.statusCode, durationMs,
            requestId: reqId, userAgent: req.headers['user-agent'],
            userId, sessionId, traceId,
            rateLimitHit, corsViolation, botSignal,
            responseSizeBytes: resBytes || undefined,
            corsOrigin: origin,
            activeSessions: self._sessions.count(),
          }),
        });
      });

      listener?.(req, res);
    };

    const origHttp  = http.createServer.bind(http);
    (http as any).createServer = (...args: any[]) => {
      if (typeof args[0] === 'function') args[0] = wrapListener(args[0]);
      else if (typeof args[1] === 'function') args[1] = wrapListener(args[1]);
      return origHttp(...(args as Parameters<typeof http.createServer>));
    };

    const origHttps = https.createServer.bind(https);
    (https as any).createServer = (...args: any[]) => {
      const last = args[args.length - 1];
      if (typeof last === 'function') args[args.length - 1] = wrapListener(last);
      return origHttps(...(args as Parameters<typeof https.createServer>));
    };
  }

  /* ── Outbound HTTP client ─────────────────────────────────────────────── */

  private _patchHttpClient(): void {
    const self = this;

    const wrap = (orig: typeof http.request, scheme: string) =>
      (...args: any[]): http.ClientRequest => {
        const req     = orig(...(args as Parameters<typeof http.request>));
        const urlStr  = typeof args[0] === 'string' ? args[0]
                      : args[0] instanceof URL       ? args[0].toString()
                      : `${(args[0] as http.RequestOptions).host}${(args[0] as http.RequestOptions).path}`;
        const method  = (args[0] as http.RequestOptions).method || 'GET';
        const start   = Date.now();
        try { req.setHeader('traceparent', buildTraceparent(self.traceId, _gen8Hex())); } catch { /* ignore */ }

        self._emit({
          message: `Outbound ${scheme}: ${method} ${maskPII(urlStr)}`,
          layer:   LogLayer.SERVICE, level: LogLevel.INFO,
          context: { method, path: maskPII(urlStr) },
        });

        req.on('response', (res) => {
          const durationMs = Date.now() - start;
          self._emit({
            message: `Outbound ${scheme} ← ${method} ${maskPII(urlStr)} ${res.statusCode} (${durationMs}ms)`,
            layer:   LogLayer.SERVICE,
            level:   (res.statusCode || 200) >= 400 ? LogLevel.WARN : LogLevel.INFO,
            context: maskContext({ method, path: maskPII(urlStr), statusCode: res.statusCode, durationMs, rateLimitHit: res.statusCode === 429 }),
          });
        });

        req.on('error', (err) => {
          self._emit({
            message: `Outbound ${scheme} error: ${method} ${maskPII(urlStr)} — ${err.message}`,
            layer:   LogLayer.SERVICE, level: LogLevel.ERROR,
            context: { method, path: maskPII(urlStr), durationMs: Date.now() - start, exceptionType: err.constructor.name, stackTrace: err.stack },
          });
        });

        return req;
      };

    http.request  = wrap(http.request.bind(http),   'HTTP')  as typeof http.request;
    https.request = wrap(https.request.bind(https), 'HTTPS') as typeof https.request;
  }

  /* ── File system patch ────────────────────────────────────────────────── */

  private _patchFS(): void {
    const self = this;
    const ops  = ['readFile','writeFile','appendFile','unlink','readdir','stat','mkdir','rmdir'] as const;

    ops.forEach((op) => {
      const orig = (fs as any)[op] as Function;
      if (typeof orig !== 'function') return;

      (fs as any)[op] = (...args: any[]) => {
        const filePath = String(args[0]);
        if (filePath.includes('sentinel-')) return orig.apply(fs, args);

        const start   = Date.now();
        const isRead  = op === 'readFile';
        const isWrite = op === 'writeFile' || op === 'appendFile';

        self._emit({
          message: `FS.${op}: ${maskPII(filePath)}`,
          layer:   LogLayer.DATA_ACCESS, level: LogLevel.DEBUG,
          context: { fileOperation: op, filePath: maskPII(filePath) },
        });

        const cbIdx = args.findIndex((a, i) => i > 0 && typeof a === 'function');
        if (cbIdx !== -1) {
          const origCb = args[cbIdx];
          args[cbIdx] = (err: NodeJS.ErrnoException | null, ...rest: any[]) => {
            const durationMs = Date.now() - start;
            if (err) {
              self._emit({
                message: `FS.${op} failed: ${maskPII(filePath)} — ${err.message}`,
                layer:   LogLayer.DATA_ACCESS, level: LogLevel.ERROR,
                context: { fileOperation: op, filePath: maskPII(filePath), durationMs, exceptionType: err.code },
              });
            } else {
              self._emit({
                message: `FS.${op} done: ${maskPII(filePath)} (${durationMs}ms)`,
                layer:   LogLayer.DATA_ACCESS, level: LogLevel.DEBUG,
                context: {
                  fileOperation: op, filePath: maskPII(filePath), durationMs,
                  fileSizeBytes:  op === 'stat' ? rest[0]?.size : undefined,
                  fileReadBytes:  isRead  && rest[0] != null ? (Buffer.isBuffer(rest[0]) ? rest[0].length : Buffer.byteLength(String(rest[0]))) : undefined,
                  fileWriteBytes: isWrite && args[1] != null ? (Buffer.isBuffer(args[1]) ? args[1].length : Buffer.byteLength(String(args[1]))) : undefined,
                },
              });
            }
            origCb(err, ...rest);
          };
        }
        return orig.apply(fs, args);
      };
    });
  }

  /* ── Process hooks + vitals ───────────────────────────────────────────── */

  private _hookProcess(): void {
    const self = this;

    process.on('uncaughtException', (err) => {
      self._emit({
        message: `Uncaught Exception: ${err.message}`,
        layer:   LogLayer.SECURITY, level: LogLevel.FATAL,
        context: { exceptionType: err.constructor.name, stackTrace: err.stack, processUptimeSeconds: (Date.now() - self.processStart) / 1000 },
      });
    });

    process.on('unhandledRejection', (reason) => {
      self._emit({
        message: `Unhandled Rejection: ${reason}`,
        layer:   LogLayer.OBSERVABILITY, level: LogLevel.ERROR,
        context: { exceptionType: String(reason) },
      });
    });

    (['SIGTERM', 'SIGINT'] as NodeJS.Signals[]).forEach((sig) => {
      process.on(sig, () => {
        self._emit({
          message: `Process signal: ${sig}`,
          layer:   LogLayer.INFRASTRUCTURE, level: LogLevel.WARN,
          context: { containerEvent: 'stop', containerName: self.cfg.serviceName, processUptimeSeconds: (Date.now() - self.processStart) / 1000 },
        });
      });
    });

    let prevCpuTimes = os.cpus().map((c) => ({ ...c.times }));

    // Extended vitals every 30s
    setInterval(async () => {
      const mem     = process.memoryUsage();
      const freeMem = os.freemem();
      const cpus    = os.cpus();

      const cpuPercents = cpus.map((cpu, i) => {
        const prev  = prevCpuTimes[i] || cpu.times;
        const delta = (k: keyof typeof cpu.times) => cpu.times[k] - (prev as any)[k];
        const total = (['user','nice','sys','idle','irq'] as const).reduce((s, k) => s + delta(k), 0);
        const idle  = delta('idle');
        return total > 0 ? ((total - idle) / total) * 100 : 0;
      });
      prevCpuTimes = cpus.map((c) => ({ ...c.times }));
      const cpuPercent = cpuPercents.reduce((a, b) => a + b, 0) / (cpuPercents.length || 1);

      const eventLoopLagMs = await _measureEventLoopLag();

      let heapSpaces: Record<string, number> | undefined;
      try {
        const v8  = await import('v8');
        heapSpaces = Object.fromEntries(v8.getHeapSpaceStatistics().map((s) => [s.space_name, s.space_used_size]));
      } catch { /* ignore */ }

      const openFds      = await _fdCount();
      const gcCount      = self._gcCount;
      const gcDurationMs = self._gcDurationMs;
      self._gcCount      = 0;
      self._gcDurationMs = 0;

      const sessions = self._sessions.summary();

      self._emit({
        message: `Process vitals: cpu=${cpuPercent.toFixed(1)}% heap=${(mem.heapUsed / 1024 / 1024).toFixed(1)}MB rss=${(mem.rss / 1024 / 1024).toFixed(1)}MB sessions=${sessions.totalActiveSessions}`,
        layer:   LogLayer.INFRASTRUCTURE,
        level:   cpuPercent > 85 ? LogLevel.WARN : LogLevel.INFO,
        context: {
          cpuPercent:           parseFloat(cpuPercent.toFixed(2)),
          cpuPercentsPerCore:   cpuPercents.map((p) => parseFloat(p.toFixed(2))),
          cpuCoreCount:         cpus.length,
          memoryUsedBytes:      mem.heapUsed,
          memoryTotalBytes:     mem.heapTotal,
          memoryAvailableBytes: freeMem,
          memoryRssBytes:       mem.rss,
          memoryExternalBytes:  mem.external,
          swapUsedBytes:        Math.max(0, os.totalmem() - freeMem - mem.heapUsed),
          networkInBytes:       self.netBytesIn,
          networkOutBytes:      self.netBytesOut,
          eventLoopLagMs,
          gcCount,
          gcDurationMs:         parseFloat(gcDurationMs.toFixed(2)),
          openFileDescriptors:  openFds,
          heapSpaces,
          activeSessions:       sessions.totalActiveSessions,
          activeUniqueUsers:    sessions.totalUniqueUsers,
          anonymousSessions:    sessions.totalAnonymous,
          containerName:        self.cfg.serviceName,
          processUptimeSeconds: (Date.now() - self.processStart) / 1000,
          host:                 os.hostname(),
        },
      });
    }, 30_000).unref();

    // Disk vitals every 60s
    setInterval(async () => {
      try {
        const { statfs } = await import('fs/promises') as any;
        if (typeof statfs !== 'function') return;
        const s: any  = await statfs('/');
        const total   = s.bsize * s.blocks;
        const free    = s.bsize * s.bavail;
        const used    = total - free;
        const pct     = total > 0 ? Math.round((used / total) * 100) : 0;
        const iTotal  = s.files || 0;
        const iFree   = s.ffree || 0;
        const iUsed   = iTotal - iFree;
        self._emit({
          message: `Disk vitals: ${pct}% used (${(used / 1e9).toFixed(2)}GB / ${(total / 1e9).toFixed(2)}GB)`,
          layer:   LogLayer.INFRASTRUCTURE,
          level:   pct > 85 ? LogLevel.WARN : LogLevel.INFO,
          context: {
            diskUsedBytes: used, diskTotalBytes: total, diskFreeBytes: free, diskUsedPercent: pct,
            inodeTotalCount: iTotal, inodeUsedCount: iUsed,
            inodeUsedPercent: iTotal > 0 ? Math.round((iUsed / iTotal) * 100) : 0,
            containerName: self.cfg.serviceName,
          },
        });
      } catch { /* statfs not available */ }
    }, 60_000).unref();
  }

  /* ── TLS cert monitor ─────────────────────────────────────────────────── */

  private _startCertMonitor(): void {
    const self  = this;
    const check = () => {
      self.cfg.certCheckHosts.forEach((hostname) => {
        const socket = tls.connect(443, hostname, { servername: hostname }, () => {
          try {
            const cert     = socket.getPeerCertificate();
            const daysLeft = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86_400_000);
            const issuer   = cert.issuer?.O || cert.issuer?.CN || 'unknown';
            self._emit({
              message: `TLS cert: ${hostname} expires in ${daysLeft} days`,
              layer:   LogLayer.INFRASTRUCTURE,
              level:   daysLeft < 7 ? LogLevel.FATAL : daysLeft < 14 ? LogLevel.ERROR : daysLeft < 30 ? LogLevel.WARN : LogLevel.INFO,
              context: { certDomain: hostname, certExpiryDays: daysLeft, certIssuer: issuer },
            });
          } catch { /* ignore */ }
          socket.destroy();
        });
        socket.on('error', (err) => {
          self._emit({
            message: `TLS cert check failed: ${hostname} — ${err.message}`,
            layer:   LogLayer.INFRASTRUCTURE, level: LogLevel.ERROR,
            context: { certDomain: hostname, exceptionType: err.constructor.name },
          });
        });
      });
    };
    check();
    setInterval(check, this.cfg.certCheckIntervalMs).unref();
  }

  /* ── DB driver patches ────────────────────────────────────────────────── */


   private _patchDatabaseDrivers(): void {
  this._tryPatchPg();
  this._tryPatchNeo4j();
  this._tryPatchMongoose();
  this._tryPatchMongoDB();  // ← add this line
  this._tryPatchRedis();
}

  private _tryPatchPg(): void {
    let pg: any;
    try { pg = require('pg'); } catch { return; }
    const self = this;

    try {
      const origQuery = pg.Client.prototype.query.bind(pg.Client.prototype);
      pg.Client.prototype.query = async function (...args: any[]) {
        const sql   = typeof args[0] === 'string' ? args[0] : args[0]?.text || '';
        const start = Date.now();
        const sqlUp = sql.trim().toUpperCase();
        try {
          const result     = await origQuery.apply(this, args);
          const durationMs = Date.now() - start;
          const isSlow     = durationMs > self.cfg.slowQueryMs;
          self._emit({
            message: `PG${isSlow ? ' [SLOW]' : ''}: ${sql.slice(0, 120)}`,
            layer:   LogLayer.DATA_ACCESS,
            level:   isSlow ? LogLevel.WARN : LogLevel.INFO,
            context: {
              database: 'postgres', queryType: sqlUp.split(' ')[0],
              durationMs, rowsAffected: result?.rowCount,
              slowQuery: isSlow, slowQueryThresholdMs: self.cfg.slowQueryMs,
              transactionAction: sqlUp.startsWith('COMMIT') ? 'commit' : sqlUp.startsWith('ROLLBACK') ? 'rollback' : undefined,
              migrationName: /^(CREATE|DROP|ALTER)\s+TABLE/.test(sqlUp) ? sql.slice(0, 80) : undefined,
            },
          });
          return result;
        } catch (err: any) {
          self._emit({
            message: `PG error: ${err.message}`,
            layer:   LogLayer.DATA_ACCESS, level: LogLevel.ERROR,
            context: { database: 'postgres', durationMs: Date.now() - start, deadlock: err.code === '40P01', lockTimeout: err.code === '55P03', exceptionType: err.code, stackTrace: err.stack },
          });
          throw err;
        }
      };
    } catch (e) { if (this.cfg.debug) console.error('[SENTINEL] pg patch failed:', e); }

    // Pool connection wait time
    try {
      if (pg.Pool?.prototype?.connect) {
        const origConnect = pg.Pool.prototype.connect.bind(pg.Pool.prototype);
        pg.Pool.prototype.connect = async function (...args: any[]) {
          const start  = Date.now();
          const client = await origConnect.apply(this, args);
          const waitMs = Date.now() - start;
          if (waitMs > 50) {
            self._emit({
              message: `PG pool: connection wait ${waitMs}ms`,
              layer:   LogLayer.DATA_ACCESS, level: LogLevel.DEBUG,
              context: { database: 'postgres', connectionPoolSize: this.totalCount, connectionPoolUsed: this.totalCount - this.idleCount, connectionWaitMs: waitMs },
            });
          }
          return client;
        };
      }
    } catch { /* ignore */ }
  }

  private _tryPatchNeo4j(): void {
    let neo4j: any;
    try { neo4j = require('neo4j-driver'); } catch { return; }
    const self = this;
    try {
      const orig = neo4j.Session.prototype.run?.bind(neo4j.Session.prototype);
      if (!orig) return;
      neo4j.Session.prototype.run = async function (...args: any[]) {
        const start = Date.now();
        try {
          const result     = await orig.apply(this, args);
          const durationMs = Date.now() - start;
          const isSlow     = durationMs > self.cfg.slowQueryMs;
          self._emit({
            message: `Neo4j${isSlow ? ' [SLOW]' : ''}: ${String(args[0]).slice(0, 120)}`,
            layer:   LogLayer.DATA_ACCESS,
            level:   isSlow ? LogLevel.WARN : LogLevel.INFO,
            context: { database: 'neo4j', durationMs, slowQuery: isSlow },
          });
          return result;
        } catch (err: any) {
          self._emit({ message: `Neo4j error: ${err.message}`, layer: LogLayer.DATA_ACCESS, level: LogLevel.ERROR, context: { database: 'neo4j', exceptionType: err.code, stackTrace: err.stack } });
          throw err;
        }
      };
    } catch (e) { if (this.cfg.debug) console.error('[SENTINEL] neo4j patch failed:', e); }
  }

   
  private _tryPatchMongoose(): void {
    let mongoose: any;
    try { mongoose = require('mongoose'); } catch { return; }
    const self = this;
    try {
      mongoose.plugin((schema: any) => {
        const hooks = ['save','find','findOne','findOneAndUpdate','deleteOne','deleteMany','updateOne','updateMany'];
        hooks.forEach((hook) => {
          schema.pre(hook,  function (this: any, next: Function) { this._sentinelStart = Date.now(); next(); });
          schema.post(hook, function (this: any, result: any) {
            const durationMs = Date.now() - (this._sentinelStart || Date.now());
            const isSlow     = durationMs > self.cfg.slowQueryMs;
            self._emit({
              message: `Mongoose ${hook}${isSlow ? ' [SLOW]' : ''}`,
              layer:   LogLayer.DATA_ACCESS,
              level:   isSlow ? LogLevel.WARN : LogLevel.INFO,
              context: { database: 'mongodb', queryType: hook.toUpperCase(), durationMs, rowCount: Array.isArray(result) ? result.length : 1, slowQuery: isSlow },
            });
          });
        });
      });
    } catch (e) { if (this.cfg.debug) console.error('[SENTINEL] mongoose patch failed:', e); }
  }


   private _tryPatchMongoDB(): void {
  let mongodb: any;
  try { mongodb = require('mongodb'); } catch { return; }
  const self = this;

  const origCollection = mongodb.Db.prototype.collection.bind(mongodb.Db.prototype);
  mongodb.Db.prototype.collection = function (...args: any[]) {
    const col = origCollection.apply(this, args);
    const ops = ['find','findOne','insertOne','insertMany',
                 'updateOne','updateMany','deleteOne','deleteMany',
                 'aggregate','countDocuments','findOneAndUpdate',
                 'findOneAndDelete'];
    ops.forEach((op) => {
      const orig = col[op]?.bind(col);
      if (!orig) return;
      col[op] = async (...a: any[]) => {
        const start = Date.now();
        try {
          const result     = await orig(...a);
          const durationMs = Date.now() - start;
          const isSlow     = durationMs > self.cfg.slowQueryMs;
          self._emit({
            message: `MongoDB ${op}${isSlow ? ' [SLOW]' : ''}: ${col.collectionName}`,
            layer:   LogLayer.DATA_ACCESS,
            level:   isSlow ? LogLevel.WARN : LogLevel.INFO,
            context: {
              database:             'mongodb',
              queryType:            op.toUpperCase(),
              table:                col.collectionName,
              durationMs,
              slowQuery:            isSlow,
              slowQueryThresholdMs: self.cfg.slowQueryMs,
              rowCount:             Array.isArray(result) ? result.length : undefined,
            },
          });
          return result;
        } catch (err: any) {
          self._emit({
            message: `MongoDB ${op} error: ${err.message}`,
            layer:   LogLayer.DATA_ACCESS,
            level:   LogLevel.ERROR,
            context: {
              database:      'mongodb',
              queryType:     op.toUpperCase(),
              table:         col.collectionName,
              durationMs:    Date.now() - start,
              exceptionType: err.constructor.name,
              stackTrace:    err.stack,
            },
          });
          throw err;
        }
      };
    });
    return col;
  };
}
  private _tryPatchRedis(): void {
    let Redis: any;
    try { Redis = require('ioredis'); } catch { return; }
    const self = this;
    try {
      const orig = Redis.prototype.sendCommand.bind(Redis.prototype);
      Redis.prototype.sendCommand = async function (...args: any[]) {
        const cmd   = args[0]?.name || 'CMD';
        const start = Date.now();
        try {
          const result     = await orig.apply(this, args);
          const durationMs = Date.now() - start;
          self._emit({
            message: `Redis ${cmd} (${durationMs}ms)`,
            layer:   LogLayer.DATA_ACCESS, level: LogLevel.DEBUG,
            context: { database: 'redis', queryType: cmd, durationMs, cacheHit: result !== null, cacheMiss: result === null, cacheEviction: ['DEL','UNLINK','EXPIRE','EXPIREAT'].includes(cmd) },
          });
          return result;
        } catch (err: any) {
          self._emit({ message: `Redis ${cmd} error: ${err.message}`, layer: LogLayer.DATA_ACCESS, level: LogLevel.ERROR, context: { database: 'redis', exceptionType: err.constructor.name } });
          throw err;
        }
      };
    } catch (e) { if (this.cfg.debug) console.error('[SENTINEL] ioredis patch failed:', e); }
  }

  /* ── Queue driver patches ─────────────────────────────────────────────── */

  private _patchQueueDrivers(): void {
    this._tryPatchAmqplib();
    this._tryPatchBullMQ();
    this._tryPatchKafkaJS();
  }

  private _tryPatchAmqplib(): void {
    let amqp: any;
    try { amqp = require('amqplib'); } catch { return; }
    const self        = this;
    const origConnect = amqp.connect.bind(amqp);

    const patchChannel = (ch: any) => {
      const origPublish = ch.publish.bind(ch);
      ch.publish = (exchange: string, routingKey: string, content: Buffer, options?: any) => {
        const headers = { ...(options?.headers || {}), traceparent: buildTraceparent(self.traceId, _gen8Hex()) };
        self._emit({ message: `AMQP publish: ${exchange || '(default)'}/${routingKey}`, layer: LogLayer.INFRASTRUCTURE, level: LogLevel.INFO, context: { queueName: routingKey, queueAction: 'publish', exchange, messageBytes: content?.length } });
        return origPublish(exchange, routingKey, content, { ...options, headers });
      };
      const origConsume = ch.consume.bind(ch);
      ch.consume = async (queue: string, onMessage: Function, options?: any) => {
        return origConsume(queue, (msg: any) => {
          if (!msg) return;
          const start   = Date.now();
          const tp      = msg.properties?.headers?.traceparent;
          let   traceId = self.traceId;
          if (tp) { const p = parseTraceparent(tp); if (p) traceId = p.traceId; }
          try {
            onMessage(msg);
            self._emit({ message: `AMQP consume: ${queue} (${Date.now() - start}ms)`, layer: LogLayer.INFRASTRUCTURE, level: LogLevel.INFO, trace_id: traceId, context: { queueName: queue, queueAction: 'consume', durationMs: Date.now() - start } });
          } catch (err: any) {
            self._emit({ message: `AMQP consume error: ${queue} — ${err.message}`, layer: LogLayer.INFRASTRUCTURE, level: LogLevel.ERROR, trace_id: traceId, context: { queueName: queue, exceptionType: err.constructor.name, stackTrace: err.stack } });
            throw err;
          }
        }, options);
      };
    };

    amqp.connect = async (...args: any[]) => {
      const conn = await origConnect(...args);
      for (const m of ['createChannel', 'createConfirmChannel'] as const) {
        const origCreate = conn[m]?.bind(conn);
        if (!origCreate) continue;
        conn[m] = async () => { const ch = await origCreate(); patchChannel(ch); return ch; };
      }
      return conn;
    };
  }

  private _tryPatchBullMQ(): void {
    let bullmq: any;
    try { bullmq = require('bullmq'); } catch { return; }
    const self = this;
    try {
      const { Worker, Queue } = bullmq;

      const origAdd = Queue.prototype.add?.bind(Queue.prototype);
      if (origAdd) {
        Queue.prototype.add = async function (name: string, data: any, opts?: any) {
          const start = Date.now();
          try {
            const job = await origAdd.apply(this, [name, data, opts]);
            self._emit({ message: `BullMQ enqueue: ${this.name}/${name} (${Date.now() - start}ms)`, layer: LogLayer.INFRASTRUCTURE, level: LogLevel.INFO, context: { queueName: this.name, queueAction: 'enqueue', jobName: name, jobId: job?.id } });
            return job;
          } catch (err: any) {
            self._emit({ message: `BullMQ enqueue error: ${this.name}/${name} — ${err.message}`, layer: LogLayer.INFRASTRUCTURE, level: LogLevel.ERROR, context: { queueName: this.name, jobName: name, exceptionType: err.constructor.name } });
            throw err;
          }
        };
      }

      const origProcess = Worker.prototype.processJob?.bind(Worker.prototype);
      if (origProcess) {
        Worker.prototype.processJob = async function (job: any, token: string) {
          const start = Date.now();
          try {
            const result     = await origProcess.apply(this, [job, token]);
            const durationMs = Date.now() - start;
            self._emit({ message: `BullMQ done: ${job.queueName}/${job.name} (${durationMs}ms)`, layer: LogLayer.INFRASTRUCTURE, level: LogLevel.INFO, context: { queueName: job.queueName, jobName: job.name, jobId: job.id, durationMs } });
            return result;
          } catch (err: any) {
            const durationMs = Date.now() - start;
            self._emit({ message: `BullMQ failed: ${job.queueName}/${job.name} — ${err.message}`, layer: LogLayer.INFRASTRUCTURE, level: LogLevel.ERROR, context: { queueName: job.queueName, jobName: job.name, jobId: job.id, durationMs, exceptionType: err.constructor.name, stackTrace: err.stack } });
            throw err;
          }
        };
      }
    } catch (e) { if (this.cfg.debug) console.error('[SENTINEL] bullmq patch failed:', e); }
  }

  private _tryPatchKafkaJS(): void {
    let Kafka: any;
    try { ({ Kafka } = require('kafkajs')); } catch { return; }
    const self = this;
    try {
      const origProducer = Kafka.prototype.producer?.bind(Kafka.prototype);
      if (origProducer) {
        Kafka.prototype.producer = function (...args: any[]) {
          const producer = origProducer.apply(this, args);
          const origSend = producer.send?.bind(producer);
          if (origSend) {
            producer.send = async (record: any) => {
              const start = Date.now();
              record.messages = (record.messages || []).map((m: any) => ({ ...m, headers: { ...(m.headers || {}), traceparent: buildTraceparent(self.traceId, _gen8Hex()) } }));
              try {
                const result     = await origSend(record);
                const durationMs = Date.now() - start;
                self._emit({ message: `Kafka produce: ${record.topic} (${record.messages?.length} msgs, ${durationMs}ms)`, layer: LogLayer.INFRASTRUCTURE, level: LogLevel.INFO, context: { queueName: record.topic, queueAction: 'produce', messageCount: record.messages?.length, durationMs } });
                return result;
              } catch (err: any) {
                self._emit({ message: `Kafka produce error: ${record.topic} — ${err.message}`, layer: LogLayer.INFRASTRUCTURE, level: LogLevel.ERROR, context: { queueName: record.topic, exceptionType: err.constructor.name, stackTrace: err.stack } });
                throw err;
              }
            };
          }
          return producer;
        };
      }

      const origConsumer = Kafka.prototype.consumer?.bind(Kafka.prototype);
      if (origConsumer) {
        Kafka.prototype.consumer = function (...args: any[]) {
          const consumer = origConsumer.apply(this, args);
          const origRun  = consumer.run?.bind(consumer);
          if (origRun) {
            consumer.run = (opts: any) => {
              const origEach = opts?.eachMessage;
              if (typeof origEach === 'function') {
                opts.eachMessage = async (payload: any) => {
                  const start   = Date.now();
                  const tp      = payload.message?.headers?.traceparent?.toString();
                  let   traceId = self.traceId;
                  if (tp) { const p = parseTraceparent(tp); if (p) traceId = p.traceId; }
                  try {
                    await origEach(payload);
                    const durationMs = Date.now() - start;
                    self._emit({ message: `Kafka consume: ${payload.topic}/${payload.partition} (${durationMs}ms)`, layer: LogLayer.INFRASTRUCTURE, level: LogLevel.INFO, trace_id: traceId, context: { queueName: payload.topic, partition: payload.partition, offset: payload.message?.offset, durationMs } });
                  } catch (err: any) {
                    self._emit({ message: `Kafka consume error: ${payload.topic} — ${err.message}`, layer: LogLayer.INFRASTRUCTURE, level: LogLevel.ERROR, trace_id: traceId, context: { queueName: payload.topic, exceptionType: err.constructor.name, stackTrace: err.stack } });
                    throw err;
                  }
                };
              }
              return origRun(opts);
            };
          }
          return consumer;
        };
      }
    } catch (e) { if (this.cfg.debug) console.error('[SENTINEL] kafkajs patch failed:', e); }
  }

  /* ── Class method wrapping ────────────────────────────────────────────── */

  private _wrapMethod(proto: object, key: string, className: string, layer: LogLayer): void {
    const self = this;
    const orig = (proto as any)[key] as (...args: any[]) => any;

    (proto as any)[key] = function (...args: any[]) {
      const start   = Date.now();
      let   isAsync = false;
      try {
        const result = orig.apply(this, args);
        if (result && typeof (result as any).then === 'function') {
          isAsync = true;
          return (result as Promise<any>)
            .then((val) => {
              self._emit({ message: `${className}.${key} → ok (${Date.now() - start}ms)`, layer, level: LogLevel.INFO, context: { className, functionName: key, durationMs: Date.now() - start, isAsync: true } });
              return val;
            })
            .catch((err: any) => {
              self._emit({ message: `${className}.${key} → error: ${err?.message}`, layer, level: LogLevel.ERROR, context: { className, functionName: key, durationMs: Date.now() - start, isAsync: true, exceptionType: err?.constructor?.name, stackTrace: err?.stack } });
              throw err;
            });
        }
        self._emit({ message: `${className}.${key} → ok (${Date.now() - start}ms)`, layer, level: LogLevel.INFO, context: { className, functionName: key, durationMs: Date.now() - start, isAsync: false } });
        return result;
      } catch (err: any) {
        if (!isAsync) self._emit({ message: `${className}.${key} → threw: ${err?.message}`, layer, level: LogLevel.ERROR, context: { className, functionName: key, durationMs: Date.now() - start, exceptionType: err?.constructor?.name, stackTrace: err?.stack } });
        throw err;
      }
    };
  }
}

/* ── Factory ─────────────────────────────────────────────────────────────── */

export const initSentinel = async (config?: SentinelNodeConfig): Promise<SentinelNode> => {
  const s = new SentinelNode(config);
  await s.hook();
  return s;
};
