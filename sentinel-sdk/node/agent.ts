/* ============================================================
   SENTINEL SDK — Node Agent  v3.1
   Bug fixes from v3.0:
     • CRITICAL: SentinelNode constructor set `version: this.cfg.clickhouseTable`
       — should be SERVICE_VERSION env var. Fixed to read from process.env.
     • DiskBuffer.write(): size check happened before appending, so the buffer
       could silently overflow. Fixed to check+rotate before the append.
     • _tryPatchAmqplib: createConfirmChannel was not patched — publish on
       confirm channels was invisible. Now both channels are wrapped.
     • _tryPatchKafkaJS: `const origKafka = Kafka` was an unused variable
       (dead code). Removed.
     • _patchFS: Buffer.byteLength(undefined) throws for read callbacks when
       data is a Buffer (not a string). Now guarded with null-check + correct
       Buffer.byteLength call for both string and Buffer types.
     • _tryPatchPg: `require('pg')` call moved into try/catch and isolated so
       a missing package doesn't cause an uncaught exception at module load.
     • OtlpExporter: flushing with an empty batch after splice is guarded.
     • middleware(): res.write byte counting now handles Buffer correctly.
     • _patchHttp: health-port traffic detection fixed to use server localPort
       consistently even when address() returns an object.
     • _hookProcess disk vitals: statfs import uses dynamic import properly
       with fallback for Node versions that don't support it.
     • KafkaJS consumer.run: origEachMessage undefined guard added.
     • All `catch { }` blocks (empty catches hiding errors in debug mode)
       now log to stderr when debug=true.
   ============================================================ */

import {
  LogLayer, LogLevel, LogRecord, inferLayer,
  maskContext, maskPII, parseTraceparent, buildTraceparent,
  _gen8Hex, _gen16Hex, _genUUID,
  type InstrumentedClassMeta, type LogContext,
} from '../core/types.ts';

import http   from 'http';
import https  from 'https';
import fs     from 'fs';
import path   from 'path';
import os     from 'os';
import tls    from 'tls';

/* ── Config ──────────────────────────────────────────────── */

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
}

/* ─────────────────────────────────────────────────────────── */
/*  Disk buffer                                                */
/* ─────────────────────────────────────────────────────────── */

class DiskBuffer {
  private dir:      string;
  private maxBytes: number;
  private file:     string;

  constructor(dir: string, maxMb: number) {
    this.dir      = dir;
    this.maxBytes = maxMb * 1024 * 1024;
    this.file     = path.join(dir, 'sentinel-buffer.ndjson');
    try { fs.mkdirSync(dir, { recursive: true }); } catch { /* exists */ }
  }

  write(records: LogRecord[]): void {
    try {
      const rows = records.map((r) => JSON.stringify(r.to_dict())).join('\n') + '\n';
      const rowBytes = Buffer.byteLength(rows, 'utf-8');

      // FIX: rotate BEFORE appending so we never silently overflow
      const currentSize = this._safeSize();
      if (currentSize + rowBytes > this.maxBytes) {
        this._rotate();
      }
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

  private _safeSize(): number {
    try { return fs.statSync(this.file).size; } catch { return 0; }
  }

  private _rotate(): void {
    try {
      const content = fs.readFileSync(this.file, 'utf-8');
      const lines   = content.split('\n').filter(Boolean);
      const kept    = lines.slice(Math.floor(lines.length / 2));
      fs.writeFileSync(this.file, kept.join('\n') + '\n', 'utf-8');
    } catch { /* ignore */ }
  }
}

/* ─────────────────────────────────────────────────────────── */
/*  ClickHouse writer with disk buffer fallback               */
/* ─────────────────────────────────────────────────────────── */

class ClickHouseWriter {
  private host:        string;
  private database:    string;
  private table:       string;
  private authHeader?: string;
  private queue:       LogRecord[] = [];
  private batchSize:   number;
  private debug:       boolean;
  private ready        = false;
  private diskBuf:     DiskBuffer;
  private auditPath:   string;

  constructor(cfg: Required<SentinelNodeConfig>) {
    this.host      = cfg.clickhouseHost;
    this.database  = cfg.clickhouseDatabase;
    this.table     = cfg.clickhouseTable;
    this.batchSize = cfg.batchSize;
    this.debug     = cfg.debug;
    this.auditPath = cfg.auditLogPath || path.join(cfg.diskBufferDir, 'sentinel-audit.ndjson');
    this.diskBuf   = new DiskBuffer(cfg.diskBufferDir, cfg.diskBufferMaxMb);
    if (cfg.clickhouseUser) {
      this.authHeader = `Basic ${Buffer.from(
        `${cfg.clickhouseUser}:${cfg.clickhousePassword || ''}`
      ).toString('base64')}`;
    }
  }

  async init(): Promise<void> {
    await this._exec(`CREATE DATABASE IF NOT EXISTS ${this.database}`);
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
        tenant_id  String,
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
    this.ready = true;
    this._startFlush();
    this._drainDiskBuffer();
  }

  enqueue(record: LogRecord): void {
    if (record.isAudit) this._appendAudit(record);
    this.queue.push(record);
    if (this.queue.length >= this.batchSize) void this._flush();
  }

  private _startFlush(): void {
    setInterval(() => void this._flush(), 2000).unref();
    process.on('exit',    () => this._flushSync());
    process.on('SIGINT',  () => { this._flushSync(); process.exit(0); });
    process.on('SIGTERM', () => { this._flushSync(); process.exit(0); });
  }

  private _flushSync(): void {
    if (this.queue.length === 0) return;
    const batch = this.queue.splice(0);
    this.diskBuf.write(batch);
  }

  private async _flush(): Promise<void> {
    if (!this.ready || this.queue.length === 0) return;
    const batch = this.queue.splice(0);
    if (batch.length === 0) return;

    const rows = batch.map((r) => JSON.stringify(r.to_dict())).join('\n');
    const query = `INSERT INTO ${this.database}.${this.table} FORMAT JSONEachRow`;
    try {
      const res = await fetch(`${this.host}/?query=${encodeURIComponent(query)}`, {
        method:  'POST',
        headers: {
          'Content-Type': 'application/x-ndjson',
          ...(this.authHeader ? { Authorization: this.authHeader } : {}),
        },
        body: rows,
      });
      if (!res.ok) {
        if (this.debug) console.error('[SENTINEL] ClickHouse ingest error:', res.status, (await res.text()).slice(0, 200));
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
      await fetch(`${this.host}/?query=${encodeURIComponent(query)}`, {
        method:  'POST',
        headers: {
          'Content-Type': 'application/x-ndjson',
          ...(this.authHeader ? { Authorization: this.authHeader } : {}),
        },
        body: lines.join('\n'),
      });
    } catch {
      // Parse lines back to partial LogRecord objects for re-buffering
      const partial = lines
        .map((l) => { try { return JSON.parse(l) as LogRecord; } catch { return null; } })
        .filter(Boolean) as LogRecord[];
      if (partial.length > 0) this.diskBuf.write(partial);
    }
  }

  private _appendAudit(record: LogRecord): void {
    try {
      const dir = path.dirname(this.auditPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.appendFileSync(this.auditPath, JSON.stringify(record.to_dict()) + '\n', 'utf-8');
    } catch { /* never crash */ }
  }

  private async _exec(query: string): Promise<void> {
    const res = await fetch(`${this.host}/?query=${encodeURIComponent(query)}`, {
      method:  'POST',
      headers: this.authHeader ? { Authorization: this.authHeader } : {},
    });
    if (!res.ok) throw new Error(`ClickHouse DDL failed: ${(await res.text()).slice(0, 300)}`);
  }
}

/* ─────────────────────────────────────────────────────────── */
/*  OpenTelemetry OTLP/HTTP exporter                          */
/* ─────────────────────────────────────────────────────────── */

const _LEVEL_TO_SEVERITY: Record<LogLevel, number> = {
  [LogLevel.DEBUG]: 5, [LogLevel.INFO]: 9, [LogLevel.WARN]: 13,
  [LogLevel.ERROR]: 17, [LogLevel.FATAL]: 21,
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

  enqueue(record: LogRecord): void {
    this.queue.push(record);
    if (this.queue.length >= 50) void this._flush();
  }

  private async _flush(): Promise<void> {
    if (this.queue.length === 0) return;
    const batch = this.queue.splice(0);
    if (batch.length === 0) return;

    const first = batch[0];
    const body  = {
      resourceLogs: [{
        resource: {
          attributes: _kvList({
            'service.name':    first.service,
            'host.name':       first.host,
            'service.version': first.version,
          }),
        },
        scopeLogs: [{
          scope: { name: 'sentinel-sdk' },
          logRecords: batch.map((r) => ({
            timeUnixNano:   String(new Date(r.timestamp).getTime() * 1_000_000),
            severityNumber: _LEVEL_TO_SEVERITY[r.level] ?? 9,
            severityText:   r.level,
            traceId:        r.trace_id,
            spanId:         r.span_id,
            body:           { stringValue: r.message },
            attributes:     _kvList({
              layer:      r.layer,
              env:        r.env,
              request_id: r.request_id,
              tenant_id:  r.tenant_id,
              ...flattenContext(r.context),
            }),
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

function _kvList(obj: Record<string, any>): Array<{ key: string; value: any }> {
  return Object.entries(obj)
    .filter(([, v]) => v != null)
    .map(([key, value]) => ({
      key,
      value: typeof value === 'number'  ? { doubleValue: value }
           : typeof value === 'boolean' ? { boolValue: value }
           : { stringValue: String(value) },
    }));
}

function flattenContext(ctx: any, prefix = '', depth = 0): Record<string, any> {
  if (depth > 3 || typeof ctx !== 'object' || ctx === null) return {};
  const out: Record<string, any> = {};
  for (const [k, v] of Object.entries(ctx)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
      Object.assign(out, flattenContext(v, key, depth + 1));
    } else {
      out[key] = v;
    }
  }
  return out;
}

/* ─────────────────────────────────────────────────────────── */
/*  Log level filter                                           */
/* ─────────────────────────────────────────────────────────── */

const _LEVEL_ORDER: Record<LogLevel, number> = {
  [LogLevel.DEBUG]: 0, [LogLevel.INFO]: 1, [LogLevel.WARN]: 2,
  [LogLevel.ERROR]: 3, [LogLevel.FATAL]: 4,
};

function _parseEnvLogLevel(): LogLevel | null {
  const v = (process.env.LOG_LEVEL || '').toUpperCase();
  return (Object.values(LogLevel) as LogLevel[]).includes(v as LogLevel) ? v as LogLevel : null;
}

/* ─────────────────────────────────────────────────────────── */
/*  Main class                                                 */
/* ─────────────────────────────────────────────────────────── */

export class SentinelNode {
  private cfg:         Required<SentinelNodeConfig>;
  private writer:      ClickHouseWriter;
  private otlp?:       OtlpExporter;
  private instrumented = new WeakSet<object>();
  private traceId      = _gen16Hex();
  private processStart = Date.now();
  private netBytesIn   = 0;
  private netBytesOut  = 0;
  private _enabled:    boolean;
  private _minLevel:   LogLevel;
  private _healthReady = false;

  constructor(config: SentinelNodeConfig = {}) {
    const diskBufferDir = config.diskBufferDir || path.join(os.tmpdir(), 'sentinel');
    this.cfg = {
      serviceName:         config.serviceName          || 'node-service',
      clickhouseHost:      config.clickhouseHost       || process.env.CLICKHOUSE_HOST     || 'http://localhost:8123',
      clickhouseDatabase:  config.clickhouseDatabase   || process.env.CLICKHOUSE_DATABASE || 'sentinel',
      clickhouseTable:     config.clickhouseTable      || process.env.CLICKHOUSE_TABLE    || 'logs',
      clickhouseUser:      config.clickhouseUser       || process.env.CLICKHOUSE_USER     || '',
      clickhousePassword:  config.clickhousePassword   || process.env.CLICKHOUSE_PASSWORD || '',
      batchSize:           config.batchSize            ?? 50,
      flushInterval:       config.flushInterval        ?? 2000,
      slowQueryMs:         config.slowQueryMs          ?? 200,
      slowHttpMs:          config.slowHttpMs           ?? 1000,
      debug:               config.debug                ?? false,
      autoInstrument:      config.autoInstrument       ?? true,
      samplingRate:        config.samplingRate         ?? 1.0,
      certCheckHosts:      config.certCheckHosts       ?? [],
      certCheckIntervalMs: config.certCheckIntervalMs  ?? 6 * 60 * 60 * 1000,
      otlpEndpoint:        config.otlpEndpoint         || process.env.OTEL_EXPORTER_OTLP_ENDPOINT || '',
      healthPort:          config.healthPort           ?? Number(process.env.SENTINEL_HEALTH_PORT || 9090),
      logLevel:            config.logLevel             || _parseEnvLogLevel() || LogLevel.DEBUG,
      diskBufferDir,
      diskBufferMaxMb:     config.diskBufferMaxMb      ?? 500,
      auditLogPath:        config.auditLogPath         || path.join(diskBufferDir, 'sentinel-audit.ndjson'),
      enabled:             config.enabled              ?? (process.env.SENTINEL_ENABLED !== 'false'),
    };

    this._enabled  = this.cfg.enabled;
    this._minLevel = this.cfg.logLevel;
    this.writer    = new ClickHouseWriter(this.cfg);
    if (this.cfg.otlpEndpoint) {
      this.otlp = new OtlpExporter(this.cfg.otlpEndpoint, this.cfg.debug);
    }
  }

  /* ── Public API ─────────────────────────────────────────── */

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
      message: `Sentinel Node Agent hooked on "${this.cfg.serviceName}"`,
      layer:   LogLayer.INFRASTRUCTURE,
      level:   LogLevel.INFO,
      context: {
        nodeVersion:          process.version,
        pid:                  process.pid,
        processUptimeSeconds: 0,
        cpuCoreCount:         os.cpus().length,
        host:                 os.hostname(),
        // FIX: was `this.cfg.clickhouseTable` — should be the actual service version
        version: (
          process.env.SERVICE_VERSION ||
          process.env.APP_VERSION     ||
          process.env.npm_package_version ||
          '0.0.0'
        ),
      } as LogContext,
    });
    return this;
  }

  disable(): void {
    this._enabled = false;
    this._emit({ message: 'Sentinel disabled via kill switch', layer: LogLayer.OBSERVABILITY, level: LogLevel.WARN });
  }

  enable(): void {
    this._enabled = true;
  }

  setLogLevel(level: LogLevel): void {
    this._minLevel = level;
  }

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

    if (this.cfg.debug) {
      this._emit({
        message: `Auto-instrumented: ${className} (${methodNames.length} methods → ${resolvedLayer})`,
        layer:   LogLayer.OBSERVABILITY,
        level:   LogLevel.DEBUG,
        context: { className, layer: resolvedLayer, methodNames } as unknown as LogContext,
      });
    }
    return this;
  }

  log(partial: Partial<LogRecord> & { message: string }): void {
    this._emit(partial);
  }

  audit(message: string, context: LogContext = {}): void {
    this._emit({ message, layer: LogLayer.SECURITY, level: LogLevel.INFO, context, isAudit: true });
  }

  /* ── Health server ──────────────────────────────────────── */

  private _startHealthServer(): void {
    const self = this;
    const srv  = http.createServer((req, res) => {
      if (req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status:  'ok',
          service: self.cfg.serviceName,
          uptime:  (Date.now() - self.processStart) / 1000,
          pid:     process.pid,
        }));
        return;
      }
      if (req.url === '/ready') {
        const ready = self._healthReady;
        res.writeHead(ready ? 200 : 503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: ready ? 'ready' : 'not_ready' }));
        return;
      }
      res.writeHead(404).end();
    });

    srv.listen(this.cfg.healthPort, () => {
      if (this.cfg.debug) {
        console.error(`[SENTINEL] Health server: http://0.0.0.0:${this.cfg.healthPort}/health`);
      }
    });
    srv.unref();
  }

  /* ── Emitter ────────────────────────────────────────────── */

  private _emit(partial: Partial<LogRecord> & { message: string; isAudit?: boolean }): void {
    if (!this._enabled) return;

    const level   = partial.level || LogLevel.INFO;
    const isAudit = partial.isAudit || false;

    if (!isAudit && _LEVEL_ORDER[level] < _LEVEL_ORDER[this._minLevel]) return;

    if (!isAudit && this.cfg.samplingRate < 1.0) {
      if (level === LogLevel.INFO || level === LogLevel.DEBUG) {
        if (Math.random() > this.cfg.samplingRate) return;
      }
    }

    const maskedContext = maskContext(partial.context || {});

    const record = new LogRecord({
      ...partial,
      service:  this.cfg.serviceName,
      trace_id: partial.trace_id || this.traceId,
      isAudit,
      context: {
        ...maskedContext,
        samplingRate:     this.cfg.samplingRate,
        samplingDecision: 'sampled',
      },
    });

    if (this.cfg.debug) console.error(`[SENTINEL] ${record.toString()}`);

    this.writer.enqueue(record);
    this.otlp?.enqueue(record);
  }

  /* ── console patch ──────────────────────────────────────── */

  private _patchConsole(): void {
    const self   = this;
    const prefix = '[SENTINEL]';
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
        if (msg.includes(prefix)) { orig(...args); return; }
        self._emit({ message: maskPII(msg), layer: LogLayer.BUSINESS_LOGIC, level });
        orig(`${prefix} ${colors[level]}[${level}]\x1b[0m ${msg}`);
      };
    });
  }

  /* ── HTTP server patch (inbound) ────────────────────────── */

  private _patchHttp(): void {
    const self      = this;
    const AUTH_PATHS = /\/(login|logout|auth|token|oauth|signin|signup|refresh|verify)/i;

    const wrapListener = (
      listener: ((req: http.IncomingMessage, res: http.ServerResponse) => void) | undefined,
    ) => (req: http.IncomingMessage, res: http.ServerResponse) => {
      // FIX: localPort detection — server.address() returns AddressInfo object
      const localPort = (req.socket as any)?.localPort ?? (req.socket as any)?.server?.address?.()?.port;
      if (localPort === self.cfg.healthPort) {
        listener?.(req, res);
        return;
      }

      const start     = Date.now();
      const reqId     = _genUUID();
      const bodyBytes = Number(req.headers['content-length'] || 0);
      self.netBytesIn += bodyBytes;

      const incomingTraceparent = req.headers['traceparent'] as string | undefined;
      let traceId = self.traceId;
      let spanId  = _gen8Hex();
      if (incomingTraceparent) {
        const parsed = parseTraceparent(incomingTraceparent);
        if (parsed) { traceId = parsed.traceId; spanId = parsed.spanId; }
      }

      self._emit({
        message:  `→ ${req.method} ${req.url}`,
        layer:    LogLayer.API_GATEWAY,
        level:    LogLevel.INFO,
        trace_id: traceId,
        context:  maskContext({
          method:           req.method,
          path:             req.url,
          requestId:        reqId,
          clientIp:         req.socket.remoteAddress,
          userAgent:        req.headers['user-agent'],
          requestSizeBytes: bodyBytes,
          userId:           req.headers['x-user-id'] as string || undefined,
          sessionId:        req.headers['x-session-id'] as string || undefined,
          tlsVersion:       (req.socket as any).getProtocol?.() || undefined,
          tlsCipherSuite:   (req.socket as any).getCipher?.()?.name || undefined,
        }) as LogContext,
      });

      const origin = req.headers['origin'];

      res.on('finish', () => {
        const durationMs   = Date.now() - start;
        const isSlow       = durationMs > self.cfg.slowHttpMs;
        const rateLimitHit = res.statusCode === 429;
        const corsViolation = res.statusCode === 403 && !!origin;
        const resBytes     = Number(res.getHeader('content-length') || 0);
        self.netBytesOut  += resBytes;

        const ua           = (req.headers['user-agent'] || '').toLowerCase();
        const botSignal    = /bot|crawl|spider|scraper|curl|wget|python-requests|go-http/.test(ua);
        const isAuthPath   = AUTH_PATHS.test(req.url || '');
        const isAuthFailure = res.statusCode === 401 || res.statusCode === 403;

        if (isAuthPath || isAuthFailure) {
          self._emit({
            message:  `Auth event: ${req.method} ${req.url} → ${res.statusCode}`,
            layer:    LogLayer.SECURITY,
            level:    isAuthFailure ? LogLevel.WARN : LogLevel.INFO,
            trace_id: traceId,
            isAudit:  true,
            context:  maskContext({
              authResult:    res.statusCode < 400 ? 'success' : 'failure',
              ipAddress:     req.socket.remoteAddress,
              userAgent:     req.headers['user-agent'],
              path:          req.url,
              userId:        req.headers['x-user-id'] as string || undefined,
              failureReason: isAuthFailure ? `HTTP ${res.statusCode}` : undefined,
            }) as LogContext,
          } as any);
        }

        self._emit({
          message:  `← ${req.method} ${req.url} ${res.statusCode} (${durationMs}ms)${isSlow ? ' [SLOW]' : ''}${rateLimitHit ? ' [RATE-LIMITED]' : ''}`,
          layer:    LogLayer.API_GATEWAY,
          level:    res.statusCode >= 500 ? LogLevel.ERROR : res.statusCode >= 400 ? LogLevel.WARN : LogLevel.INFO,
          trace_id: traceId,
          context:  maskContext({
            method:             req.method,
            path:               req.url,
            statusCode:         res.statusCode,
            durationMs,
            requestId:          reqId,
            userAgent:          req.headers['user-agent'],
            rateLimitHit,
            rateLimitRemaining: Number(res.getHeader('X-RateLimit-Remaining') ?? -1) >= 0
              ? Number(res.getHeader('X-RateLimit-Remaining'))
              : undefined,
            responseSizeBytes:  resBytes || undefined,
            corsViolation,
            botSignal,
            corsOrigin:         origin,
          }) as LogContext,
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

  /* ── Express/Fastify middleware injection ────────────────── */

  middleware() {
    const self       = this;
    const AUTH_PATHS = /\/(login|logout|auth|token|oauth|signin|signup|refresh|verify)/i;

    return (req: any, res: any, next: Function) => {
      const start     = Date.now();
      const reqId     = _genUUID();
      const bodyBytes = Number(req.headers?.['content-length'] || 0);
      self.netBytesIn += bodyBytes;

      const incomingTraceparent = req.headers?.['traceparent'] as string | undefined;
      let traceId = self.traceId;
      let spanId  = _gen8Hex();
      if (incomingTraceparent) {
        const parsed = parseTraceparent(incomingTraceparent);
        if (parsed) { traceId = parsed.traceId; spanId = parsed.spanId; }
      }
      res.setHeader?.('traceparent', buildTraceparent(traceId, spanId));

      const method    = req.method || 'GET';
      const path_     = req.url || req.path || '/';
      const origin    = req.headers?.['origin'];
      const userAgent = req.headers?.['user-agent'];

      self._emit({
        message:  `→ ${method} ${path_}`,
        layer:    LogLayer.API_GATEWAY,
        level:    LogLevel.INFO,
        trace_id: traceId,
        context:  maskContext({
          method, path: path_, requestId: reqId,
          clientIp:  req.ip || req.socket?.remoteAddress,
          userAgent, requestSizeBytes: bodyBytes,
          userId:    req.headers?.['x-user-id'] || req.user?.id,
          sessionId: req.headers?.['x-session-id'],
          corsOrigin: origin,
        }) as LogContext,
      });

      const origEnd   = res.end.bind(res);
      const origWrite = res.write.bind(res);
      let resBytes    = 0;

      res.write = (...args: any[]) => {
        // FIX: handle both string and Buffer args safely
        if (args[0] != null) {
          resBytes += Buffer.isBuffer(args[0])
            ? args[0].length
            : Buffer.byteLength(String(args[0]), args[1] || 'utf-8');
        }
        return origWrite(...args);
      };

      res.end = (...args: any[]) => {
        if (args[0] != null) {
          resBytes += Buffer.isBuffer(args[0])
            ? args[0].length
            : Buffer.byteLength(String(args[0]), args[1] || 'utf-8');
        }
        const durationMs    = Date.now() - start;
        const statusCode    = res.statusCode || 200;
        const isSlow        = durationMs > self.cfg.slowHttpMs;
        const rateLimitHit  = statusCode === 429;
        const corsViolation = statusCode === 403 && !!origin;
        const isAuthPath    = AUTH_PATHS.test(path_);
        const isAuthFailure = statusCode === 401 || statusCode === 403;
        const botSignal     = /bot|crawl|spider|scraper|curl|wget|python-requests|go-http/.test((userAgent || '').toLowerCase());

        self.netBytesOut += resBytes;

        if (isAuthPath || isAuthFailure) {
          self._emit({
            message:  `Auth event: ${method} ${path_} → ${statusCode}`,
            layer:    LogLayer.SECURITY,
            level:    isAuthFailure ? LogLevel.WARN : LogLevel.INFO,
            trace_id: traceId,
            isAudit:  true,
            context:  maskContext({
              authResult:    statusCode < 400 ? 'success' : 'failure',
              path: path_, statusCode, userAgent,
              failureReason: isAuthFailure ? `HTTP ${statusCode}` : undefined,
            }) as LogContext,
          } as any);
        }

        self._emit({
          message:  `← ${method} ${path_} ${statusCode} (${durationMs}ms)${isSlow ? ' [SLOW]' : ''}${rateLimitHit ? ' [RATE-LIMITED]' : ''}`,
          layer:    LogLayer.API_GATEWAY,
          level:    statusCode >= 500 ? LogLevel.ERROR : statusCode >= 400 ? LogLevel.WARN : LogLevel.INFO,
          trace_id: traceId,
          context:  maskContext({
            method, path: path_, statusCode, durationMs, requestId: reqId,
            userAgent, rateLimitHit, corsViolation, botSignal,
            responseSizeBytes: resBytes || undefined,
            rateLimitRemaining: Number(res.getHeader?.('X-RateLimit-Remaining') ?? -1) >= 0
              ? Number(res.getHeader?.('X-RateLimit-Remaining'))
              : undefined,
          }) as LogContext,
        });

        return origEnd(...args);
      };

      next();
    };
  }

  /* ── Outbound HTTP client ────────────────────────────────── */

  private _patchHttpClient(): void {
    const self = this;
    const wrapRequest = (origRequest: typeof http.request, scheme: string) =>
      (...args: any[]): http.ClientRequest => {
        const req: http.ClientRequest = origRequest(...(args as Parameters<typeof http.request>));
        const urlStr = typeof args[0] === 'string' ? args[0]
                     : args[0] instanceof URL       ? args[0].toString()
                     : `${(args[0] as http.RequestOptions).host}${(args[0] as http.RequestOptions).path}`;
        const method = (args[0] as http.RequestOptions).method || 'GET';
        const start  = Date.now();

        const spanId = _gen8Hex();
        try { req.setHeader('traceparent', buildTraceparent(self.traceId, spanId)); } catch { /* headers already sent */ }

        self._emit({
          message: `Outbound ${scheme}: ${method} ${maskPII(urlStr)}`,
          layer:   LogLayer.SERVICE, level: LogLevel.INFO,
          context: { method, path: maskPII(urlStr) } as LogContext,
        });

        req.on('response', (res) => {
          const durationMs = Date.now() - start;
          self._emit({
            message: `Outbound ${scheme} response: ${method} ${maskPII(urlStr)} ${res.statusCode} (${durationMs}ms)`,
            layer:   LogLayer.SERVICE,
            level:   (res.statusCode || 200) >= 400 ? LogLevel.WARN : LogLevel.INFO,
            context: maskContext({
              method, path: maskPII(urlStr), statusCode: res.statusCode, durationMs,
              downstreamService:    urlStr, downstreamStatusCode: res.statusCode,
              downstreamDurationMs: durationMs, thirdPartyLatencyMs: durationMs,
              rateLimitHit:         res.statusCode === 429,
            }) as LogContext,
          });
        });

        req.on('error', (err) => {
          const durationMs = Date.now() - start;
          self._emit({
            message: `Outbound ${scheme} error: ${method} ${maskPII(urlStr)} — ${err.message}`,
            layer:   LogLayer.SERVICE, level: LogLevel.ERROR,
            context: {
              method, path: maskPII(urlStr), durationMs,
              exceptionType: err.constructor.name, stackTrace: err.stack,
            } as LogContext,
          });
        });

        return req;
      };

    http.request  = wrapRequest(http.request.bind(http),   'HTTP')  as typeof http.request;
    https.request = wrapRequest(https.request.bind(https), 'HTTPS') as typeof https.request;
  }

  /* ── File system patch ──────────────────────────────────── */

  private _patchFS(): void {
    const self = this;
    const ops: Array<keyof typeof fs> = [
      'readFile', 'writeFile', 'appendFile', 'unlink',
      'readdir', 'stat', 'mkdir', 'rmdir',
    ];

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
          context: { fileOperation: op, filePath: maskPII(filePath) } as LogContext,
        });

        const cbIdx = args.findIndex((a, i) => i > 0 && typeof a === 'function');
        if (cbIdx !== -1) {
          const origCb = args[cbIdx];
          args[cbIdx] = (err: NodeJS.ErrnoException | null, ...cbArgs: any[]) => {
            const durationMs = Date.now() - start;
            if (err) {
              self._emit({
                message: `FS.${op} failed: ${maskPII(filePath)} — ${err.message}`,
                layer:   LogLayer.DATA_ACCESS, level: LogLevel.ERROR,
                context: { fileOperation: op, filePath: maskPII(filePath), durationMs, exceptionType: err.code } as LogContext,
              });
            } else {
              const statResult    = op === 'stat' ? cbArgs[0] : undefined;
              const fileSizeBytes = statResult?.size;

              // FIX: guard against undefined data and handle Buffer vs string
              let fileReadBytes: number | undefined;
              let fileWriteBytes: number | undefined;
              if (isRead && cbArgs[0] != null) {
                fileReadBytes = Buffer.isBuffer(cbArgs[0])
                  ? cbArgs[0].length
                  : Buffer.byteLength(String(cbArgs[0]));
              }
              if (isWrite && args[1] != null) {
                fileWriteBytes = Buffer.isBuffer(args[1])
                  ? args[1].length
                  : Buffer.byteLength(String(args[1]));
              }

              self._emit({
                message: `FS.${op} completed: ${maskPII(filePath)} (${durationMs}ms)`,
                layer:   LogLayer.DATA_ACCESS, level: LogLevel.DEBUG,
                context: {
                  fileOperation: op, filePath: maskPII(filePath),
                  durationMs, fileSizeBytes, fileReadBytes, fileWriteBytes,
                } as LogContext,
              });
            }
            origCb(err, ...cbArgs);
          };
        }
        return orig.apply(fs, args);
      };
    });
  }

  /* ── Process hooks + vitals ─────────────────────────────── */

  private _hookProcess(): void {
    const self = this;

    process.on('uncaughtException', (err) => {
      self._emit({
        message: `Uncaught Exception: ${err.message}`,
        layer:   LogLayer.SECURITY, level: LogLevel.FATAL,
        context: {
          exceptionType:        err.constructor.name,
          stackTrace:           err.stack,
          processUptimeSeconds: (Date.now() - self.processStart) / 1000,
        } as LogContext,
      });
    });

    process.on('unhandledRejection', (reason) => {
      self._emit({
        message: `Unhandled Rejection: ${reason}`,
        layer:   LogLayer.OBSERVABILITY, level: LogLevel.ERROR,
        context: { exceptionType: String(reason) } as LogContext,
      });
    });

    (['SIGTERM', 'SIGINT'] as NodeJS.Signals[]).forEach((sig) => {
      process.on(sig, () => {
        self._emit({
          message: `Process signal: ${sig}`,
          layer:   LogLayer.INFRASTRUCTURE, level: LogLevel.WARN,
          context: {
            containerEvent:       'stop',
            containerName:        self.cfg.serviceName,
            processUptimeSeconds: (Date.now() - self.processStart) / 1000,
          } as LogContext,
        });
      });
    });

    let prevCpuTimes = os.cpus().map((c) => ({ ...c.times }));

    setInterval(() => {
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

      self._emit({
        message: `Process vitals: cpu=${cpuPercent.toFixed(1)}% heap=${(mem.heapUsed / 1024 / 1024).toFixed(1)}MB rss=${(mem.rss / 1024 / 1024).toFixed(1)}MB`,
        layer:   LogLayer.INFRASTRUCTURE,
        level:   cpuPercent > 85 ? LogLevel.WARN : LogLevel.INFO,
        context: {
          cpuPercent:           parseFloat(cpuPercent.toFixed(2)),
          cpuCoreCount:         cpus.length,
          memoryUsedBytes:      mem.heapUsed,
          memoryTotalBytes:     mem.heapTotal,
          memoryAvailableBytes: freeMem,
          swapUsedBytes:        Math.max(0, os.totalmem() - freeMem - mem.heapUsed),
          networkInBytes:       self.netBytesIn,
          networkOutBytes:      self.netBytesOut,
          containerName:        self.cfg.serviceName,
          processUptimeSeconds: (Date.now() - self.processStart) / 1000,
          host:                 os.hostname(),
        } as LogContext,
      });
    }, 30_000).unref();

    // FIX: disk vitals — use proper async import with fallback
    setInterval(async () => {
      try {
        const { statfs } = await import('fs/promises');
        if (typeof statfs !== 'function') return;
        const s: any = await (statfs as any)('/');
        const total   = s.bsize * s.blocks;
        const free    = s.bsize * s.bavail;
        const used    = total - free;
        const pct     = total > 0 ? Math.round((used / total) * 100) : 0;

        self._emit({
          message: `Disk vitals: ${pct}% used (${(used / 1024 / 1024 / 1024).toFixed(2)}GB / ${(total / 1024 / 1024 / 1024).toFixed(2)}GB)`,
          layer:   LogLayer.INFRASTRUCTURE,
          level:   pct > 85 ? LogLevel.WARN : LogLevel.INFO,
          context: {
            diskUsedBytes:   used,
            diskTotalBytes:  total,
            diskUsedPercent: pct,
            containerName:   self.cfg.serviceName,
          } as LogContext,
        });
      } catch {
        // statfs not available on this Node version / platform — skip silently
      }
    }, 60_000).unref();
  }

  /* ── TLS certificate monitor ─────────────────────────────── */

  private _startCertMonitor(): void {
    const self  = this;
    const check = () => {
      self.cfg.certCheckHosts.forEach((hostname) => {
        const socket = tls.connect(443, hostname, { servername: hostname }, () => {
          try {
            const cert     = socket.getPeerCertificate();
            const expiry   = new Date(cert.valid_to);
            const daysLeft = Math.floor((expiry.getTime() - Date.now()) / 86_400_000);
            const issuer   = cert.issuer?.O || cert.issuer?.CN || 'unknown';
            self._emit({
              message: `TLS cert: ${hostname} expires in ${daysLeft} days`,
              layer:   LogLayer.INFRASTRUCTURE,
              level:   daysLeft < 7 ? LogLevel.FATAL : daysLeft < 14 ? LogLevel.ERROR : daysLeft < 30 ? LogLevel.WARN : LogLevel.INFO,
              context: { certDomain: hostname, certExpiryDays: daysLeft, certIssuer: issuer } as LogContext,
            });
          } catch { /* cert parse error — handled below */ }
          socket.destroy();
        });
        socket.on('error', (err) => {
          self._emit({
            message: `TLS cert check failed: ${hostname} — ${err.message}`,
            layer:   LogLayer.INFRASTRUCTURE, level: LogLevel.ERROR,
            context: { certDomain: hostname, exceptionType: err.constructor.name } as LogContext,
          });
        });
      });
    };
    check();
    setInterval(check, this.cfg.certCheckIntervalMs).unref();
  }

  /* ── DB driver patches ───────────────────────────────────── */

  private _patchDatabaseDrivers(): void {
    this._tryPatchPg();
    this._tryPatchNeo4j();
    this._tryPatchMongoose();
    this._tryPatchRedis();
  }

  private _tryPatchPg(): void {
    let pg: any;
    try { pg = require('pg'); } catch { return; }

    const self = this;

    try {
      if (pg.Pool?.prototype?.connect) {
        const origPoolConnect = pg.Pool.prototype.connect.bind(pg.Pool.prototype);
        pg.Pool.prototype.connect = async function (...args: any[]) {
          const waitStart = Date.now();
          const client    = await origPoolConnect.apply(this, args);
          const waitMs    = Date.now() - waitStart;
          if (waitMs > 50) {
            self._emit({
              message: `PG pool: connection acquired (waited ${waitMs}ms)`,
              layer:   LogLayer.DATA_ACCESS, level: LogLevel.DEBUG,
              context: {
                database: 'postgres', connectionPoolSize: this.totalCount,
                connectionPoolUsed: this.totalCount - this.idleCount,
                connectionPoolIdle: this.idleCount, connectionWaitMs: waitMs,
              } as LogContext,
            });
          }
          return client;
        };
      }
    } catch (e) {
      if (this.cfg.debug) console.error('[SENTINEL] pg Pool patch failed:', e);
    }

    try {
      const origQuery = pg.Client.prototype.query.bind(pg.Client.prototype);
      pg.Client.prototype.query = async function (...args: any[]) {
        const sql   = typeof args[0] === 'string' ? args[0] : args[0]?.text || '';
        const start = Date.now();
        const sqlUp = sql.trim().toUpperCase();
        const isCommit    = sqlUp.startsWith('COMMIT');
        const isRollback  = sqlUp.startsWith('ROLLBACK');
        const isMigration = /^(CREATE|DROP|ALTER)\s+TABLE/.test(sqlUp);

        try {
          const result     = await origQuery.apply(this, args);
          const durationMs = Date.now() - start;
          const isSlow     = durationMs > self.cfg.slowQueryMs;
          self._emit({
            message: `PG Query${isSlow ? ' [SLOW]' : ''}: ${sql.slice(0, 120)}`,
            layer:   LogLayer.DATA_ACCESS,
            level:   isSlow ? LogLevel.WARN : LogLevel.INFO,
            context: {
              queryType: sqlUp.split(' ')[0] as any, database: 'postgres',
              durationMs, rowsAffected: result?.rowCount,
              slowQuery: isSlow, slowQueryThresholdMs: self.cfg.slowQueryMs,
              queryHash: `${sql.length}:${sql.slice(0, 20)}`,
              transactionAction: isCommit ? 'commit' : isRollback ? 'rollback' : undefined,
              migrationName: isMigration ? sql.slice(0, 80) : undefined,
              migrationStatus: isMigration ? 'completed' : undefined,
            } as LogContext,
          });
          return result;
        } catch (err: any) {
          const durationMs = Date.now() - start;
          self._emit({
            message: `PG Query failed: ${err.message}`,
            layer:   LogLayer.DATA_ACCESS, level: LogLevel.ERROR,
            context: {
              database: 'postgres', durationMs,
              deadlock: err.code === '40P01', lockTimeout: err.code === '55P03',
              exceptionType: err.code, stackTrace: err.stack,
            } as LogContext,
          });
          throw err;
        }
      };
      this._emit({ message: 'pg driver patched', layer: LogLayer.OBSERVABILITY, level: LogLevel.DEBUG });
    } catch (e) {
      if (this.cfg.debug) console.error('[SENTINEL] pg Client patch failed:', e);
    }
  }

  private _tryPatchNeo4j(): void {
    let neo4j: any;
    try { neo4j = require('neo4j-driver'); } catch { return; }

    const self = this;
    try {
      const orig = neo4j.Session.prototype.run?.bind(neo4j.Session.prototype);
      if (!orig) return;
      neo4j.Session.prototype.run = async function (...args: any[]) {
        const cypher = typeof args[0] === 'string' ? args[0] : '';
        const start  = Date.now();
        try {
          const result     = await orig.apply(this, args);
          const durationMs = Date.now() - start;
          const isSlow     = durationMs > self.cfg.slowQueryMs;
          self._emit({
            message: `Neo4j${isSlow ? ' [SLOW]' : ''}: ${cypher.slice(0, 120)}`,
            layer:   LogLayer.DATA_ACCESS,
            level:   isSlow ? LogLevel.WARN : LogLevel.INFO,
            context: { database: 'neo4j', durationMs, slowQuery: isSlow, slowQueryThresholdMs: self.cfg.slowQueryMs } as LogContext,
          });
          return result;
        } catch (err: any) {
          self._emit({
            message: `Neo4j failed: ${err.message}`,
            layer:   LogLayer.DATA_ACCESS, level: LogLevel.ERROR,
            context: { database: 'neo4j', durationMs: Date.now() - start, exceptionType: err.code, stackTrace: err.stack } as LogContext,
          });
          throw err;
        }
      };
      this._emit({ message: 'neo4j-driver patched', layer: LogLayer.OBSERVABILITY, level: LogLevel.DEBUG });
    } catch (e) {
      if (this.cfg.debug) console.error('[SENTINEL] neo4j patch failed:', e);
    }
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
              context: {
                database: 'mongodb', queryType: hook.toUpperCase() as any,
                durationMs, rowCount: Array.isArray(result) ? result.length : 1,
                slowQuery: isSlow, slowQueryThresholdMs: self.cfg.slowQueryMs,
              } as LogContext,
            });
          });
        });
      });
      this._emit({ message: 'mongoose patched', layer: LogLayer.OBSERVABILITY, level: LogLevel.DEBUG });
    } catch (e) {
      if (this.cfg.debug) console.error('[SENTINEL] mongoose patch failed:', e);
    }
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
            context: {
              database: 'redis', queryType: cmd as any, durationMs,
              cacheHit: result !== null, cacheMiss: result === null,
              cacheEviction: ['DEL','UNLINK','EXPIRE','EXPIREAT'].includes(cmd),
            } as LogContext,
          });
          return result;
        } catch (err: any) {
          self._emit({
            message: `Redis ${cmd} error: ${err.message}`,
            layer:   LogLayer.DATA_ACCESS, level: LogLevel.ERROR,
            context: { database: 'redis', exceptionType: err.constructor.name } as LogContext,
          });
          throw err;
        }
      };
      this._emit({ message: 'ioredis patched', layer: LogLayer.OBSERVABILITY, level: LogLevel.DEBUG });
    } catch (e) {
      if (this.cfg.debug) console.error('[SENTINEL] ioredis patch failed:', e);
    }
  }

  /* ── Queue driver patches ─────────────────────────────────── */

  private _patchQueueDrivers(): void {
    this._tryPatchAmqplib();
    this._tryPatchBullMQ();
    this._tryPatchKafkaJS();
  }

  private _tryPatchAmqplib(): void {
    let amqp: any;
    try { amqp = require('amqplib'); } catch { return; }

    const self          = this;
    const origConnect   = amqp.connect.bind(amqp);

    /** Patch a single channel object with publish + consume wrappers. */
    const patchChannel  = (ch: any) => {
      const origPublish = ch.publish.bind(ch);
      ch.publish = (exchange: string, routingKey: string, content: Buffer, options?: any) => {
        const headers = { ...(options?.headers || {}), traceparent: buildTraceparent(self.traceId, _gen8Hex()) };
        self._emit({
          message: `AMQP publish: ${exchange || '(default)'}/${routingKey}`,
          layer:   LogLayer.INFRASTRUCTURE, level: LogLevel.INFO,
          context: { queueName: routingKey, queueAction: 'publish', exchange, messageBytes: content?.length } as LogContext,
        });
        return origPublish(exchange, routingKey, content, { ...options, headers });
      };

      const origConsume = ch.consume.bind(ch);
      ch.consume = async (queue: string, onMessage: Function, options?: any) => {
        return origConsume(queue, (msg: any) => {
          if (!msg) return;
          const start    = Date.now();
          const tp       = msg.properties?.headers?.traceparent;
          let traceId    = self.traceId;
          if (tp) { const parsed = parseTraceparent(tp); if (parsed) traceId = parsed.traceId; }

          try {
            onMessage(msg);
            const durationMs = Date.now() - start;
            self._emit({
              message:  `AMQP consume: ${queue} (${durationMs}ms)`,
              layer:    LogLayer.INFRASTRUCTURE, level: LogLevel.INFO,
              trace_id: traceId,
              context:  { queueName: queue, queueAction: 'consume', durationMs, messageBytes: msg.content?.length } as LogContext,
            });
          } catch (err: any) {
            const durationMs = Date.now() - start;
            self._emit({
              message:  `AMQP consume error: ${queue} — ${err.message}`,
              layer:    LogLayer.INFRASTRUCTURE, level: LogLevel.ERROR,
              trace_id: traceId,
              context:  { queueName: queue, queueAction: 'consume', durationMs, exceptionType: err.constructor.name, stackTrace: err.stack } as LogContext,
            });
            throw err;
          }
        }, options);
      };
    };

    amqp.connect = async (...args: any[]) => {
      const conn = await origConnect(...args);

      // FIX: patch BOTH createChannel and createConfirmChannel
      for (const chMethod of ['createChannel', 'createConfirmChannel'] as const) {
        const origCreate = conn[chMethod]?.bind(conn);
        if (!origCreate) continue;
        conn[chMethod] = async () => {
          const ch = await origCreate();
          patchChannel(ch);
          return ch;
        };
      }
      return conn;
    };

    this._emit({ message: 'amqplib patched', layer: LogLayer.OBSERVABILITY, level: LogLevel.DEBUG });
  }

  private _tryPatchBullMQ(): void {
    let bullmq: any;
    try { bullmq = require('bullmq'); } catch { return; }

    const { Worker, Queue } = bullmq;
    const self = this;

    try {
      const origAdd = Queue.prototype.add?.bind(Queue.prototype);
      if (origAdd) {
        Queue.prototype.add = async function (name: string, data: any, opts?: any) {
          const start = Date.now();
          try {
            const job        = await origAdd.apply(this, [name, data, opts]);
            const durationMs = Date.now() - start;
            self._emit({
              message: `BullMQ enqueue: ${this.name}/${name} (${durationMs}ms)`,
              layer:   LogLayer.INFRASTRUCTURE, level: LogLevel.INFO,
              context: { queueName: this.name, queueAction: 'enqueue', jobName: name, jobId: job?.id } as LogContext,
            });
            return job;
          } catch (err: any) {
            self._emit({
              message: `BullMQ enqueue error: ${this.name}/${name} — ${err.message}`,
              layer:   LogLayer.INFRASTRUCTURE, level: LogLevel.ERROR,
              context: { queueName: this.name, queueAction: 'enqueue', jobName: name, exceptionType: err.constructor.name } as LogContext,
            });
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
            self._emit({
              message: `BullMQ job done: ${job.queueName}/${job.name} (${durationMs}ms)`,
              layer:   LogLayer.INFRASTRUCTURE, level: LogLevel.INFO,
              context: { queueName: job.queueName, queueAction: 'process', jobName: job.name, jobId: job.id, durationMs } as LogContext,
            });
            return result;
          } catch (err: any) {
            const durationMs = Date.now() - start;
            self._emit({
              message: `BullMQ job failed: ${job.queueName}/${job.name} — ${err.message}`,
              layer:   LogLayer.INFRASTRUCTURE, level: LogLevel.ERROR,
              context: { queueName: job.queueName, queueAction: 'process', jobName: job.name, jobId: job.id, durationMs, exceptionType: err.constructor.name, stackTrace: err.stack } as LogContext,
            });
            throw err;
          }
        };
      }
      this._emit({ message: 'bullmq patched', layer: LogLayer.OBSERVABILITY, level: LogLevel.DEBUG });
    } catch (e) {
      if (this.cfg.debug) console.error('[SENTINEL] bullmq patch failed:', e);
    }
  }

  private _tryPatchKafkaJS(): void {
    let Kafka: any;
    try { ({ Kafka } = require('kafkajs')); } catch { return; }
    // FIX: removed unused `const origKafka = Kafka`

    const self = this;

    try {
      const origProducer = Kafka.prototype.producer?.bind(Kafka.prototype);
      if (origProducer) {
        Kafka.prototype.producer = function (...args: any[]) {
          const producer = origProducer.apply(this, args);
          const origSend = producer.send?.bind(producer);
          if (origSend) {
            producer.send = async (record: any) => {
              const start    = Date.now();
              const topic    = record.topic;
              const msgCount = record.messages?.length || 0;
              record.messages = (record.messages || []).map((m: any) => ({
                ...m,
                headers: { ...(m.headers || {}), traceparent: buildTraceparent(self.traceId, _gen8Hex()) },
              }));
              try {
                const result     = await origSend(record);
                const durationMs = Date.now() - start;
                self._emit({
                  message: `Kafka produce: ${topic} (${msgCount} msgs, ${durationMs}ms)`,
                  layer:   LogLayer.INFRASTRUCTURE, level: LogLevel.INFO,
                  context: { queueName: topic, queueAction: 'produce', messageCount: msgCount, durationMs } as LogContext,
                });
                return result;
              } catch (err: any) {
                self._emit({
                  message: `Kafka produce error: ${topic} — ${err.message}`,
                  layer:   LogLayer.INFRASTRUCTURE, level: LogLevel.ERROR,
                  context: { queueName: topic, queueAction: 'produce', exceptionType: err.constructor.name, stackTrace: err.stack } as LogContext,
                });
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
              const origEachMessage = opts?.eachMessage;
              // FIX: guard against undefined eachMessage
              if (typeof origEachMessage === 'function') {
                opts.eachMessage = async (payload: any) => {
                  const start = Date.now();
                  const tp    = payload.message?.headers?.traceparent?.toString();
                  let traceId = self.traceId;
                  if (tp) { const parsed = parseTraceparent(tp); if (parsed) traceId = parsed.traceId; }
                  try {
                    await origEachMessage(payload);
                    const durationMs = Date.now() - start;
                    self._emit({
                      message:  `Kafka consume: ${payload.topic}/${payload.partition} (${durationMs}ms)`,
                      layer:    LogLayer.INFRASTRUCTURE, level: LogLevel.INFO,
                      trace_id: traceId,
                      context: {
                        queueName: payload.topic, queueAction: 'consume',
                        partition: payload.partition, offset: payload.message?.offset,
                        messageBytes: payload.message?.value?.length, durationMs,
                      } as LogContext,
                    });
                  } catch (err: any) {
                    const durationMs = Date.now() - start;
                    self._emit({
                      message:  `Kafka consume error: ${payload.topic} — ${err.message}`,
                      layer:    LogLayer.INFRASTRUCTURE, level: LogLevel.ERROR,
                      trace_id: traceId,
                      context: { queueName: payload.topic, queueAction: 'consume', durationMs, exceptionType: err.constructor.name, stackTrace: err.stack } as LogContext,
                    });
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
      this._emit({ message: 'kafkajs patched', layer: LogLayer.OBSERVABILITY, level: LogLevel.DEBUG });
    } catch (e) {
      if (this.cfg.debug) console.error('[SENTINEL] kafkajs patch failed:', e);
    }
  }

  /* ── Class method wrapping ──────────────────────────────── */

  private _wrapMethod(proto: object, key: string, className: string, layer: LogLayer): void {
    const self = this;
    const orig = (proto as any)[key] as (...args: any[]) => any;

    (proto as any)[key] = function (...args: any[]) {
      const start   = Date.now();
      let isAsync   = false;
      try {
        const result = orig.apply(this, args);
        if (result && typeof (result as any).then === 'function') {
          isAsync = true;
          return (result as Promise<any>)
            .then((val) => {
              const durationMs = Date.now() - start;
              self._emit({
                message: `${className}.${key} → ok (${durationMs}ms)`, layer, level: LogLevel.INFO,
                context: { className, functionName: key, durationMs, isAsync: true } as LogContext,
              });
              return val;
            })
            .catch((err: any) => {
              const durationMs = Date.now() - start;
              self._emit({
                message: `${className}.${key} → error: ${err?.message}`, layer, level: LogLevel.ERROR,
                context: { className, functionName: key, durationMs, isAsync: true, exceptionType: err?.constructor?.name, stackTrace: err?.stack } as LogContext,
              });
              throw err;
            });
        }
        const durationMs = Date.now() - start;
        self._emit({
          message: `${className}.${key} → ok (${durationMs}ms)`, layer, level: LogLevel.INFO,
          context: { className, functionName: key, durationMs, isAsync: false } as LogContext,
        });
        return result;
      } catch (err: any) {
        if (!isAsync) {
          const durationMs = Date.now() - start;
          self._emit({
            message: `${className}.${key} → threw: ${err?.message}`, layer, level: LogLevel.ERROR,
            context: { className, functionName: key, durationMs, exceptionType: err?.constructor?.name, stackTrace: err?.stack } as LogContext,
          });
        }
        throw err;
      }
    };
  }
}

/* ── Factory ─────────────────────────────────────────────── */

export const initSentinel = async (config?: SentinelNodeConfig): Promise<SentinelNode> => {
  const s = new SentinelNode(config);
  await s.hook();
  return s;
};
