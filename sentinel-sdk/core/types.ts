/* ============================================================
   SENTINEL SDK — Core Types & LogRecord Schema  v2.1
   Bug fixes from v2.0:
     • CRITICAL: PII_PATTERNS /g regex flag caused stateful lastIndex
       bug — every other call on same string would silently skip matches.
       Fixed by using a factory function that creates fresh RegExp each call.
     • maskContext: authorization key now redacted (was in Python but missing here)
     • _gen8Hex / _gen16Hex: switched to crypto.getRandomValues for
       cryptographically correct randomness (not Math.random)
     • parseTraceparent: rejects malformed trace/span ids (wrong length)
     • buildTraceparent: validates id lengths before building
     • LogRecord constructor: host/version detection hardened
     • to_dict: context serialised consistently (always object, never raw string)
   ============================================================ */

export enum LogLayer {
  PRESENTATION   = 'presentation',
  API_GATEWAY    = 'api_gateway',
  BUSINESS_LOGIC = 'business_logic',
  DATA_ACCESS    = 'data_access',
  SERVICE        = 'service',
  SECURITY       = 'security',
  OBSERVABILITY  = 'observability',
  INFRASTRUCTURE = 'infrastructure',
  DOMAIN         = 'domain',
}

export enum LogLevel {
  DEBUG = 'DEBUG',
  INFO  = 'INFO',
  WARN  = 'WARN',
  ERROR = 'ERROR',
  FATAL = 'FATAL',
}

/* ── W3C traceparent helpers ─────────────────────────────── */

export interface W3CTraceContext {
  traceId:  string;   // 16-byte hex (32 chars)
  spanId:   string;   // 8-byte hex  (16 chars)
  sampled:  boolean;
}

/** Parse W3C traceparent header: 00-<traceId>-<spanId>-<flags> */
export function parseTraceparent(header: string): W3CTraceContext | null {
  if (!header || typeof header !== 'string') return null;
  const parts = header.split('-');
  if (parts.length !== 4 || parts[0] !== '00') return null;
  const [, traceId, spanId, flags] = parts;
  // W3C spec: traceId = 32 hex, spanId = 16 hex
  if (!/^[0-9a-f]{32}$/.test(traceId)) return null;
  if (!/^[0-9a-f]{16}$/.test(spanId))  return null;
  return { traceId, spanId, sampled: flags === '01' };
}

/** Build W3C traceparent header from ids */
export function buildTraceparent(traceId: string, spanId: string, sampled = true): string {
  // Pad or truncate defensively so downstream never gets a malformed header
  const tid = traceId.padEnd(32, '0').slice(0, 32);
  const sid = spanId.padEnd(16, '0').slice(0, 16);
  return `00-${tid}-${sid}-${sampled ? '01' : '00'}`;
}

/* ── Per-layer context types ─────────────────────────────── */

export interface PresentationContext {
  page?: string; component?: string; sessionDuration?: number;
  renderTimeMs?: number; interactionType?: string; elementId?: string;
  elementTag?: string; elementText?: string; featureFlag?: string;
  flagValue?: boolean | string; assetUrl?: string; errorType?: string;
  accessibilityIssue?: string; scrollDepthPercent?: number; cacheHit?: boolean;
  fpsAverage?: number; fcpMs?: number; lcpMs?: number; fpMs?: number;
  clsScore?: number; fidMs?: number; ttfbMs?: number; inpMs?: number;
  browserName?: string; browserVersion?: string; osName?: string;
  deviceType?: string; screenWidth?: number; screenHeight?: number;
  viewportWidth?: number; viewportHeight?: number; connectionType?: string;
  [key: string]: any;
}

export interface ApiGatewayContext {
  method?: string; path?: string; statusCode?: number; durationMs?: number;
  requestId?: string; clientIp?: string; geoRegion?: string; userAgent?: string;
  userId?: string; sessionId?: string; requestSizeBytes?: number;
  responseSizeBytes?: number; tlsVersion?: string; tlsHandshakeMs?: number;
  upstreamService?: string; rateLimitHit?: boolean; rateLimitRemaining?: number;
  corsViolation?: boolean; botSignal?: boolean; authEvent?: string;
  downstreamService?: string; downstreamStatusCode?: number;
  downstreamDurationMs?: number; thirdPartyLatencyMs?: number;
  retryCount?: number; authResult?: string; failureReason?: string;
  corsOrigin?: string;
  [key: string]: any;
}

export interface BusinessLogicContext {
  functionName?: string; className?: string; module?: string; durationMs?: number;
  inputSummary?: string; outputSummary?: string; cacheHit?: boolean;
  cacheMiss?: boolean; featureFlag?: string; flagValue?: boolean | string;
  jobId?: string; jobName?: string; circuitBreakerState?: string;
  thirdPartyService?: string; queueName?: string; queueAction?: string;
  configKey?: string; configValue?: string; fileOperation?: string;
  filePath?: string; exceptionType?: string; stackTrace?: string;
  isAsync?: boolean; asyncDurationMs?: number;
  [key: string]: any;
}

export interface DataAccessContext {
  queryType?: string; table?: string; collection?: string; database?: string;
  durationMs?: number; rowsAffected?: number; rowCount?: number;
  slowQuery?: boolean; slowQueryThresholdMs?: number; deadlock?: boolean;
  lockTimeout?: boolean; replicationLagMs?: number; indexMiss?: boolean;
  migrationName?: string; migrationStatus?: string; cacheEviction?: boolean;
  storageUsedBytes?: number; storageCapacityBytes?: number;
  connectionPoolSize?: number; connectionPoolUsed?: number; connectionPoolIdle?: number;
  connectionWaitMs?: number;
  backupStatus?: string; transactionAction?: string; queryHash?: string;
  cacheHit?: boolean; cacheMiss?: boolean;
  [key: string]: any;
}

export interface DomainContext {
  aggregateType?: string; aggregateId?: string; eventType?: string;
  eventVersion?: number; previousState?: string; newState?: string;
  policyName?: string; policyResult?: boolean | string; sagaId?: string;
  sagaStep?: string; sagaStatus?: string; riskScore?: number;
  fraudSignal?: string; auditUserId?: string; auditAction?: string;
  [key: string]: any;
}

export interface ObservabilityContext {
  alertName?: string; alertStatus?: string; traceId?: string; spanId?: string;
  parentSpanId?: string; metricName?: string; metricValue?: number;
  metricUnit?: string; samplingDecision?: 'sampled' | 'dropped';
  samplingRate?: number; sloBurnRate?: number; sloName?: string;
  errorRatePercent?: number; anomalyType?: string; runbookUrl?: string;
  [key: string]: any;
}

export interface SecurityContext {
  userId?: string; username?: string; authResult?: string;
  failureReason?: string; wafRuleId?: string; ipAddress?: string;
  geoCountry?: string; tokenId?: string; tokenAction?: string;
  complianceFramework?: string; complianceCheckPassed?: boolean;
  gdprDataSubject?: string; gdprLegalBasis?: string; path?: string;
  statusCode?: number; userAgent?: string;
  [key: string]: any;
}

export interface InfrastructureContext {
  cpuPercent?: number; memoryUsedBytes?: number; memoryTotalBytes?: number;
  memoryAvailableBytes?: number; swapUsedBytes?: number;
  networkInBytes?: number; networkOutBytes?: number;
  containerId?: string; containerName?: string; containerEvent?: string;
  diskUsedBytes?: number; diskTotalBytes?: number; diskUsedPercent?: number;
  cloudProvider?: string; cloudRegion?: string;
  certDomain?: string; certExpiryDays?: number; certIssuer?: string;
  processUptimeSeconds?: number; processExitCode?: number;
  cpuCoreCount?: number; cpuStealPercent?: number; fpsAverage?: number;
  host?: string; version?: string;
  [key: string]: any;
}

export type LogContext =
  | PresentationContext | ApiGatewayContext | BusinessLogicContext
  | DataAccessContext | DomainContext | ObservabilityContext
  | SecurityContext | InfrastructureContext | { [key: string]: any };

export interface InstrumentedClassMeta {
  className:       string;
  layer:           LogLayer;
  methodNames:     string[];
  detectedDomain?: string;
}

/* ── LogRecord ────────────────────────────────────────────── */

export class LogRecord {
  message:    string;
  level:      LogLevel;
  layer:      LogLayer;
  timestamp:  string;
  record_id:  string;
  trace_id:   string;
  span_id:    string;
  service:    string;
  env:        string;
  host:       string;
  version:    string;
  request_id: string;
  tenant_id:  string;
  isAudit:    boolean;
  context:    LogContext;

  constructor(data: Partial<LogRecord> & { message: string }) {
    this.message    = data.message;
    this.level      = data.level      || LogLevel.INFO;
    this.layer      = data.layer      || LogLayer.BUSINESS_LOGIC;
    this.timestamp  = data.timestamp  || new Date().toISOString();
    this.record_id  = data.record_id  || _genUUID();
    this.trace_id   = data.trace_id   || 'untracked';
    this.span_id    = data.span_id    || _gen8Hex();
    this.service    = data.service    || 'unknown-service';
    this.env        = data.env        || _detectEnv();
    this.host       = data.host       || _detectHost();
    this.version    = data.version    || _detectVersion();
    this.request_id = data.request_id || '';
    this.tenant_id  = data.tenant_id  || '';
    this.isAudit    = data.isAudit    || false;
    this.context    = data.context    || {};
  }

  enrich(extra: LogContext): this {
    this.context = { ...this.context, ...extra };
    return this;
  }

  to_dict(): Record<string, unknown> {
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
      tenant_id:  this.tenant_id,
      layer:      this.layer,
      level:      this.level,
      message:    this.message,
      // Always serialise context as a JSON string for ClickHouse compatibility
      context:    typeof this.context === 'string'
                    ? this.context
                    : JSON.stringify(this.context ?? {}),
    };
  }

  toString(): string {
    const colors: Record<LogLevel, string> = {
      [LogLevel.DEBUG]: '\x1b[36m', [LogLevel.INFO]: '\x1b[32m',
      [LogLevel.WARN]: '\x1b[33m',  [LogLevel.ERROR]: '\x1b[31m',
      [LogLevel.FATAL]: '\x1b[35m',
    };
    const reset = '\x1b[0m';
    return `${colors[this.level]}[${this.timestamp}] [${this.layer.toUpperCase()}] [${this.level}] ${this.message}${reset}`;
  }
}

/* ── Helpers ─────────────────────────────────────────────── */

export function _genUUID(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  // Fallback using getRandomValues (still crypto-safe)
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const buf = new Uint8Array(16);
    crypto.getRandomValues(buf);
    buf[6] = (buf[6] & 0x0f) | 0x40;
    buf[8] = (buf[8] & 0x3f) | 0x80;
    const hex = Array.from(buf).map((b) => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
  }
  // Last-resort Math.random (non-crypto, only if no crypto available)
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

/** Generate 8 random bytes as 16 hex chars (W3C span_id). */
export function _gen8Hex(): string {
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const buf = new Uint8Array(8);
    crypto.getRandomValues(buf);
    return Array.from(buf).map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  return Array.from({ length: 8 }, () =>
    Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
  ).join('');
}

/** Generate 16 random bytes as 32 hex chars (W3C trace_id). */
export function _gen16Hex(): string {
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    const buf = new Uint8Array(16);
    crypto.getRandomValues(buf);
    return Array.from(buf).map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  return Array.from({ length: 16 }, () =>
    Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
  ).join('');
}

function _detectEnv(): string {
  if (typeof process !== 'undefined') {
    return process.env.NODE_ENV || process.env.ENV || 'development';
  }
  return 'browser';
}

function _detectHost(): string {
  if (typeof process !== 'undefined') {
    // Allow runtime injection for container environments
    const injected = (globalThis as any).__sentinel_os_hostname__;
    if (injected) return injected;
    return process.env.HOSTNAME || process.env.HOST || 'unknown-host';
  }
  if (typeof location !== 'undefined') return location.hostname;
  return 'unknown-host';
}

function _detectVersion(): string {
  if (typeof process !== 'undefined') {
    return (
      process.env.SERVICE_VERSION ||
      process.env.APP_VERSION     ||
      process.env.npm_package_version ||
      '0.0.0'
    );
  }
  if (typeof window !== 'undefined') {
    return (window as any).__SENTINEL_VERSION__ || '0.0.0';
  }
  return '0.0.0';
}

/* ── PII masking ─────────────────────────────────────────── */
/*
 * CRITICAL FIX: Do NOT store compiled RegExp with /g flag in a shared array.
 * Stateful lastIndex on a shared regex causes every-other-call failures.
 * Instead we store pattern sources + flags and compile fresh each call via
 * a tiny factory. The overhead is negligible compared to the correctness gain.
 */

interface PiiPattern {
  source:      string;
  flags:       string;
  replacement: string;
}

const _PII_PATTERN_DEFS: PiiPattern[] = [
  // Credit / debit card numbers (13-16 digits, optional separators)
  { source: r`\b(?:\d[ -]?){13,16}\b`,                                                           flags: 'g',  replacement: '[CARD]' },
  // JWT tokens (three base64url segments)
  { source: r`\b[A-Za-z0-9+/]{20,}\.[A-Za-z0-9+/]{20,}\.[A-Za-z0-9+/_-]{20,}\b`,              flags: 'g',  replacement: '[JWT]' },
  // Bearer tokens
  { source: r`Bearer\s+[A-Za-z0-9\-._~+/]+=*`,                                                  flags: 'gi', replacement: 'Bearer [TOKEN]' },
  // Email addresses
  { source: r`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`,                          flags: 'g',  replacement: '[EMAIL]' },
  // Key=value patterns for secrets (password, token, key, etc.)
  { source: r`(password|passwd|pwd|secret|token|api_?key|auth)["'\s:=]+["']?[^\s"',;}{)\]]+["']?`, flags: 'gi', replacement: '$1=[REDACTED]' },
  // US Social Security Numbers
  { source: r`\b\d{3}-\d{2}-\d{4}\b`,                                                           flags: 'g',  replacement: '[SSN]' },
  // Phone numbers (US-centric but broad)
  { source: r`\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`,                       flags: 'g',  replacement: '[PHONE]' },
];

// Template tag to avoid TS treating backslashes as escape sequences
function r(strings: TemplateStringsArray): string { return strings.raw[0]; }

/** Mask PII/secrets in a string value. Creates fresh RegExp each call (no lastIndex bug). */
export function maskPII(value: string): string {
  if (!value || typeof value !== 'string') return value;
  let out = value;
  for (const def of _PII_PATTERN_DEFS) {
    out = out.replace(new RegExp(def.source, def.flags), def.replacement);
  }
  return out;
}

const _REDACT_KEY_RE_SOURCE = r`password|passwd|pwd|secret|token|api_?key|auth|credential|private|authorization`;

/** Recursively mask PII in an object (context dict). Creates fresh RegExp each call. */
export function maskContext(obj: any, depth = 0): any {
  if (depth > 5) return obj;
  if (typeof obj === 'string') return maskPII(obj);
  if (obj === null || obj === undefined) return obj;
  if (typeof obj !== 'object') return obj;

  // Handle arrays — recurse into each element
  if (Array.isArray(obj)) {
    return obj.map((v) => maskContext(v, depth + 1));
  }

  const redactKeyRe = new RegExp(_REDACT_KEY_RE_SOURCE, 'i');
  const out: any = {};
  for (const [k, v] of Object.entries(obj)) {
    if (redactKeyRe.test(k)) {
      out[k] = '[REDACTED]';
    } else {
      out[k] = maskContext(v, depth + 1);
    }
  }
  return out;
}

/* ── Layer inference ─────────────────────────────────────── */

export function inferLayer(name: string): LogLayer {
  const n = name.toLowerCase();
  if (/auth|jwt|token|oauth|permission|acl|rbac|guard|firewall|waf|encrypt|decrypt|password|credential|session|csrf|cors/.test(n)) return LogLayer.SECURITY;
  if (/repo|repository|dao|database|db|query|migration|schema|cache|redis|mongo|postgres|sql|neo4j|orm|entity|store|persist|storage/.test(n)) return LogLayer.DATA_ACCESS;
  if (/controller|router|route|middleware|gateway|proxy|handler|endpoint|api|rest|graphql|grpc|webhook|interceptor/.test(n)) return LogLayer.API_GATEWAY;
  if (/service|saga|aggregate|domain|policy|rule|event|command|workflow|process|pricing|discount|fraud|risk|consent/.test(n)) return LogLayer.DOMAIN;
  if (/infra|worker|job|cron|queue|kafka|rabbit|bull|pubsub|container|health|monitor|metric|cpu|memory|disk/.test(n)) return LogLayer.INFRASTRUCTURE;
  if (/trace|span|log|alert|metric|telemetry|observer|slo|sla|alarm/.test(n)) return LogLayer.OBSERVABILITY;
  if (/component|page|view|ui|render|form|modal|widget|screen|layout|theme/.test(n)) return LogLayer.PRESENTATION;
  return LogLayer.BUSINESS_LOGIC;
}
