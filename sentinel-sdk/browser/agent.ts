/* ============================================================
   SENTINEL SDK — Browser Agent v2
   ─────────────────────────────────────────────────────────
   ZERO-CONFIG: Drop this script and it auto-hooks everything.
   No initSentinel() required. Just install + import.

   New in v2:
     • Zero-config auto-init via IIFE (no manual call needed)
     • Per-user userId (persisted across sessions in localStorage)
     • Per-tab sessionId (unique per browser tab/visit)
     • Concurrent session tracking via BroadcastChannel heartbeat
       → backend can answer "how many users right now?"
     • Browser system metrics (CPU via scheduler, memory via
       performance.memory, connection, battery — browser equiv
       of psutil cpu/disk/memory since JS has no OS disk access)
     • Improved trace propagation (traceId on every record)
   ============================================================ */

import {
  LogLayer, LogLevel, LogRecord, inferLayer,
  type InstrumentedClassMeta, type LogContext,
} from '../core/types.ts';

/* ── Config ──────────────────────────────────────────────── */

export interface SentinelBrowserConfig {
  serviceName?:    string;
  relayUrl?:       string;
  batchSize?:      number;
  flushInterval?:  number;
  slowFetchMs?:    number;
  debug?:          boolean;
  samplingRate?:   number;   // 0.0–1.0, default 1.0
  // userId resolution: if omitted, SDK auto-generates and persists one
  resolveUserId?:  () => string | null | undefined;
}

/* ── ID helpers ──────────────────────────────────────────── */

function genId(len = 16): string {
  // crypto.randomUUID preferred, fallback to Math.random
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID().replace(/-/g, '').slice(0, len);
  }
  return Array.from({ length: len }, () =>
    Math.floor(Math.random() * 16).toString(16)
  ).join('');
}

/**
 * Returns a stable userId persisted in localStorage.
 * Survives page reloads; a new one is created only on first visit
 * (or after localStorage is cleared).
 */
function resolveOrCreateUserId(): string {
  const KEY = '__sentinel_uid';
  try {
    const existing = localStorage.getItem(KEY);
    if (existing) return existing;
    const uid = `u_${genId(20)}`;
    localStorage.setItem(KEY, uid);
    return uid;
  } catch {
    // localStorage blocked (private mode, iframe sandbox, etc.)
    return `u_anon_${genId(12)}`;
  }
}

/**
 * Per-tab sessionId — lives only in sessionStorage so a new tab
 * or fresh navigation gets a fresh session.
 */
function resolveOrCreateSessionId(): string {
  const KEY = '__sentinel_sid';
  try {
    const existing = sessionStorage.getItem(KEY);
    if (existing) return existing;
    const sid = `s_${genId(20)}`;
    sessionStorage.setItem(KEY, sid);
    return sid;
  } catch {
    return `s_${genId(20)}`;
  }
}

/* ── Device/browser helpers ──────────────────────────────── */

function parseBrowser(ua: string): { browserName: string; browserVersion: string } {
  const pairs: Array<[RegExp, string]> = [
    [/Edg\/([0-9.]+)/, 'Edge'],     [/OPR\/([0-9.]+)/, 'Opera'],
    [/Chrome\/([0-9.]+)/, 'Chrome'],[/Firefox\/([0-9.]+)/, 'Firefox'],
    [/Safari\/([0-9.]+)/, 'Safari'],
  ];
  for (const [re, name] of pairs) {
    const m = ua.match(re);
    if (m) return { browserName: name, browserVersion: m[1] };
  }
  return { browserName: 'unknown', browserVersion: '' };
}

function parseOS(ua: string): string {
  if (/Windows/.test(ua))           return 'Windows';
  if (/iPhone|iPad|iPod/.test(ua))  return 'iOS';
  if (/Mac OS X/.test(ua))          return 'macOS';
  if (/Android/.test(ua))           return 'Android';
  if (/Linux/.test(ua))             return 'Linux';
  return 'unknown';
}

function parseDeviceType(ua: string): 'mobile' | 'tablet' | 'desktop' {
  if (/Mobi/.test(ua))           return 'mobile';
  if (/Tablet|iPad/.test(ua))    return 'tablet';
  return 'desktop';
}

function connectionInfo(): Record<string, any> {
  const conn = (navigator as any).connection || (navigator as any).mozConnection || (navigator as any).webkitConnection;
  if (!conn) return { connectionType: 'unknown' };
  return {
    connectionType:       conn.effectiveType || conn.type || 'unknown',
    connectionDownlinkMbps: conn.downlink,
    connectionRttMs:      conn.rtt,
    connectionSaveData:   conn.saveData,
  };
}

/* ── Browser "psutil" equivalents ────────────────────────── */
/*
 * NOTE: The browser has NO access to disk or OS-level CPU the way
 * psutil does. These are the correct browser counterparts:
 *
 *   psutil.cpu_percent()          → scheduler.yield timing heuristic
 *   psutil.virtual_memory().total → performance.memory.jsHeapSizeLimit
 *   psutil.virtual_memory().used  → performance.memory.usedJSHeapSize
 *   psutil.disk_usage()           → StorageManager.estimate() [quota/usage]
 *
 * If you need true server-side OS metrics (CPU%, disk%) from your
 * Python backend, emit them from your server-side Sentinel agent
 * and correlate by traceId.
 */

async function collectBrowserSystemMetrics(): Promise<Record<string, any>> {
  const metrics: Record<string, any> = {};

  // ── JS Heap memory (closest to psutil virtual_memory) ──
  const mem = (performance as any).memory;
  if (mem) {
    metrics.memoryUsedBytes  = mem.usedJSHeapSize;       // ~ psutil.virtual_memory().used
    metrics.memoryTotalBytes = mem.jsHeapSizeLimit;       // ~ psutil.virtual_memory().total
    metrics.memoryAllocated  = mem.totalJSHeapSize;
    metrics.memoryUsedPercent = mem.jsHeapSizeLimit > 0
      ? Math.round((mem.usedJSHeapSize / mem.jsHeapSizeLimit) * 100)
      : undefined;
  }

  // ── Storage quota (closest to psutil disk_usage) ──
  try {
    if (navigator.storage?.estimate) {
      const est = await navigator.storage.estimate();
      metrics.diskUsedBytes       = est.usage;            // ~ psutil.disk_usage('/').used
      metrics.diskQuotaBytes      = est.quota;            // ~ psutil.disk_usage('/').total
      metrics.diskUsedPercent     = (est.quota && est.usage)
        ? Math.round((est.usage / est.quota) * 100)       // ~ psutil.disk_usage('/').percent
        : undefined;
    }
  } catch { /* storage API not available */ }

  // ── CPU pressure heuristic via scheduler.yield timing ──
  // True CPU% is not accessible from JS; this measures main-thread
  // busyness which correlates with high CPU load.
  try {
    if ((navigator as any).scheduling?.isInputPending !== undefined) {
      metrics.cpuInputPending = (navigator as any).scheduling.isInputPending();
    }
    const t0 = performance.now();
    await new Promise<void>((res) => setTimeout(res, 0));
    const yieldMs = performance.now() - t0;
    // A healthy idle browser yields in <5ms; >50ms suggests CPU pressure
    metrics.cpuYieldMs      = Math.round(yieldMs);
    metrics.cpuPercent      = Math.min(100, Math.round((yieldMs / 100) * 100)); // heuristic, not real %
  } catch { /* timing not available */ }

  // ── Battery (bonus: no psutil equivalent in browser SDK) ──
  try {
    if ((navigator as any).getBattery) {
      const batt = await (navigator as any).getBattery();
      metrics.batteryLevel    = Math.round(batt.level * 100);
      metrics.batteryCharging = batt.charging;
    }
  } catch { /* battery API not available or permission denied */ }

  return metrics;
}

/* ── Concurrent session heartbeat ───────────────────────── */
/*
 * Uses BroadcastChannel so all open tabs of the same origin
 * can see each other. Every tab announces itself every 5s.
 * The backend receives session_heartbeat events and can count
 * distinct sessionIds seen in the last ~10s = active sessions.
 *
 * This gives you: "X users are currently active" from your
 * ingestion layer with a simple:
 *   SELECT COUNT(DISTINCT sessionId)
 *   FROM logs
 *   WHERE eventType = 'session_heartbeat'
 *     AND timestamp > NOW() - INTERVAL '10 seconds'
 */

class SessionRegistry {
  private channel?: BroadcastChannel;
  private activePeers = new Set<string>();
  private heartbeatTimer?: ReturnType<typeof setInterval>;

  constructor(
    private sessionId: string,
    private userId: string,
    private onHeartbeat: (peers: number) => void,
  ) {}

  start(): void {
    try {
      this.channel = new BroadcastChannel('__sentinel_sessions');
      this.channel.onmessage = (e) => {
        if (e.data?.type === 'heartbeat' && e.data.sessionId !== this.sessionId) {
          this.activePeers.add(e.data.sessionId);
          // Peer cleanup after 10s of no heartbeat
          setTimeout(() => this.activePeers.delete(e.data.sessionId), 10_000);
        }
      };
    } catch { /* BroadcastChannel not supported (Safari <15.4) */ }

    this.heartbeatTimer = setInterval(() => {
      this.channel?.postMessage({ type: 'heartbeat', sessionId: this.sessionId, userId: this.userId });
      // +1 for self
      this.onHeartbeat(this.activePeers.size + 1);
    }, 5_000);

    // Announce immediately
    this.channel?.postMessage({ type: 'heartbeat', sessionId: this.sessionId, userId: this.userId });
  }

  stop(): void {
    clearInterval(this.heartbeatTimer);
    this.channel?.close();
  }

  /** Number of tabs currently known to be open (this tab + peers) */
  get activeSessions(): number {
    return this.activePeers.size + 1;
  }
}

/* ── Main class ──────────────────────────────────────────── */

export class SentinelBrowser {
  private cfg:            Required<Omit<SentinelBrowserConfig, 'resolveUserId'>> & { resolveUserId?: () => string | null | undefined };
  private queue:          LogRecord[] = [];
  private flushTimer?:    ReturnType<typeof setInterval>;
  private navStart        = Date.now();
  private instrumented    = new WeakSet<object>();
  private deviceMeta:     Record<string, any>;

  // ── Identity ──────────────────────────────────────────────
  readonly userId:    string;
  readonly sessionId: string;
  readonly traceId:   string;   // per-page-load trace

  private sessionRegistry: SessionRegistry;
  private activeSessions   = 1;

  constructor(config: SentinelBrowserConfig = {}) {
    // Resolve identity FIRST so it's available on every emitted record
    this.userId    = config.resolveUserId?.() || resolveOrCreateUserId();
    this.sessionId = resolveOrCreateSessionId();
    this.traceId   = genId(32);

    this.cfg = {
      serviceName:   config.serviceName   ?? 'browser-app',
      relayUrl:      config.relayUrl      ?? '/sentinel/ingest',
      batchSize:     config.batchSize     ?? 20,
      flushInterval: config.flushInterval ?? 3000,
      slowFetchMs:   config.slowFetchMs   ?? 1000,
      debug:         config.debug         ?? false,
      samplingRate:  config.samplingRate  ?? 1.0,
      resolveUserId: config.resolveUserId,
    };

    const ua = navigator.userAgent;
    this.deviceMeta = {
      ...parseBrowser(ua),
      osName:         parseOS(ua),
      deviceType:     parseDeviceType(ua),
      screenWidth:    screen.width,
      screenHeight:   screen.height,
      viewportWidth:  window.innerWidth,
      viewportHeight: window.innerHeight,
      locale:         navigator.language,
      timezone:       Intl.DateTimeFormat().resolvedOptions().timeZone,
      ...connectionInfo(),
    };

    this.sessionRegistry = new SessionRegistry(
      this.sessionId,
      this.userId,
      (peers) => {
        this.activeSessions = peers;
        // Emit heartbeat to relay — backend counts these for concurrency
        this._emit({
          message: `Session heartbeat (${peers} active tab${peers !== 1 ? 's' : ''})`,
          layer:   LogLayer.OBSERVABILITY,
          level:   LogLevel.DEBUG,
          context: {
            eventType:      'session_heartbeat',
            activeSessions: peers,
            page:           location.pathname,
          } as LogContext,
        });
      },
    );
  }

  /* ── Public API ─────────────────────────────────────────── */

  hook(): this {
    this._patchFetch();
    this._patchXHR();
    this._hookNavigation();
    this._hookInteractions();
    this._hookErrors();
    this._monitorVitals();
    this._monitorFPS();
    this._startFlushLoop();
    this._detectFramework();
    this.sessionRegistry.start();

    // Emit session start with full identity context
    this._emit({
      message: `Session started — userId: ${this.userId} | sessionId: ${this.sessionId}`,
      layer:   LogLayer.INFRASTRUCTURE,
      level:   LogLevel.INFO,
      context: {
        eventType: 'session_start',
        url:       location.href,
        referrer:  document.referrer,
        ...this.deviceMeta,
      } as LogContext,
    });

    // Collect and emit browser system metrics immediately + every 30s
    const emitSystemMetrics = async () => {
      const sys = await collectBrowserSystemMetrics();
      this._emit({
        message: `System metrics — heap: ${sys.memoryUsedPercent ?? '?'}% | disk: ${sys.diskUsedPercent ?? '?'}% | cpu yield: ${sys.cpuYieldMs ?? '?'}ms`,
        layer:   LogLayer.INFRASTRUCTURE,
        level:   LogLevel.INFO,
        context: {
          eventType: 'system_metrics',
          ...sys,
          page: location.pathname,
        } as LogContext,
      });
    };
    void emitSystemMetrics();
    setInterval(() => void emitSystemMetrics(), 30_000);

    return this;
  }

  instrument<T extends object>(target: T | (new (...a: any[]) => T), layer?: LogLayer): this {
    const proto = typeof target === 'function' ? target.prototype : Object.getPrototypeOf(target);
    if (!proto || this.instrumented.has(proto)) return this;
    this.instrumented.add(proto);

    const className     = (typeof target === 'function' ? target.name : target.constructor?.name) || 'UnknownClass';
    const resolvedLayer = layer || inferLayer(className);
    const methodNames: string[] = [];

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

    const meta: InstrumentedClassMeta = { className, layer: resolvedLayer, methodNames };
    this._emit({
      message: `Auto-instrumented: ${className} (${methodNames.length} methods)`,
      layer:   LogLayer.OBSERVABILITY,
      level:   LogLevel.DEBUG,
      context: meta as unknown as LogContext,
    });
    return this;
  }

  autoDiscover(): this {
    this._discoverAngular();
    this._discoverWindowGlobals();
    return this;
  }

  log(partial: Partial<LogRecord> & { message: string }): void {
    this._emit(partial);
  }

  flush(): Promise<void> {
    return this._flush();
  }

  /* ── Emitter ────────────────────────────────────────────── */

  private _emit(partial: Partial<LogRecord> & { message: string }): void {
    if (this.cfg.samplingRate < 1.0 && Math.random() > this.cfg.samplingRate) return;

    const record = new LogRecord({
      ...partial,
      service:    this.cfg.serviceName,
      // Every record carries the full identity triple:
      //   traceId   — per page-load, correlates all events on this navigation
      //   sessionId — per browser tab, correlates all events in this visit
      //   userId    — per human user, correlates across sessions/devices
      trace_id:   partial.trace_id || this.traceId,
      context: {
        ...(partial.context || {}),
        // Identity fields on every single log record
        userId:           this.userId,
        sessionId:        this.sessionId,
        traceId:          this.traceId,
        activeSessions:   this.activeSessions,
        samplingRate:     this.cfg.samplingRate,
        samplingDecision: 'sampled',
      },
    });

    if (this.cfg.debug) {
      const lvlMap: Record<LogLevel, keyof Console> = {
        [LogLevel.DEBUG]: 'debug', [LogLevel.INFO]: 'log',
        [LogLevel.WARN]:  'warn',  [LogLevel.ERROR]: 'error', [LogLevel.FATAL]: 'error',
      };
      (console as any)[lvlMap[record.level]]('[SENTINEL]', record.to_dict());
    }

    this.queue.push(record);
    if (this.queue.length >= this.cfg.batchSize) void this._flush();
  }

  private async _flush(): Promise<void> {
    if (this.queue.length === 0) return;
    const batch = this.queue.splice(0, this.queue.length);
    try {
      const res = await fetch(this.cfg.relayUrl, {
        method:    'POST',
        headers:   { 'Content-Type': 'application/json', 'X-Sentinel': '1' },
        body:      JSON.stringify(batch.map((r) => r.to_dict())),
        keepalive: true,
      });
      if (!res.ok && this.cfg.debug) console.warn('[SENTINEL] relay rejected batch:', res.status);
    } catch (err) {
      if (this.cfg.debug) console.error('[SENTINEL] flush error:', err);
      this.queue.unshift(...batch);
    }
  }

  private _startFlushLoop(): void {
    this.flushTimer = setInterval(() => void this._flush(), this.cfg.flushInterval);
    window.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden') void this._flush();
    });
    window.addEventListener('beforeunload', () => {
      this.sessionRegistry.stop();
      void this._flush();
    });
  }

  /* ── Fetch patch ────────────────────────────────────────── */

  private _patchFetch(): void {
    const orig = window.fetch.bind(window);
    const self = this;
    const AUTH_PATHS = /\/(login|logout|auth|token|oauth|signin|signup|refresh|verify)/i;

    (window as any).fetch = async (...args: Parameters<typeof fetch>): Promise<Response> => {
      const [resource, init] = args;
      const url = typeof resource === 'string' ? resource : (resource as Request).url;
      if (url.includes(self.cfg.relayUrl) || url.includes('X-Sentinel')) return orig(...args);

      const method    = init?.method || 'GET';
      const startTime = performance.now();

      self._emit({
        message: `→ ${method} ${url}`,
        layer:   LogLayer.API_GATEWAY,
        level:   LogLevel.INFO,
        context: {
          method, path: url,
          requestSizeBytes: typeof init?.body === 'string' ? init.body.length : 0,
        } as LogContext,
      });

      try {
        const response   = await orig(...args);
        const durationMs = performance.now() - startTime;
        const isError    = !response.ok;
        const isSlow     = durationMs > self.cfg.slowFetchMs;
        const rateLimitHit       = response.status === 429;
        const rateLimitRemaining = Number(
          response.headers.get('X-RateLimit-Remaining') ??
          response.headers.get('RateLimit-Remaining') ?? -1
        );

        if (AUTH_PATHS.test(url) || response.status === 401 || response.status === 403) {
          self._emit({
            message: `Auth event: ${method} ${url} → ${response.status}`,
            layer:   LogLayer.SECURITY,
            level:   response.status >= 400 ? LogLevel.WARN : LogLevel.INFO,
            context: {
              authResult:    response.status < 400 ? 'success' : 'failure',
              path:          url,
              statusCode:    response.status,
              failureReason: response.status >= 400 ? `HTTP ${response.status}` : undefined,
              ...self.deviceMeta,
            } as LogContext,
          });
        }

        self._emit({
          message: `← ${method} ${url} ${response.status} (${durationMs.toFixed(1)}ms)${isSlow ? ' [SLOW]' : ''}${rateLimitHit ? ' [RATE-LIMITED]' : ''}`,
          layer:   LogLayer.API_GATEWAY,
          level:   isError ? LogLevel.ERROR : isSlow ? LogLevel.WARN : LogLevel.INFO,
          context: {
            method, path: url,
            statusCode:            response.status,
            durationMs,
            slowQuery:             isSlow,
            slowQueryThresholdMs:  self.cfg.slowFetchMs,
            rateLimitHit,
            rateLimitRemaining:    rateLimitRemaining >= 0 ? rateLimitRemaining : undefined,
            responseSizeBytes:     Number(response.headers.get('content-length') || 0) || undefined,
          } as LogContext,
        });

        return response;
      } catch (err) {
        const durationMs = performance.now() - startTime;
        self._emit({
          message: `✗ ${method} ${url} — network error after ${durationMs.toFixed(1)}ms`,
          layer:   LogLayer.API_GATEWAY,
          level:   LogLevel.ERROR,
          context: { method, path: url, durationMs, exceptionType: String(err) } as LogContext,
        });
        throw err;
      }
    };

    Object.defineProperty(window, 'fetch', { value: (window as any).fetch, configurable: true, writable: true });
  }

  /* ── XHR patch ──────────────────────────────────────────── */

  private _patchXHR(): void {
    const OrigXHR = window.XMLHttpRequest;
    const self    = this;

    class SentinelXHR extends OrigXHR {
      private _method = 'GET';
      private _url    = '';
      private _start  = 0;

      open(method: string, url: string | URL, ...rest: any[]): void {
        this._method = method;
        this._url    = String(url);
        (super.open as any)(method, url, ...rest);
      }

      send(body?: Document | XMLHttpRequestBodyInit | null): void {
        this._start = performance.now();
        self._emit({
          message: `XHR → ${this._method} ${this._url}`,
          layer:   LogLayer.API_GATEWAY,
          level:   LogLevel.INFO,
          context: {
            method: this._method, path: this._url,
            requestSizeBytes: typeof body === 'string' ? body.length : 0,
          } as LogContext,
        });

        this.addEventListener('loadend', () => {
          const durationMs         = performance.now() - this._start;
          const rateLimitHit       = this.status === 429;
          const rateLimitRemaining = Number(this.getResponseHeader('X-RateLimit-Remaining') ?? -1);
          self._emit({
            message: `XHR ← ${this._method} ${this._url} ${this.status} (${durationMs.toFixed(1)}ms)${rateLimitHit ? ' [RATE-LIMITED]' : ''}`,
            layer:   LogLayer.API_GATEWAY,
            level:   this.status >= 400 ? LogLevel.ERROR : LogLevel.INFO,
            context: {
              method: this._method, path: this._url,
              statusCode: this.status, durationMs,
              rateLimitHit,
              rateLimitRemaining: rateLimitRemaining >= 0 ? rateLimitRemaining : undefined,
            } as LogContext,
          });
        });

        super.send(body);
      }
    }

    (window as any).XMLHttpRequest = SentinelXHR;
  }

  /* ── Navigation ─────────────────────────────────────────── */

  private _hookNavigation(): void {
    const self = this;
    let prevPage = location.pathname;

    window.addEventListener('load', () => {
      const loadTimeMs = performance.now();
      self._emit({
        message: `Page loaded: ${location.pathname} in ${loadTimeMs.toFixed(1)}ms`,
        layer:   LogLayer.PRESENTATION,
        level:   loadTimeMs > 3000 ? LogLevel.WARN : LogLevel.INFO,
        context: { page: location.pathname, renderTimeMs: loadTimeMs, ...self.deviceMeta } as LogContext,
      });
    });

    const origPush    = history.pushState.bind(history);
    const origReplace = history.replaceState.bind(history);

    history.pushState = (...args) => {
      origPush(...args);
      self._onNavigate('pushState', prevPage);
      prevPage = location.pathname;
    };
    history.replaceState = (...args) => {
      origReplace(...args);
      self._onNavigate('replaceState', prevPage);
      prevPage = location.pathname;
    };
    window.addEventListener('popstate', () => {
      self._onNavigate('popstate', prevPage);
      prevPage = location.pathname;
    });
  }

  private _onNavigate(trigger: string, previousPage: string): void {
    this._emit({
      message: `Navigation: ${trigger} → ${location.pathname}`,
      layer:   LogLayer.PRESENTATION,
      level:   LogLevel.INFO,
      context: {
        page:              location.pathname,
        previousPage,
        navigationTrigger: trigger,
        sessionDuration:   (Date.now() - this.navStart) / 1000,
        interactionType:   'navigate',
      } as LogContext,
    });
  }

  /* ── Interactions ────────────────────────────────────────── */

  private _hookInteractions(): void {
    const self = this;

    window.addEventListener('click', (e) => {
      const t = e.target as HTMLElement;
      self._emit({
        message: `Click: <${t.tagName?.toLowerCase()}>${t.id ? '#' + t.id : ''}`,
        layer:   LogLayer.PRESENTATION,
        level:   LogLevel.INFO,
        context: {
          interactionType: 'click',
          elementTag:  t.tagName,
          elementId:   t.id,
          elementText: t.innerText?.slice(0, 60),
          page:        location.pathname,
        } as LogContext,
      });
    }, { capture: true, passive: true });

    let maxScroll = 0;
    let scrollTimer: ReturnType<typeof setTimeout>;
    window.addEventListener('scroll', () => {
      clearTimeout(scrollTimer);
      scrollTimer = setTimeout(() => {
        const depth = Math.round(
          ((window.scrollY + window.innerHeight) / document.documentElement.scrollHeight) * 100
        );
        if (depth > maxScroll) {
          maxScroll = depth;
          self._emit({
            message: `Scroll depth: ${depth}%`,
            layer:   LogLayer.PRESENTATION,
            level:   LogLevel.INFO,
            context: { interactionType: 'scroll', scrollDepthPercent: depth, page: location.pathname } as LogContext,
          });
        }
      }, 500);
    }, { passive: true });

    window.addEventListener('submit', (e) => {
      const t      = e.target as HTMLFormElement;
      const formId = t.id || t.getAttribute('name') || 'unknown-form';
      const fields    = Array.from(t.elements).filter((el: any) => el.name) as HTMLInputElement[];
      const completed = fields.filter((f) => f.value?.length > 0).length;
      self._emit({
        message: `Form submitted: ${formId}`,
        layer:   LogLayer.PRESENTATION,
        level:   LogLevel.INFO,
        context: {
          interactionType:     'submit',
          formId,
          elementId:           formId,
          elementTag:          'FORM',
          formFieldsCompleted: completed,
          formFieldsTotal:     fields.length,
          page:                location.pathname,
        } as LogContext,
      });
    }, { capture: true });

    const dirtyForms = new Map<string, { id: string; completed: number; total: number; lastField: string }>();
    window.addEventListener('input', (e) => {
      const el   = e.target as HTMLInputElement;
      const form = el.closest('form');
      if (!form) return;
      const formId    = form.id || form.getAttribute('name') || 'unknown-form';
      const fields    = Array.from(form.elements).filter((f: any) => f.name) as HTMLInputElement[];
      const completed = fields.filter((f) => f.value?.length > 0).length;
      dirtyForms.set(formId, { id: formId, completed, total: fields.length, lastField: el.name || el.id });
    }, { passive: true });

    window.addEventListener('visibilitychange', () => {
      if (document.visibilityState !== 'hidden') return;
      dirtyForms.forEach((info) => {
        self._emit({
          message: `Form abandoned: ${info.id} (${info.completed}/${info.total} fields)`,
          layer:   LogLayer.PRESENTATION,
          level:   LogLevel.WARN,
          context: {
            interactionType:      'form_abandon',
            formId:               info.id,
            formFieldsCompleted:  info.completed,
            formFieldsTotal:      info.total,
            formAbandonedAtField: info.lastField,
            page:                 location.pathname,
          } as LogContext,
        });
      });
    });
  }

  /* ── Errors ─────────────────────────────────────────────── */

  private _hookErrors(): void {
    const self = this;

    window.addEventListener('error', (e) => {
      if (e.target && (e.target as HTMLElement).tagName) {
        const t = e.target as HTMLElement;
        self._emit({
          message: `Asset load failure: ${(t as any).src || (t as any).href}`,
          layer:   LogLayer.PRESENTATION,
          level:   LogLevel.ERROR,
          context: {
            elementTag: t.tagName,
            assetUrl:   (t as any).src || (t as any).href,
            errorType:  'asset_load',
            page:       location.pathname,
            ...self.deviceMeta,
          } as LogContext,
        });
        return;
      }
      self._emit({
        message: `JS Error: ${e.message}`,
        layer:   LogLayer.SECURITY,
        level:   LogLevel.FATAL,
        context: {
          errorType:  'js_error',
          assetUrl:   e.filename,
          stackTrace: e.error?.stack,
          page:       location.pathname,
          ...self.deviceMeta,
        } as LogContext,
      });
    }, true);

    window.addEventListener('unhandledrejection', (e) => {
      self._emit({
        message: `Unhandled Rejection: ${e.reason}`,
        layer:   LogLayer.OBSERVABILITY,
        level:   LogLevel.ERROR,
        context: {
          errorType:     'unhandled_rejection',
          exceptionType: String(e.reason),
          page:          location.pathname,
        } as LogContext,
      });
    });
  }

  /* ── Web Vitals ─────────────────────────────────────────── */

  private _monitorVitals(): void {
    if (!('PerformanceObserver' in window)) return;
    const self = this;

    const vitalField: Record<string, string> = {
      'first-contentful-paint':   'fcpMs',
      'first-paint':              'fpMs',
      'largest-contentful-paint': 'lcpMs',
      'first-input':              'fidMs',
      'layout-shift':             'clsScore',
    };

    const types = ['paint','largest-contentful-paint','layout-shift','navigation','resource','longtask','first-input'];

    types.forEach((type) => {
      try {
        const obs = new PerformanceObserver((list) => {
          list.getEntries().forEach((entry) => {
            const value  = (entry as any).value ?? (entry as any).processingStart != null
              ? ((entry as any).processingStart - entry.startTime)
              : (entry as any).duration ?? entry.startTime;
            const isSlow = type === 'longtask' || (type === 'largest-contentful-paint' && value > 2500);
            const field  = vitalField[entry.name] || vitalField[type];
            const extra: Record<string, any> = field ? { [field]: value } : {};

            if (type === 'navigation') {
              const nav = entry as PerformanceNavigationTiming;
              extra['ttfbMs'] = nav.responseStart - nav.requestStart;
            }

            self._emit({
              message: `Web Vital [${entry.name || type}]: ${value.toFixed(2)}${type === 'layout-shift' ? '' : 'ms'}`,
              layer:   LogLayer.PRESENTATION,
              level:   isSlow ? LogLevel.WARN : LogLevel.INFO,
              context: {
                metricName:   entry.name || type,
                metricValue:  value,
                metricUnit:   type === 'layout-shift' ? 'score' : 'ms',
                renderTimeMs: type === 'navigation' ? value : undefined,
                page:         location.pathname,
                ...extra,
              } as LogContext,
            });

            if (type === 'resource') {
              const res = entry as PerformanceResourceTiming;
              if (res.responseStatus >= 400) {
                self._emit({
                  message: `Asset failure (${res.responseStatus}): ${entry.name}`,
                  layer:   LogLayer.PRESENTATION,
                  level:   LogLevel.ERROR,
                  context: { assetUrl: entry.name, statusCode: res.responseStatus, page: location.pathname } as LogContext,
                });
              }
            }
          });
        });
        obs.observe({ type, buffered: true } as any);
      } catch { /* browser doesn't support this type */ }
    });
  }

  /* ── FPS monitor ─────────────────────────────────────────── */

  private _monitorFPS(): void {
    const self = this;
    let frames = 0;
    let lastReport = performance.now();

    const tick = () => {
      frames++;
      const now = performance.now();
      if (now - lastReport >= 5000) {
        const fps  = Math.round((frames / (now - lastReport)) * 1000);
        frames     = 0;
        lastReport = now;
        if (fps < 30) {
          self._emit({
            message: `Low FPS detected: ${fps}fps`,
            layer:   LogLayer.PRESENTATION,
            level:   fps < 15 ? LogLevel.ERROR : LogLevel.WARN,
            context: { fpsAverage: fps, page: location.pathname } as LogContext,
          });
        }
      }
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  /* ── Class wrapping ──────────────────────────────────────── */

  private _wrapMethod(proto: object, key: string, className: string, layer: LogLayer): void {
    const self = this;
    const orig = (proto as any)[key] as (...args: any[]) => any;

    (proto as any)[key] = function (...args: any[]) {
      const start   = performance.now();
      let isAsync   = false;
      try {
        const result = orig.apply(this, args);
        if (result && typeof result.then === 'function') {
          isAsync = true;
          return result
            .then((val: any) => {
              const durationMs = performance.now() - start;
              self._emit({ message: `${className}.${key} completed (async, ${durationMs.toFixed(1)}ms)`, layer, level: LogLevel.INFO,
                context: { className, functionName: key, durationMs, isAsync: true } as LogContext });
              return val;
            })
            .catch((err: any) => {
              const durationMs = performance.now() - start;
              self._emit({ message: `${className}.${key} failed (async): ${err?.message}`, layer, level: LogLevel.ERROR,
                context: { className, functionName: key, durationMs, isAsync: true, exceptionType: err?.constructor?.name, stackTrace: err?.stack } as LogContext });
              throw err;
            });
        }
        const durationMs = performance.now() - start;
        self._emit({ message: `${className}.${key} completed (${durationMs.toFixed(1)}ms)`, layer, level: LogLevel.INFO,
          context: { className, functionName: key, durationMs, isAsync: false } as LogContext });
        return result;
      } catch (err: any) {
        if (!isAsync) {
          const durationMs = performance.now() - start;
          self._emit({ message: `${className}.${key} threw: ${err?.message}`, layer, level: LogLevel.ERROR,
            context: { className, functionName: key, durationMs, exceptionType: err?.constructor?.name, stackTrace: err?.stack } as LogContext });
        }
        throw err;
      }
    };
  }

  /* ── Framework detection ────────────────────────────────── */

  private _detectFramework(): void {
    if ((window as any).__REACT_DEVTOOLS_GLOBAL_HOOK__) {
      this._emit({ message: 'React detected', layer: LogLayer.OBSERVABILITY, level: LogLevel.DEBUG, context: { component: 'React' } as LogContext });
      this._hookReact();
    }
    if ((window as any).ng) {
      this._emit({ message: 'Angular detected', layer: LogLayer.OBSERVABILITY, level: LogLevel.DEBUG, context: { component: 'Angular' } as LogContext });
      this._discoverAngular();
    }
  }

  private _hookReact(): void {
    const hook = (window as any).__REACT_DEVTOOLS_GLOBAL_HOOK__;
    if (!hook) return;
    const orig = hook.onCommitFiberRoot?.bind(hook);
    if (!orig) return;
    const self = this;
    hook.onCommitFiberRoot = (...args: any[]) => {
      try {
        const name = args[1]?.current?.type?.displayName || args[1]?.current?.type?.name;
        if (name) self._emit({ message: `React render: <${name}>`, layer: LogLayer.PRESENTATION, level: LogLevel.DEBUG,
          context: { component: name, renderTimeMs: 0 } as LogContext });
      } catch { /* ignore */ }
      return orig(...args);
    };
  }

  private _discoverAngular(): void {
    try {
      const ng   = (window as any).ng;
      if (!ng) return;
      const root = document.querySelector('[ng-version]') || document.querySelector('app-root');
      if (!root) return;
      const ctx  = ng.getContext?.(root) || ng.probe?.(root)?.componentInstance;
      if (ctx) this.instrument(ctx);
    } catch { /* not ready */ }
  }

  private _discoverWindowGlobals(): void {
    Object.keys(window).forEach((key) => {
      try {
        const val = (window as any)[key];
        if (val && typeof val === 'object' && val.constructor &&
            val.constructor !== Object && val.constructor !== Array && val.constructor !== Function &&
            !this.instrumented.has(Object.getPrototypeOf(val))) {
          this.instrument(val);
        }
      } catch { /* some window props throw */ }
    });
  }
}

/* ── Factory ─────────────────────────────────────────────── */

export const initBrowserSentinel = (config?: SentinelBrowserConfig): SentinelBrowser => {
  const s = new SentinelBrowser(config);
  s.hook();
  return s;
};

/* ══════════════════════════════════════════════════════════════
   ZERO-CONFIG AUTO-INIT
   ══════════════════════════════════════════════════════════════
   This IIFE runs the moment the module is first imported or the
   script tag is parsed — before any application code runs.
   The client app does NOT need to call initBrowserSentinel().

   How it picks up config:
     1. window.__SENTINEL_CONFIG__  (set before this script loads)
     2. <script data-sentinel-service="my-app" ...>  (data attributes)
     3. Safe defaults (service name = hostname)

   To use:
     Option A — pure auto (zero code in client):
       <script src="/sentinel/sentinel-browser.js"></script>

     Option B — config via window global (before script tag):
       <script>
         window.__SENTINEL_CONFIG__ = {
           serviceName: 'my-enterprise-app',
           samplingRate: 0.5,
         };
       </script>
       <script src="/sentinel/sentinel-browser.js"></script>

     Option C — config via data attributes on script tag:
       <script
         src="/sentinel/sentinel-browser.js"
         data-sentinel-service="checkout-ui"
         data-sentinel-relay="/api/sentinel/ingest"
       ></script>

     Option D — if bundled as ESM, simply import it:
       import '@your-org/sentinel-browser';
       // That's it. No initSentinel call needed.
   ══════════════════════════════════════════════════════════════ */

;(function autoInit() {
  // Only run in a real browser context
  if (typeof window === 'undefined' || typeof document === 'undefined') return;

  // Guard: don't double-init if imported multiple times
  if ((window as any).__SENTINEL_INITIALIZED__) return;
  (window as any).__SENTINEL_INITIALIZED__ = true;

  // ── Config resolution priority ────────────────────────────

  // 1. window.__SENTINEL_CONFIG__ (developer-set global)
  const winCfg: SentinelBrowserConfig = (window as any).__SENTINEL_CONFIG__ || {};

  // 2. data-* attributes on the <script> tag that loaded us
  const scriptEl = (
    document.currentScript ||
    document.querySelector('script[src*="sentinel-browser"]')
  ) as HTMLScriptElement | null;

  const dataCfg: SentinelBrowserConfig = {};
  if (scriptEl?.dataset) {
    if (scriptEl.dataset.sentinelService)  dataCfg.serviceName   = scriptEl.dataset.sentinelService;
    if (scriptEl.dataset.sentinelRelay)    dataCfg.relayUrl      = scriptEl.dataset.sentinelRelay;
    if (scriptEl.dataset.sentinelSampling) dataCfg.samplingRate  = Number(scriptEl.dataset.sentinelSampling);
    if (scriptEl.dataset.sentinelSlow)     dataCfg.slowFetchMs   = Number(scriptEl.dataset.sentinelSlow);
    if (scriptEl.dataset.sentinelDebug)    dataCfg.debug         = scriptEl.dataset.sentinelDebug !== 'false';
  }

  // 3. Fallback defaults
  const defaultCfg: SentinelBrowserConfig = {
    serviceName: location.hostname || 'browser-app',
  };

  // Merge: data-attrs < window config < (hardcoded defaults for anything not set)
  const finalCfg: SentinelBrowserConfig = { ...defaultCfg, ...dataCfg, ...winCfg };

  // ── Init ──────────────────────────────────────────────────
  const instance = new SentinelBrowser(finalCfg);
  instance.hook();

  // Expose on window so app code can call sentinel.log() if it wants
  (window as any).__SENTINEL__ = instance;
})();
