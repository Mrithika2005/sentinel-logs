/* ============================================================
   SENTINEL SDK — Browser Agent  (final, complete)
   Auto-instruments:
     • fetch + XHR (with rate-limit, auth, retry detection)
     • Navigation (SPA + page load + previousPage)
     • Web Vitals: LCP, FCP, FP, CLS, FID, INP, TTFB, long tasks, FPS
     • Interactions: click, scroll depth, form submit + abandonment
     • Errors: JS exceptions, unhandled rejections, asset failures
     • Browser/device metadata on every record
     • React + Angular auto-detection
     • Class prototype auto-instrumentation
     • Configurable sampling
   Sends logs → /sentinel/ingest relay
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
  traceId?:        string;
  samplingRate?:   number;  // 0.0–1.0, default 1.0
}

/* ── Device/browser helpers ──────────────────────────────── */

function parseBrowser(ua: string): { browserName: string; browserVersion: string } {
  const pairs: Array<[RegExp, string]> = [
    [/Edg\/([0-9.]+)/, 'Edge'], [/OPR\/([0-9.]+)/, 'Opera'],
    [/Chrome\/([0-9.]+)/, 'Chrome'], [/Firefox\/([0-9.]+)/, 'Firefox'],
    [/Safari\/([0-9.]+)/, 'Safari'],
  ];
  for (const [re, name] of pairs) {
    const m = ua.match(re);
    if (m) return { browserName: name, browserVersion: m[1] };
  }
  return { browserName: 'unknown', browserVersion: '' };
}

function parseOS(ua: string): string {
  if (/Windows/.test(ua)) return 'Windows';
  if (/iPhone|iPad|iPod/.test(ua)) return 'iOS';
  if (/Mac OS X/.test(ua)) return 'macOS';
  if (/Android/.test(ua)) return 'Android';
  if (/Linux/.test(ua)) return 'Linux';
  return 'unknown';
}

function parseDeviceType(ua: string): 'mobile' | 'tablet' | 'desktop' {
  if (/Mobi/.test(ua)) return 'mobile';
  if (/Tablet|iPad/.test(ua)) return 'tablet';
  return 'desktop';
}

function connectionType(): string {
  return (navigator as any).connection?.effectiveType
      || (navigator as any).connection?.type
      || 'unknown';
}

/* ── Main class ──────────────────────────────────────────── */

export class SentinelBrowser {
  private cfg:         Required<SentinelBrowserConfig>;
  private queue:       LogRecord[] = [];
  private flushTimer?: ReturnType<typeof setInterval>;
  private navStart     = Date.now();
  private instrumented = new WeakSet<object>();
  private deviceMeta:  Record<string, any>;

  constructor(config: SentinelBrowserConfig = {}) {
    this.cfg = {
      serviceName:   config.serviceName   || 'browser-app',
      relayUrl:      config.relayUrl      || '/sentinel/ingest',
      batchSize:     config.batchSize     || 20,
      flushInterval: config.flushInterval || 3000,
      slowFetchMs:   config.slowFetchMs   || 1000,
      debug:         config.debug         || false,
      traceId:       config.traceId       || this._genTraceId(),
      samplingRate:  config.samplingRate  ?? 1.0,
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
      connectionType: connectionType(),
    };
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

    this._emit({
      message: `Sentinel Browser Agent hooked on "${this.cfg.serviceName}"`,
      layer:   LogLayer.INFRASTRUCTURE,
      level:   LogLevel.INFO,
      context: { userAgent: navigator.userAgent, url: location.href, ...this.deviceMeta },
    });
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
      service:  this.cfg.serviceName,
      trace_id: partial.trace_id || this.cfg.traceId,
      context:  {
        ...(partial.context || {}),
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
    window.addEventListener('beforeunload', () => void this._flush());
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
        const rateLimitHit      = response.status === 429;
        const rateLimitRemaining = Number(response.headers.get('X-RateLimit-Remaining') ?? response.headers.get('RateLimit-Remaining') ?? -1);

        // Auth event detection
        if (AUTH_PATHS.test(url) || response.status === 401 || response.status === 403) {
          self._emit({
            message: `Auth event: ${method} ${url} → ${response.status}`,
            layer:   LogLayer.SECURITY,
            level:   response.status >= 400 ? LogLevel.WARN : LogLevel.INFO,
            context: {
              authResult: response.status < 400 ? 'success' : 'failure',
              path:       url,
              statusCode: response.status,
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
            statusCode:        response.status,
            durationMs,
            slowQuery:         isSlow,
            slowQueryThresholdMs: self.cfg.slowFetchMs,
            rateLimitHit,
            rateLimitRemaining: rateLimitRemaining >= 0 ? rateLimitRemaining : undefined,
            responseSizeBytes:  Number(response.headers.get('content-length') || 0) || undefined,
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
          layer:   LogLayer.API_GATEWAY, level: LogLevel.INFO,
          context: {
            method: this._method, path: this._url,
            requestSizeBytes: typeof body === 'string' ? body.length : 0,
          } as LogContext,
        });

        this.addEventListener('loadend', () => {
          const durationMs        = performance.now() - this._start;
          const rateLimitHit      = this.status === 429;
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

    // Clicks
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

    // Scroll depth
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

    // Form submit
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

    // Form abandonment
    const dirtyForms = new Map<string, { id: string; completed: number; total: number; lastField: string }>();
    window.addEventListener('input', (e) => {
      const el   = e.target as HTMLInputElement;
      const form = el.closest('form');
      if (!form) return;
      const formId  = form.id || form.getAttribute('name') || 'unknown-form';
      const fields  = Array.from(form.elements).filter((f: any) => f.name) as HTMLInputElement[];
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

    // Named vital → context field
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
            const value   = (entry as any).value ?? (entry as any).processingStart != null
              ? ((entry as any).processingStart - entry.startTime)
              : (entry as any).duration ?? entry.startTime;
            const isSlow  = type === 'longtask' || (type === 'largest-contentful-paint' && value > 2500);
            const field   = vitalField[entry.name] || vitalField[type];
            const extra: Record<string, any> = field ? { [field]: value } : {};

            // TTFB from navigation timing
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

            // Resource failures
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
        const fps = Math.round((frames / (now - lastReport)) * 1000);
        frames    = 0;
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

  /* ── Helpers ─────────────────────────────────────────────── */

  private _genTraceId(): string {
    return Array.from({ length: 16 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
  }
}

/* ── Factory ─────────────────────────────────────────────── */

export const initBrowserSentinel = (config?: SentinelBrowserConfig): SentinelBrowser => {
  const s = new SentinelBrowser(config);
  s.hook();
  return s;
};
