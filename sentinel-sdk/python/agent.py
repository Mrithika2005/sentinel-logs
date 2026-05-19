AGENT.PY

"""
SENTINEL SDK — Python Agent  v4.0
==================================

What's new in v4.0
——————————

1. ZERO-CONFIG AUTO-INIT
   Installing the package is enough. The SDK ships a sitecustomize.py
   that fires init_sentinel() before any user code runs. No import,
   no init_sentinel() call needed in client code. Configuration is
   read from environment variables (SENTINEL_SERVICE_NAME,
   SENTINEL_CLICKHOUSE_HOST, SENTINEL_OTLP_ENDPOINT, etc.).

2. PER-REQUEST TRACE IDs  (fixes the shared trace_id bug)
   v3.x used a single process-level self._trace_id, so every
   concurrent request had the same trace_id. v4.0 uses
   contextvars.ContextVar so every async task / thread gets its own
   trace_id, span_id, request_id, user_id, and session_id
   automatically. The Gantt waterfall approximation is gone — you can
   now join on traceId exactly.

3. SESSION TRACKING
   Every new HTTP request that arrives without a known
   X-Session-Id is assigned one. The registry tracks:
     • active sessions  (last seen < SESSION_TTL seconds ago)
     • total sessions since startup
     • per-session metadata (user, tenant, IP, start time, last seen)
   Query live counts with sentinel.session_stats().
   The registry is purged every 60 s in a background thread.

4. PSUTIL VITALS FIX
   _emit_vitals() now calls psutil.cpu_percent(interval=0.1) directly
   (non-blocking, accurate) instead of the manual cpu_times delta.
   Also adds diskUsedPercent, diskUsedBytes, memoryTotalBytes inline.

5. ALL v3.1 FIXES RETAINED

Environment variables for auto-init
-------------------------------------
  SENTINEL_SERVICE_NAME       (default: "python-service")
  SENTINEL_CLICKHOUSE_HOST    (default: "http://localhost:8123")
  SENTINEL_CLICKHOUSE_DB      alias for CLICKHOUSE_DATABASE
  SENTINEL_CLICKHOUSE_TABLE   alias for CLICKHOUSE_TABLE
  SENTINEL_CLICKHOUSE_USER    alias for CLICKHOUSE_USER
  SENTINEL_CLICKHOUSE_PASS    alias for CLICKHOUSE_PASSWORD
  SENTINEL_OTLP_ENDPOINT      alias for OTEL_EXPORTER_OTLP_ENDPOINT
  SENTINEL_HEALTH_PORT        (default: 9090)
  SENTINEL_LOG_LEVEL          alias for LOG_LEVEL (default: DEBUG)
  SENTINEL_SAMPLING_RATE      (default: 1.0)
  SENTINEL_DISK_BUFFER_DIR    (default: /tmp/sentinel)
  SENTINEL_DISK_MAX_MB        (default: 500)
  SENTINEL_ENABLED            (default: true)
  SENTINEL_DEBUG              (default: false)
  SENTINEL_SLOW_QUERY_MS      (default: 200)
  SENTINEL_SLOW_HTTP_MS       (default: 1000)
  SENTINEL_SLOW_FUNCTION_MS   (default: 500)
  SENTINEL_CERT_HOSTS         comma-separated hostnames for TLS checks
  SENTINEL_SESSION_TTL        seconds before idle session expires (default: 1800)

Manual usage (still works as before)
--------------------------------------
    from sentinel_sdk.python.agent import init_sentinel, SentinelMeta

    sentinel = init_sentinel(
        "my-service",
        otlp_endpoint="http://otel-collector:4318",
        health_port=9090,
        log_level="INFO",
        debug=True,
    )
"""

from __future__ import annotations

import base64
import builtins
import contextvars
import datetime
import functools
import inspect
import json
import logging
import os
import re as _re
import secrets
import signal
import ssl
import socket
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar

# ── Optional imports (graceful) ───────────────────────────────────────────────

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import httpx as _httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    import sqlalchemy as _sa
    from sqlalchemy import event as _sa_event
    HAS_SQLALCHEMY = True
except ImportError:
    HAS_SQLALCHEMY = False

try:
    import psycopg2 as _psycopg2
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

try:
    import neo4j as _neo4j
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False

try:
    import redis as _redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

try:
    import psutil as _psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import celery as _celery
    from celery import signals as _celery_signals
    HAS_CELERY = True
except ImportError:
    HAS_CELERY = False

try:
    import pika as _pika
    HAS_PIKA = True
except ImportError:
    HAS_PIKA = False

try:
    import aiokafka as _aiokafka
    HAS_AIOKAFKA = True
except ImportError:
    HAS_AIOKAFKA = False


# ── Layer & Level constants ───────────────────────────────────────────────────

class LogLayer:
    PRESENTATION   = 'presentation'
    API_GATEWAY    = 'api_gateway'
    BUSINESS_LOGIC = 'business_logic'
    DATA_ACCESS    = 'data_access'
    SERVICE        = 'service'
    SECURITY       = 'security'
    OBSERVABILITY  = 'observability'
    INFRASTRUCTURE = 'infrastructure'
    DOMAIN         = 'domain'


class LogLevel:
    DEBUG = 'DEBUG'
    INFO  = 'INFO'
    WARN  = 'WARN'
    ERROR = 'ERROR'
    FATAL = 'FATAL'


_LEVEL_ORDER: Dict[str, int] = {
    LogLevel.DEBUG: 0, LogLevel.INFO: 1, LogLevel.WARN: 2,
    LogLevel.ERROR: 3, LogLevel.FATAL: 4,
}

# ── Per-request context (ContextVar — safe for async + threads) ───────────────
#
# These replace the old single self._trace_id on the agent.
# Each incoming request (Flask/FastAPI middleware) binds its own values so
# every concurrent user has a completely independent trace context.
#
# Thread-based frameworks (Flask/gunicorn sync workers): ContextVar resets
#   automatically per request when you call _bind_request_context().
# Async frameworks (FastAPI/uvicorn): each asyncio Task has its own copy
#   because contextvars.copy_context() is used under the hood by asyncio.
#
# Access from anywhere in the call stack:
#   _ctx_trace_id.get()     → current request's trace_id
#   _ctx_session_id.get()   → current request's session_id
#   etc.

_ctx_trace_id:   contextvars.ContextVar[str] = contextvars.ContextVar('sentinel_trace_id',   default='untracked')
_ctx_span_id:    contextvars.ContextVar[str] = contextvars.ContextVar('sentinel_span_id',    default='')
_ctx_request_id: contextvars.ContextVar[str] = contextvars.ContextVar('sentinel_request_id', default='')
_ctx_session_id: contextvars.ContextVar[str] = contextvars.ContextVar('sentinel_session_id', default='')
_ctx_user_id:    contextvars.ContextVar[str] = contextvars.ContextVar('sentinel_user_id',    default='')
_ctx_tenant_id:  contextvars.ContextVar[str] = contextvars.ContextVar('sentinel_tenant_id',  default='')


def _bind_request_context(
    trace_id:   str,
    span_id:    str,
    request_id: str = '',
    session_id: str = '',
    user_id:    str = '',
    tenant_id:  str = '',
) -> None:
    """Set all per-request ContextVars for the current execution context."""
    _ctx_trace_id.set(trace_id)
    _ctx_span_id.set(span_id)
    _ctx_request_id.set(request_id)
    _ctx_session_id.set(session_id)
    _ctx_user_id.set(user_id)
    _ctx_tenant_id.set(tenant_id)


# ── PII masking ───────────────────────────────────────────────────────────────

_PII_PATTERNS: List[Tuple[_re.Pattern, str]] = [
    (_re.compile(r'\b(?:\d[ -]?){13,16}\b'),
     '[CARD]'),
    (_re.compile(r'\b[A-Za-z0-9+/]{20,}\.[A-Za-z0-9+/]{20,}\.[A-Za-z0-9+/_-]{20,}\b'),
     '[JWT]'),
    (_re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', _re.I),
     'Bearer [TOKEN]'),
    (_re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
     '[EMAIL]'),
    (_re.compile(r'(password|passwd|pwd|secret|token|api_?key|auth)["\'\s:=]+["\']?[^\s"\'`,;}{)\]]+["\']?', _re.I),
     r'\1=[REDACTED]'),
    (_re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
     '[SSN]'),
    (_re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
     '[PHONE]'),
]

_REDACT_KEYS = _re.compile(
    r'password|passwd|pwd|secret|token|api_?key|auth|credential|private|authorization',
    _re.I,
)


def mask_pii(value: str) -> str:
    if not isinstance(value, str):
        return value
    for pattern, replacement in _PII_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def mask_context(obj: Any, depth: int = 0) -> Any:
    if depth > 5:
        return obj
    if isinstance(obj, str):
        return mask_pii(obj)
    if isinstance(obj, (list, tuple)):
        masked = [mask_context(v, depth + 1) for v in obj]
        return type(obj)(masked)
    if not isinstance(obj, dict):
        return obj
    out: Dict[str, Any] = {}
    for k, v in obj.items():
        if _REDACT_KEYS.search(str(k)):
            out[k] = '[REDACTED]'
        elif isinstance(v, dict):
            out[k] = mask_context(v, depth + 1)
        elif isinstance(v, (list, tuple)):
            out[k] = mask_context(v, depth + 1)
        elif isinstance(v, str):
            out[k] = mask_pii(v)
        else:
            out[k] = v
    return out


# ── W3C traceparent helpers ───────────────────────────────────────────────────

def _gen_8hex() -> str:
    return secrets.token_hex(8)


def _gen_16hex() -> str:
    return secrets.token_hex(16)


_TRACE_ID_RE = _re.compile(r'^[0-9a-f]{32}$')
_SPAN_ID_RE  = _re.compile(r'^[0-9a-f]{16}$')


def build_traceparent(trace_id: str, span_id: str, sampled: bool = True) -> str:
    tid = (trace_id or '').ljust(32, '0')[:32]
    sid = (span_id  or '').ljust(16, '0')[:16]
    return f'00-{tid}-{sid}-{"01" if sampled else "00"}'


def parse_traceparent(header: str) -> Optional[Dict[str, Any]]:
    if not header or not isinstance(header, str):
        return None
    parts = header.split('-')
    if len(parts) != 4 or parts[0] != '00':
        return None
    trace_id, span_id, flags = parts[1], parts[2], parts[3]
    if not _TRACE_ID_RE.match(trace_id) or not _SPAN_ID_RE.match(span_id):
        return None
    return {'trace_id': trace_id, 'span_id': span_id, 'sampled': flags == '01'}


# ── Layer inference ───────────────────────────────────────────────────────────

_LAYER_PATTERNS: List[Tuple[_re.Pattern, str]] = [
    (_re.compile(r'auth|jwt|token|oauth|permission|acl|rbac|guard|firewall|waf|encrypt|decrypt|password|credential|session|csrf|cors', _re.I), LogLayer.SECURITY),
    (_re.compile(r'repo|repository|dao|database|db|query|migration|schema|cache|redis|mongo|postgres|sql|neo4j|orm|entity|store|persist|storage', _re.I), LogLayer.DATA_ACCESS),
    (_re.compile(r'controller|router|route|middleware|gateway|proxy|handler|endpoint|api|rest|graphql|grpc|webhook|interceptor|view', _re.I), LogLayer.API_GATEWAY),
    (_re.compile(r'service|saga|aggregate|domain|policy|rule|event|command|workflow|process|pricing|discount|fraud|risk|consent', _re.I), LogLayer.DOMAIN),
    (_re.compile(r'infra|worker|job|cron|queue|kafka|rabbit|bull|pubsub|container|health|monitor|metric|cpu|memory|disk|celery', _re.I), LogLayer.INFRASTRUCTURE),
    (_re.compile(r'trace|span|log|alert|metric|telemetry|observer|slo|sla|alarm', _re.I), LogLayer.OBSERVABILITY),
    (_re.compile(r'component|page|ui|render|form|modal|widget|screen|layout|theme|template', _re.I), LogLayer.PRESENTATION),
]

_AUTH_PATH_RE = _re.compile(r'/(login|logout|auth|token|oauth|signin|signup|refresh|verify)', _re.I)
_BOT_UA_RE    = _re.compile(r'bot|crawl|spider|scraper|curl|wget|python-requests|go-http|aiohttp', _re.I)
_MIGRATION_RE = _re.compile(r'^\s*(CREATE|DROP|ALTER)\s+TABLE', _re.I)


def infer_layer(name: str) -> str:
    for pattern, layer in _LAYER_PATTERNS:
        if pattern.search(name):
            return layer
    return LogLayer.BUSINESS_LOGIC


# ── Session registry ──────────────────────────────────────────────────────────
#
# Tracks every unique session that has hit the service. A session is
# identified by X-Session-Id (if present) or auto-generated.
#
# Thread-safe. Purge runs every 60 s. A session is considered "active"
# when its last_seen is within SESSION_TTL seconds of now.

class _SessionEntry:
    __slots__ = ('session_id', 'user_id', 'tenant_id', 'ip', 'user_agent',
                 'started_at', 'last_seen', 'request_count')

    def __init__(self, session_id: str, user_id: str, tenant_id: str,
                 ip: str, user_agent: str):
        now = time.time()
        self.session_id    = session_id
        self.user_id       = user_id
        self.tenant_id     = tenant_id
        self.ip            = ip
        self.user_agent    = user_agent
        self.started_at    = now
        self.last_seen     = now
        self.request_count = 1

    def touch(self, user_id: str = '', tenant_id: str = '') -> None:
        self.last_seen     = time.time()
        self.request_count += 1
        if user_id:
            self.user_id = user_id
        if tenant_id:
            self.tenant_id = tenant_id


class SessionRegistry:
    """
    Keeps a live map of sessions. Thread-safe. Auto-purges expired sessions.

    Usage
    -----
        stats = sentinel.session_stats()
        # {
        #   "active_sessions":  12,
        #   "total_sessions":   847,
        #   "active_users":     10,      # unique user_ids (non-empty) in active set
        #   "active_tenants":   3,
        # }
    """

    def __init__(self, ttl_seconds: int = 1800):
        self._ttl     = ttl_seconds
        self._lock    = threading.Lock()
        self._store:  Dict[str, _SessionEntry] = {}  # session_id → entry
        self._total   = 0  # monotonic counter, never decrements
        self._start_purge_thread()

    # ── Public ────────────────────────────────────────────────────────────────

    def touch(
        self,
        session_id: str,
        user_id:    str = '',
        tenant_id:  str = '',
        ip:         str = '',
        user_agent: str = '',
    ) -> _SessionEntry:
        """Register or refresh a session. Returns the entry."""
        with self._lock:
            if session_id in self._store:
                entry = self._store[session_id]
                entry.touch(user_id, tenant_id)
                return entry
            else:
                entry = _SessionEntry(session_id, user_id, tenant_id, ip, user_agent)
                self._store[session_id] = entry
                self._total += 1
                return entry

    def stats(self) -> Dict[str, Any]:
        """Return live counts."""
        now = time.time()
        with self._lock:
            active = [e for e in self._store.values() if now - e.last_seen < self._ttl]
            return {
                'active_sessions': len(active),
                'total_sessions':  self._total,
                'active_users':    len({e.user_id for e in active if e.user_id}),
                'active_tenants':  len({e.tenant_id for e in active if e.tenant_id}),
            }

    def active_snapshot(self) -> List[Dict[str, Any]]:
        """Return a list of active session dicts (for debugging / dashboards)."""
        now = time.time()
        with self._lock:
            return [
                {
                    'sessionId':    e.session_id,
                    'userId':       e.user_id,
                    'tenantId':     e.tenant_id,
                    'ip':           e.ip,
                    'startedAt':    e.started_at,
                    'lastSeen':     e.last_seen,
                    'requestCount': e.request_count,
                    'idleSecs':     round(now - e.last_seen, 1),
                }
                for e in self._store.values()
                if now - e.last_seen < self._ttl
            ]

    # ── Internal ──────────────────────────────────────────────────────────────

    def _purge(self) -> int:
        """Remove sessions idle longer than TTL. Returns count removed."""
        now = time.time()
        with self._lock:
            dead = [sid for sid, e in self._store.items()
                    if now - e.last_seen >= self._ttl]
            for sid in dead:
                del self._store[sid]
            return len(dead)

    def _start_purge_thread(self) -> None:
        def loop():
            while True:
                time.sleep(60)
                try:
                    self._purge()
                except Exception:
                    pass
        t = threading.Thread(target=loop, daemon=True)
        t.start()


# ── LogRecord ─────────────────────────────────────────────────────────────────

class LogRecord:
    __slots__ = (
        'message', 'level', 'layer', 'timestamp',
        'record_id', 'trace_id', 'span_id',
        'service', 'env', 'context',
        'host', 'version', 'request_id', 'tenant_id',
        'session_id', 'user_id', 'is_audit',
    )

    def __init__(
        self,
        message:    str,
        layer:      str = LogLayer.BUSINESS_LOGIC,
        level:      str = LogLevel.INFO,
        service:    str = 'unknown-python-service',
        context:    Optional[Dict[str, Any]] = None,
        trace_id:   Optional[str] = None,
        span_id:    Optional[str] = None,
        request_id: str = '',
        session_id: str = '',
        user_id:    str = '',
        tenant_id:  str = '',
        is_audit:   bool = False,
    ):
        # Prefer explicitly passed IDs, fall back to ContextVar values
        self.message    = message
        self.layer      = layer
        self.level      = level
        self.service    = service
        self.timestamp  = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.record_id  = str(uuid.uuid4())
        self.trace_id   = trace_id   or _ctx_trace_id.get()   or _gen_16hex()
        self.span_id    = span_id    or _ctx_span_id.get()    or _gen_8hex()
        self.request_id = request_id or _ctx_request_id.get()
        self.session_id = session_id or _ctx_session_id.get()
        self.user_id    = user_id    or _ctx_user_id.get()
        self.tenant_id  = tenant_id  or _ctx_tenant_id.get()
        self.env        = os.getenv('ENV', os.getenv('PYTHON_ENV', 'development'))
        self.host       = os.getenv('HOSTNAME', os.getenv('HOST', socket.gethostname()))
        self.version    = os.getenv('SERVICE_VERSION', os.getenv('APP_VERSION', '0.0.0'))
        self.is_audit   = is_audit
        self.context    = context or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp':  self.timestamp,
            'record_id':  self.record_id,
            'trace_id':   self.trace_id,
            'span_id':    self.span_id,
            'service':    self.service,
            'env':        self.env,
            'host':       self.host,
            'version':    self.version,
            'request_id': self.request_id,
            'session_id': self.session_id,
            'user_id':    self.user_id,
            'tenant_id':  self.tenant_id,
            'layer':      self.layer,
            'level':      self.level,
            'message':    self.message,
            'context':    json.dumps(self.context or {}),
        }

    def __str__(self) -> str:
        _colors = {
            LogLevel.DEBUG: '\033[36m', LogLevel.INFO:  '\033[92m',
            LogLevel.WARN:  '\033[93m', LogLevel.ERROR: '\033[91m',
            LogLevel.FATAL: '\033[95m',
        }
        reset = '\033[0m'
        c = _colors.get(self.level, '\033[92m')
        sid = f' [sess:{self.session_id[:8]}]' if self.session_id else ''
        return (
            f'{c}[{self.timestamp}] [{self.layer.upper()}] [{self.level}]'
            f'[trace:{self.trace_id[:8]}]{sid} {self.message}{reset}'
        )


# ── Disk buffer ───────────────────────────────────────────────────────────────

class _DiskBuffer:
    def __init__(self, directory: str, max_mb: int):
        self._dir       = directory
        self._max_bytes = max_mb * 1024 * 1024
        self._file      = os.path.join(directory, 'sentinel-buffer.ndjson')
        self._lock      = threading.Lock()
        os.makedirs(directory, exist_ok=True)

    def write(self, records: List[LogRecord]) -> None:
        with self._lock:
            try:
                rows = '\n'.join(json.dumps(r.to_dict()) for r in records) + '\n'
                current = self._size()
                if current + len(rows.encode()) >= self._max_bytes:
                    self._rotate()
                with open(self._file, 'a', encoding='utf-8') as f:
                    f.write(rows)
            except Exception:
                pass

    def drain(self) -> List[str]:
        with self._lock:
            try:
                if not os.path.exists(self._file):
                    return []
                with open(self._file, 'r', encoding='utf-8') as f:
                    lines = [line for line in f.read().splitlines() if line.strip()]
                os.unlink(self._file)
                return lines
            except Exception:
                return []

    def _size(self) -> int:
        try:
            return os.path.getsize(self._file)
        except Exception:
            return 0

    def _rotate(self) -> None:
        try:
            with open(self._file, 'r', encoding='utf-8') as f:
                lines = [l for l in f.read().splitlines() if l]
            kept = lines[len(lines) // 2:]
            with open(self._file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(kept) + '\n')
        except Exception:
            pass


# ── ClickHouse batch writer ───────────────────────────────────────────────────

class _ClickHouseWriter:
    def __init__(self, cfg: Dict[str, Any]):
        self._host       = cfg.get('clickhouse_host',     'http://localhost:8123')
        self._db         = cfg.get('clickhouse_database', 'sentinel')
        self._table      = cfg.get('clickhouse_table',    'logs')
        self._user       = cfg.get('clickhouse_user',     '')
        self._password   = cfg.get('clickhouse_password', '')
        self._batch      = cfg.get('batch_size',          50)
        self._debug      = cfg.get('debug',               False)
        self._audit_path = cfg.get(
            'audit_log_path',
            os.path.join(cfg.get('disk_buffer_dir', '/tmp/sentinel'), 'sentinel-audit.ndjson'),
        )
        self._queue:  List[LogRecord] = []
        self._lock    = threading.Lock()
        self._timer:  Optional[threading.Timer] = None
        self._disk_buf = _DiskBuffer(
            cfg.get('disk_buffer_dir', '/tmp/sentinel'),
            cfg.get('disk_buffer_max_mb', 500),
        )

    def init(self) -> None:
        self._exec(f'CREATE DATABASE IF NOT EXISTS {self._db}')
        # session_id, user_id added to schema for per-user tracking
        self._exec(f"""
            CREATE TABLE IF NOT EXISTS {self._db}.{self._table}
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
        """)
        self._schedule_flush()
        threading.Thread(target=self._drain_disk_buffer, daemon=True).start()

    def enqueue(self, record: LogRecord) -> None:
        if record.is_audit:
            self._append_audit(record)
        with self._lock:
            self._queue.append(record)
            if len(self._queue) >= self._batch:
                self._flush_locked()

    def _schedule_flush(self) -> None:
        self._timer = threading.Timer(2.0, self._flush_and_reschedule)
        self._timer.daemon = True
        self._timer.start()

    def _flush_and_reschedule(self) -> None:
        self.flush()
        self._schedule_flush()

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        if not self._queue:
            return
        batch = self._queue[:]
        self._queue.clear()
        rows  = '\n'.join(json.dumps(r.to_dict()) for r in batch)
        query = f'INSERT INTO {self._db}.{self._table} FORMAT JSONEachRow'
        try:
            url  = f'{self._host}/?query={urllib.parse.quote(query, safe="")}'
            data = rows.encode('utf-8')
            req  = urllib.request.Request(url, data=data, method='POST')
            req.add_header('Content-Type', 'application/x-ndjson')
            if self._user:
                cred = base64.b64encode(f'{self._user}:{self._password}'.encode()).decode()
                req.add_header('Authorization', f'Basic {cred}')
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status not in (200, 201):
                    if self._debug:
                        print(f'[SENTINEL] ClickHouse error: {resp.status}', file=sys.stderr)
                    self._disk_buf.write(batch)
        except Exception as exc:
            if self._debug:
                print(f'[SENTINEL] Flush error: {exc}', file=sys.stderr)
            self._disk_buf.write(batch)

    def _drain_disk_buffer(self) -> None:
        lines = self._disk_buf.drain()
        if not lines:
            return
        query = f'INSERT INTO {self._db}.{self._table} FORMAT JSONEachRow'
        try:
            url  = f'{self._host}/?query={urllib.parse.quote(query, safe="")}'
            data = '\n'.join(lines).encode('utf-8')
            req  = urllib.request.Request(url, data=data, method='POST')
            req.add_header('Content-Type', 'application/x-ndjson')
            if self._user:
                cred = base64.b64encode(f'{self._user}:{self._password}'.encode()).decode()
                req.add_header('Authorization', f'Basic {cred}')
            urllib.request.urlopen(req, timeout=10)
        except Exception:
            pass

    def _append_audit(self, record: LogRecord) -> None:
        try:
            os.makedirs(os.path.dirname(self._audit_path), exist_ok=True)
            with open(self._audit_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(record.to_dict()) + '\n')
        except Exception:
            pass

    def _exec(self, query: str) -> None:
        url = f'{self._host}/?query={urllib.parse.quote(query, safe="")}'
        req = urllib.request.Request(url, method='POST')
        if self._user:
            cred = base64.b64encode(f'{self._user}:{self._password}'.encode()).decode()
            req.add_header('Authorization', f'Basic {cred}')
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status not in (200, 201):
                raise RuntimeError(f'ClickHouse DDL failed: status={resp.status}')


# ── OTel OTLP/HTTP exporter ───────────────────────────────────────────────────

_SEVERITY_MAP = {
    LogLevel.DEBUG: 5, LogLevel.INFO: 9, LogLevel.WARN: 13,
    LogLevel.ERROR: 17, LogLevel.FATAL: 21,
}


class _OtlpExporter:
    def __init__(self, endpoint: str):
        self._endpoint = endpoint.rstrip('/') + '/v1/logs'
        self._queue:   List[LogRecord] = []
        self._lock     = threading.Lock()
        self._start_flush()

    def enqueue(self, record: LogRecord) -> None:
        with self._lock:
            self._queue.append(record)
            if len(self._queue) >= 50:
                threading.Thread(target=self._flush, daemon=True).start()

    def _start_flush(self) -> None:
        def loop():
            while True:
                time.sleep(2)
                self._flush()
        threading.Thread(target=loop, daemon=True).start()

    def _flush(self) -> None:
        with self._lock:
            if not self._queue:
                return
            batch = self._queue[:]
            self._queue.clear()

        if not batch:
            return

        first = batch[0]
        body  = {
            'resourceLogs': [{
                'resource': {
                    'attributes': _kv_list({
                        'service.name':    first.service,
                        'host.name':       first.host,
                        'service.version': first.version,
                    }),
                },
                'scopeLogs': [{
                    'scope': {'name': 'sentinel-sdk'},
                    'logRecords': [
                        {
                            'timeUnixNano':   str(int(
                                datetime.datetime.fromisoformat(r.timestamp)
                                .timestamp() * 1_000_000_000
                            )),
                            'severityNumber': _SEVERITY_MAP.get(r.level, 9),
                            'severityText':   r.level,
                            'traceId':        r.trace_id,
                            'spanId':         r.span_id,
                            'body':           {'stringValue': r.message},
                            'attributes':     _kv_list({
                                'layer':      r.layer,
                                'env':        r.env,
                                'request_id': r.request_id,
                                'session_id': r.session_id,
                                'user_id':    r.user_id,
                                'tenant_id':  r.tenant_id,
                                **_flatten_ctx(r.context),
                            }),
                        }
                        for r in batch
                    ],
                }],
            }],
        }

        try:
            data = json.dumps(body).encode('utf-8')
            req  = urllib.request.Request(self._endpoint, data=data, method='POST')
            req.add_header('Content-Type', 'application/json')
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass


def _kv_list(obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for k, v in obj.items():
        if v is None:
            continue
        if isinstance(v, bool):
            out.append({'key': k, 'value': {'boolValue': v}})
        elif isinstance(v, (int, float)):
            out.append({'key': k, 'value': {'doubleValue': float(v)}})
        else:
            out.append({'key': k, 'value': {'stringValue': str(v)}})
    return out


def _flatten_ctx(ctx: Any, prefix: str = '', depth: int = 0) -> Dict[str, Any]:
    if depth > 3 or not isinstance(ctx, dict):
        return {}
    out: Dict[str, Any] = {}
    for k, v in ctx.items():
        key = f'{prefix}.{k}' if prefix else k
        if isinstance(v, dict):
            out.update(_flatten_ctx(v, key, depth + 1))
        else:
            out[key] = v
    return out

# ... end of _OtlpExporter class ...


# ── Browser ingest relay ──────────────────────────────────────────────────────

def _cors_headers(origin: Optional[str], allowed_origins: List[str]) -> Dict[str, str]:
    if not allowed_origins:
        allow = origin or '*'
    elif origin in allowed_origins:
        allow = origin
    else:
        return {}
    return {
        'Access-Control-Allow-Origin':  allow,
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, X-Sentinel',
        'Access-Control-Max-Age':       '86400',
    }


def _write_browser_batch(records: List[Dict[str, Any]], writer: _ClickHouseWriter, debug: bool = False) -> None:
    if not records:
        return
    out = []
    for r in records:
        ctx = r.get('context') or {}
        if isinstance(ctx, str):
            try:    ctx = json.loads(ctx)
            except: ctx = {}
        out.append(LogRecord(
            message=    r.get('message')  or '',
            layer=      r.get('layer')    or LogLayer.PRESENTATION,
            level=      r.get('level')    or LogLevel.INFO,
            service=    r.get('service')  or 'browser',
            context=    ctx,
            trace_id=   r.get('trace_id') or ctx.get('traceId') or _gen_16hex(),
            session_id= ctx.get('sessionId') or '',
            user_id=    ctx.get('userId')    or '',
            tenant_id=  ctx.get('tenantId')  or '',
        ))
    for record in out:
        writer.enqueue(record)


def mount_fastapi_ingest(app: Any, writer: _ClickHouseWriter, cfg: Dict[str, Any]) -> None:
    allowed = [o.strip() for o in os.getenv('SENTINEL_ALLOWED_ORIGINS', '').split(',') if o.strip()]
    try:
        from fastapi import Request
        from fastapi.responses import Response
    except ImportError:
        raise RuntimeError('FastAPI not installed')

    @app.options('/sentinel/ingest', include_in_schema=False)
    async def _opt(request: Request) -> Response:
        return Response(status_code=204, headers=_cors_headers(request.headers.get('origin'), allowed))

    @app.post('/sentinel/ingest', include_in_schema=False)
    async def _post(request: Request) -> Response:
        cors = _cors_headers(request.headers.get('origin'), allowed)
        try:
            import asyncio
            records = json.loads(await request.body() or b'[]')
            if not isinstance(records, list): records = [records]
            await asyncio.get_event_loop().run_in_executor(
                None, _write_browser_batch, records, writer, cfg.get('debug', False)
            )
            return Response(status_code=204, headers=cors)
        except Exception as exc:
            if cfg.get('debug'): print(f'[SENTINEL ingest] {exc}', file=sys.stderr)
            return Response(content=json.dumps({'error': 'ingest failed'}), status_code=500,
                            media_type='application/json', headers=cors)


def mount_flask_ingest(app: Any, writer: _ClickHouseWriter, cfg: Dict[str, Any]) -> None:
    allowed = [o.strip() for o in os.getenv('SENTINEL_ALLOWED_ORIGINS', '').split(',') if o.strip()]
    try:
        from flask import request, make_response
    except ImportError:
        raise RuntimeError('Flask not installed')

    @app.route('/sentinel/ingest', methods=['OPTIONS', 'POST'])
    def _sentinel_ingest():
        cors = _cors_headers(request.headers.get('Origin'), allowed)
        if request.method == 'OPTIONS':
            resp = make_response('', 204)
        else:
            try:
                records = request.get_json(force=True, silent=True) or []
                if not isinstance(records, list): records = [records]
                _write_browser_batch(records, writer, cfg.get('debug', False))
                resp = make_response('', 204)
            except Exception as exc:
                if cfg.get('debug'): print(f'[SENTINEL ingest] {exc}', file=sys.stderr)
                resp = make_response(json.dumps({'error': 'ingest failed'}), 500)
                resp.headers['Content-Type'] = 'application/json'
        for k, v in cors.items(): resp.headers[k] = v
        return resp


# ── SentinelMeta — zero-effort class instrumentation ─────────────────────────

class SentinelMeta(type):
    """
    Metaclass — every non-dunder method is auto-wrapped with
    enter / exit / error / duration logging.

        class OrderService(metaclass=SentinelMeta):
            _sentinel_layer = LogLayer.DOMAIN
            ...
    """
    _sentinel_agent: Optional['SentinelPython'] = None

    def __new__(mcs, name, bases, namespace, **kwargs):
        cls   = super().__new__(mcs, name, bases, namespace, **kwargs)
        layer = namespace.get('_sentinel_layer') or infer_layer(name)
        for attr, val in namespace.items():
            if attr.startswith('_'):
                continue
            if callable(val) and not isinstance(val, (classmethod, staticmethod, property)):
                setattr(cls, attr, mcs._wrap(val, name, attr, layer))
        return cls

    @staticmethod
    def _wrap(fn: Callable, cls_name: str, method: str, layer: str) -> Callable:
        is_async = inspect.iscoroutinefunction(fn)

        if is_async:
            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                agent = SentinelMeta._sentinel_agent
                start = time.perf_counter()
                if agent:
                    agent._emit(
                        f'{cls_name}.{method} called',
                        layer=layer, level=LogLevel.INFO,
                        context={'className': cls_name, 'functionName': method, 'isAsync': True},
                    )
                try:
                    result = await fn(*args, **kwargs)
                    ms = (time.perf_counter() - start) * 1000
                    if agent:
                        agent._emit(
                            f'{cls_name}.{method} → ok ({ms:.1f}ms)',
                            layer=layer, level=LogLevel.INFO,
                            context={
                                'className': cls_name, 'functionName': method,
                                'durationMs': ms, 'isAsync': True,
                            },
                        )
                    return result
                except Exception as exc:
                    ms = (time.perf_counter() - start) * 1000
                    if agent:
                        agent._emit(
                            f'{cls_name}.{method} → error: {exc}',
                            layer=layer, level=LogLevel.ERROR,
                            context={
                                'className': cls_name, 'functionName': method,
                                'durationMs': ms, 'isAsync': True,
                                'exceptionType': type(exc).__name__,
                                'stackTrace': traceback.format_exc(),
                            },
                        )
                    raise
            return async_wrapper
        else:
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                agent = SentinelMeta._sentinel_agent
                start = time.perf_counter()
                if agent:
                    agent._emit(
                        f'{cls_name}.{method} called',
                        layer=layer, level=LogLevel.INFO,
                        context={'className': cls_name, 'functionName': method, 'isAsync': False},
                    )
                try:
                    result = fn(*args, **kwargs)
                    ms = (time.perf_counter() - start) * 1000
                    if agent:
                        agent._emit(
                            f'{cls_name}.{method} → ok ({ms:.1f}ms)',
                            layer=layer, level=LogLevel.INFO,
                            context={
                                'className': cls_name, 'functionName': method,
                                'durationMs': ms, 'isAsync': False,
                            },
                        )
                    return result
                except Exception as exc:
                    ms = (time.perf_counter() - start) * 1000
                    if agent:
                        agent._emit(
                            f'{cls_name}.{method} → error: {exc}',
                            layer=layer, level=LogLevel.ERROR,
                            context={
                                'className': cls_name, 'functionName': method,
                                'durationMs': ms, 'isAsync': False,
                                'exceptionType': type(exc).__name__,
                                'stackTrace': traceback.format_exc(),
                            },
                        )
                    raise
            return wrapper


T = TypeVar('T')


# ── Health server ─────────────────────────────────────────────────────────────

class _HealthServer(threading.Thread):
    def __init__(self, port: int, service_name: str, process_start: float,
                 session_registry: SessionRegistry):
        super().__init__(daemon=True)
        self._port             = port
        self._service_name     = service_name
        self._process_start    = process_start
        self._ready            = False
        self._session_registry = session_registry

    def set_ready(self) -> None:
        self._ready = True

    def run(self) -> None:
        import http.server

        srv = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/health':
                    body = json.dumps({
                        'status':  'ok',
                        'service': srv._service_name,
                        'uptime':  round(time.time() - srv._process_start, 2),
                        'pid':     os.getpid(),
                    }).encode()
                    self._respond(200, body)
                elif self.path == '/ready':
                    code = 200 if srv._ready else 503
                    body = json.dumps(
                        {'status': 'ready' if srv._ready else 'not_ready'}
                    ).encode()
                    self._respond(code, body)
                elif self.path == '/sessions':
                    # Live session stats — useful for ops dashboards
                    body = json.dumps(srv._session_registry.stats()).encode()
                    self._respond(200, body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def _respond(self, code: int, body: bytes) -> None:
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        class _ThreadingHTTPServer(
            http.server.ThreadingHTTPServer
            if hasattr(http.server, 'ThreadingHTTPServer')
            else http.server.HTTPServer
        ):
            pass

        with _ThreadingHTTPServer(('0.0.0.0', self._port), Handler) as httpd:
            httpd.serve_forever()


# ── Main agent ────────────────────────────────────────────────────────────────

class SentinelPython:
    def __init__(self, service_name: str = 'python-service', **cfg):
        self.service_name   = service_name
        self._process_start = time.time()
        self._net_bytes_in  = 0
        self._net_bytes_out = 0

        _disk_dir = cfg.get('disk_buffer_dir', os.path.join('/tmp', 'sentinel'))

        self._cfg = {
            'clickhouse_host':     cfg.get('clickhouse_host',     os.getenv('CLICKHOUSE_HOST',     os.getenv('SENTINEL_CLICKHOUSE_HOST',  'http://localhost:8123'))),
            'clickhouse_database': cfg.get('clickhouse_database', os.getenv('CLICKHOUSE_DATABASE', os.getenv('SENTINEL_CLICKHOUSE_DB',    'sentinel'))),
            'clickhouse_table':    cfg.get('clickhouse_table',    os.getenv('CLICKHOUSE_TABLE',    os.getenv('SENTINEL_CLICKHOUSE_TABLE', 'logs'))),
            'clickhouse_user':     cfg.get('clickhouse_user',     os.getenv('CLICKHOUSE_USER',     os.getenv('SENTINEL_CLICKHOUSE_USER',  ''))),
            'clickhouse_password': cfg.get('clickhouse_password', os.getenv('CLICKHOUSE_PASSWORD', os.getenv('SENTINEL_CLICKHOUSE_PASS',  ''))),
            'batch_size':          cfg.get('batch_size',          int(os.getenv('SENTINEL_BATCH_SIZE', '50'))),
            'slow_query_ms':       cfg.get('slow_query_ms',       int(os.getenv('SENTINEL_SLOW_QUERY_MS',    '200'))),
            'slow_http_ms':        cfg.get('slow_http_ms',        int(os.getenv('SENTINEL_SLOW_HTTP_MS',     '1000'))),
            'slow_function_ms':    cfg.get('slow_function_ms',    int(os.getenv('SENTINEL_SLOW_FUNCTION_MS', '500'))),
            'debug':               cfg.get('debug',               os.getenv('SENTINEL_DEBUG', 'false').lower() == 'true'),
            'sampling_rate':       cfg.get('sampling_rate',       float(os.getenv('SENTINEL_SAMPLING_RATE', '1.0'))),
            'cert_check_hosts':    cfg.get('cert_check_hosts',    [h for h in os.getenv('SENTINEL_CERT_HOSTS', '').split(',') if h]),
            'cert_check_interval': cfg.get('cert_check_interval', int(os.getenv('SENTINEL_CERT_INTERVAL', str(6 * 3600)))),
            'otlp_endpoint':       cfg.get('otlp_endpoint',       os.getenv('OTEL_EXPORTER_OTLP_ENDPOINT', os.getenv('SENTINEL_OTLP_ENDPOINT', ''))),
            'health_port':         int(cfg.get('health_port',     os.getenv('SENTINEL_HEALTH_PORT', '9090'))),
            'log_level':           (cfg.get('log_level') or os.getenv('LOG_LEVEL', os.getenv('SENTINEL_LOG_LEVEL', LogLevel.DEBUG))).upper(),
            'disk_buffer_dir':     _disk_dir,
            'disk_buffer_max_mb':  cfg.get('disk_buffer_max_mb',  int(os.getenv('SENTINEL_DISK_MAX_MB', '500'))),
            'audit_log_path':      cfg.get('audit_log_path',      os.path.join(_disk_dir, 'sentinel-audit.ndjson')),
            'session_ttl':         int(cfg.get('session_ttl',     os.getenv('SENTINEL_SESSION_TTL', '1800'))),
            'enabled':             cfg.get('enabled',             os.getenv('SENTINEL_ENABLED', 'true').lower() != 'false'),
        }

        self._enabled        = self._cfg['enabled']
        self._min_level      = self._cfg['log_level']
        self._writer         = _ClickHouseWriter(self._cfg)
        self._otlp           = _OtlpExporter(self._cfg['otlp_endpoint']) if self._cfg['otlp_endpoint'] else None
        self._sessions       = SessionRegistry(ttl_seconds=self._cfg['session_ttl'])
        self._health         = _HealthServer(
            self._cfg['health_port'], service_name,
            self._process_start, self._sessions,
        )
        self._instrumented: set = set()
        # Process-level fallback trace_id (used only when no request context is active)
        self._process_trace_id = _gen_16hex()

    # ── Public API ────────────────────────────────────────────────────────────

    def hook(self) -> 'SentinelPython':
        """Call once at startup — patches everything."""
        if not self._enabled:
            return self
        self._writer.init()
        self._health.start()

        SentinelMeta._sentinel_agent = self

        self._patch_print()
        self._patch_logging()
        self._patch_requests()
        self._patch_httpx()
        self._patch_sqlalchemy()
        self._patch_psycopg2()
        self._patch_neo4j()
        self._patch_redis()
        self._patch_queues()
        self._hook_process()
        self._start_vitals()
        if self._cfg['cert_check_hosts']:
            self._start_cert_monitor()

        self._health.set_ready()

        self._emit(
            f'Sentinel Python Agent v4.0 hooked on "{self.service_name}"',
            layer=LogLayer.INFRASTRUCTURE, level=LogLevel.INFO,
            context={
                'python_version':       sys.version,
                'pid':                  os.getpid(),
                'processUptimeSeconds': 0,
                'cpuCoreCount':         os.cpu_count() or 1,
                'host':                 os.getenv('HOSTNAME', socket.gethostname()),
                'version':              os.getenv('SERVICE_VERSION', '0.0.0'),
                'sessionTtlSeconds':    self._cfg['session_ttl'],
            },
        )
        return self

    def disable(self) -> None:
        self._enabled = False

    def enable(self) -> None:
        self._enabled = True

    def set_log_level(self, level: str) -> None:
        self._min_level = level.upper()

    def session_stats(self) -> Dict[str, Any]:
        """
        Return live session counts.

        Returns
        -------
        {
            "active_sessions": int,   # sessions seen within SESSION_TTL
            "total_sessions":  int,   # all sessions since process start
            "active_users":    int,   # distinct user_ids in active set
            "active_tenants":  int,   # distinct tenant_ids in active set
        }
        """
        return self._sessions.stats()

    def active_sessions(self) -> List[Dict[str, Any]]:
        """Return detailed list of active session dicts (for dashboards)."""
        return self._sessions.active_snapshot()

    def instrument(self, target: Any, layer: Optional[str] = None) -> 'SentinelPython':
        cls    = target if isinstance(target, type) else type(target)
        cls_id = id(cls)
        if cls_id in self._instrumented:
            return self
        self._instrumented.add(cls_id)

        resolved_layer = layer or infer_layer(cls.__name__)
        methods = [
            name for name, val in inspect.getmembers(cls, predicate=inspect.isfunction)
            if not name.startswith('__')
        ]
        for method_name in methods:
            try:
                orig    = getattr(cls, method_name)
                wrapped = SentinelMeta._wrap(orig, cls.__name__, method_name, resolved_layer)
                setattr(cls, method_name, wrapped)
            except (AttributeError, TypeError):
                pass

        self._emit(
            f'Instrumented: {cls.__name__} ({len(methods)} methods → {resolved_layer})',
            layer=LogLayer.OBSERVABILITY, level=LogLevel.DEBUG,
        )
        return self

    def track(self, layer: str = LogLayer.BUSINESS_LOGIC, slow_ms: Optional[float] = None):
        """Decorator for standalone functions (sync or async)."""
        def decorator(fn: Callable) -> Callable:
            threshold = slow_ms or self._cfg['slow_function_ms']
            is_async  = inspect.iscoroutinefunction(fn)

            if is_async:
                @functools.wraps(fn)
                async def async_wrapper(*args, **kwargs):
                    start = time.perf_counter()
                    self._emit(
                        f'{fn.__qualname__} called',
                        layer=layer, level=LogLevel.INFO,
                        context={'functionName': fn.__qualname__, 'isAsync': True},
                    )
                    try:
                        result = await fn(*args, **kwargs)
                        ms = (time.perf_counter() - start) * 1000
                        self._emit(
                            f'{fn.__qualname__} → ok ({ms:.1f}ms){"[SLOW]" if ms > threshold else ""}',
                            layer=layer,
                            level=LogLevel.WARN if ms > threshold else LogLevel.INFO,
                            context={'functionName': fn.__qualname__, 'durationMs': ms, 'isAsync': True},
                        )
                        return result
                    except Exception as exc:
                        ms = (time.perf_counter() - start) * 1000
                        self._emit(
                            f'{fn.__qualname__} → error: {exc}',
                            layer=layer, level=LogLevel.ERROR,
                            context={
                                'functionName': fn.__qualname__, 'durationMs': ms, 'isAsync': True,
                                'exceptionType': type(exc).__name__,
                                'stackTrace': traceback.format_exc(),
                            },
                        )
                        raise
                return async_wrapper
            else:
                @functools.wraps(fn)
                def wrapper(*args, **kwargs):
                    start = time.perf_counter()
                    self._emit(
                        f'{fn.__qualname__} called',
                        layer=layer, level=LogLevel.INFO,
                        context={'functionName': fn.__qualname__, 'isAsync': False},
                    )
                    try:
                        result = fn(*args, **kwargs)
                        ms = (time.perf_counter() - start) * 1000
                        self._emit(
                            f'{fn.__qualname__} → ok ({ms:.1f}ms){"[SLOW]" if ms > threshold else ""}',
                            layer=layer,
                            level=LogLevel.WARN if ms > threshold else LogLevel.INFO,
                            context={'functionName': fn.__qualname__, 'durationMs': ms, 'isAsync': False},
                        )
                        return result
                    except Exception as exc:
                        ms = (time.perf_counter() - start) * 1000
                        self._emit(
                            f'{fn.__qualname__} → error: {exc}',
                            layer=layer, level=LogLevel.ERROR,
                            context={
                                'functionName': fn.__qualname__, 'durationMs': ms, 'isAsync': False,
                                'exceptionType': type(exc).__name__,
                                'stackTrace': traceback.format_exc(),
                            },
                        )
                        raise
                return wrapper
        return decorator

    def log(self, message: str, layer: str = LogLayer.BUSINESS_LOGIC,
            level: str = LogLevel.INFO, context: Optional[Dict] = None) -> None:
        self._emit(message, layer=layer, level=level, context=context)

    def audit(self, message: str, context: Optional[Dict] = None) -> None:
        self._emit(message, layer=LogLayer.SECURITY, level=LogLevel.INFO,
                   context=context, is_audit=True)

    def flush(self) -> None:
        self._writer.flush()

    # ── Internal emitter ──────────────────────────────────────────────────────

    def _emit(
        self,
        message:    str,
        layer:      str = LogLayer.BUSINESS_LOGIC,
        level:      str = LogLevel.INFO,
        context:    Optional[Dict] = None,
        trace_id:   Optional[str] = None,
        is_audit:   bool = False,
    ) -> None:
        if not self._enabled:
            return

        if not is_audit and _LEVEL_ORDER.get(level, 0) < _LEVEL_ORDER.get(self._min_level, 0):
            return

        rate = self._cfg['sampling_rate']
        if not is_audit and rate < 1.0:
            if level in (LogLevel.INFO, LogLevel.DEBUG):
                import random
                if random.random() > rate:
                    return

        raw_ctx = dict(context or {})
        raw_ctx.setdefault('samplingRate',     rate)
        raw_ctx.setdefault('samplingDecision', 'sampled')

        ctx = mask_context(raw_ctx)

        # Use the explicitly passed trace_id first; ContextVar second;
        # process-level fallback last (background threads / startup logs)
        effective_trace_id = (
            trace_id
            or _ctx_trace_id.get()
            or self._process_trace_id
        )
        if effective_trace_id == 'untracked':
            effective_trace_id = self._process_trace_id

        record = LogRecord(
            message=message,
            layer=layer,
            level=level,
            service=self.service_name,
            context=ctx,
            trace_id=effective_trace_id,
            is_audit=is_audit,
        )
        if self._cfg['debug']:
            print(f'[SENTINEL] {record}', file=sys.stderr)

        self._writer.enqueue(record)
        if self._otlp:
            self._otlp.enqueue(record)

    # ── Shared request-context setup (used by both Flask and FastAPI) ─────────

    def _resolve_request_context(
        self,
        traceparent_header: Optional[str],
        session_id_header:  Optional[str],
        user_id:            str = '',
        tenant_id:          str = '',
        ip:                 str = '',
        user_agent:         str = '',
    ) -> Tuple[str, str, str]:
        """
        Resolve or generate trace_id, span_id, session_id for an incoming
        request and register the session.

        Returns (trace_id, span_id, session_id).
        """
        # Trace propagation
        trace_id = self._process_trace_id
        span_id  = _gen_8hex()
        if traceparent_header:
            parsed = parse_traceparent(traceparent_header)
            if parsed:
                trace_id = parsed['trace_id']
                span_id  = parsed['span_id']
        else:
            # New inbound request with no traceparent → mint a fresh trace_id
            trace_id = _gen_16hex()

        # Session resolution
        session_id = session_id_header or secrets.token_hex(16)
        self._sessions.touch(
            session_id=session_id,
            user_id=user_id,
            tenant_id=tenant_id,
            ip=ip,
            user_agent=user_agent,
        )

        # Bind everything to ContextVar so downstream calls inherit them
        _bind_request_context(
            trace_id=trace_id,
            span_id=span_id,
            request_id=_gen_8hex(),
            session_id=session_id,
            user_id=user_id,
            tenant_id=tenant_id,
        )

        return trace_id, span_id, session_id

    # ── Flask middleware ──────────────────────────────────────────────────────

    def flask_middleware(self, app: Any) -> Any:
        sentinel = self

        @app.before_request
        def before():
            import flask
            req         = flask.request
            body_bytes  = int(req.content_length or 0)
            sentinel._net_bytes_in += body_bytes

            trace_id, span_id, session_id = sentinel._resolve_request_context(
                traceparent_header=req.headers.get('traceparent'),
                session_id_header=req.headers.get('X-Session-Id'),
                user_id=req.headers.get('X-User-Id', ''),
                tenant_id=req.headers.get('X-Tenant-Id', ''),
                ip=req.remote_addr or '',
                user_agent=req.headers.get('User-Agent', ''),
            )
            flask.g._sentinel_start      = time.perf_counter()
            flask.g._sentinel_trace_id   = trace_id
            flask.g._sentinel_session_id = session_id

            sentinel._emit(
                f'→ {req.method} {req.path}',
                layer=LogLayer.API_GATEWAY, level=LogLevel.INFO,
                context=mask_context({
                    'method': req.method, 'path': req.path,
                    'clientIp': req.remote_addr, 'userAgent': req.headers.get('User-Agent'),
                    'userId': req.headers.get('X-User-Id'),
                    'sessionId': session_id,
                    'requestSizeBytes': body_bytes,
                    'corsOrigin': req.headers.get('Origin'),
                    **sentinel._sessions.stats(),
                }),
            )

        @app.after_request
        def after(response):
            import flask
            req        = flask.request
            ms         = (time.perf_counter() - getattr(flask.g, '_sentinel_start', time.perf_counter())) * 1000
            trace_id   = getattr(flask.g, '_sentinel_trace_id',   sentinel._process_trace_id)
            session_id = getattr(flask.g, '_sentinel_session_id', '')

            res_bytes = int(response.content_length or 0)
            sentinel._net_bytes_out += res_bytes

            response.headers['traceparent'] = build_traceparent(trace_id, _gen_8hex())
            response.headers['X-Session-Id'] = session_id

            rate_limit_hit       = response.status_code == 429
            rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', -1))
            cors_violation       = response.status_code == 403 and bool(req.headers.get('Origin'))
            bot_signal           = bool(_BOT_UA_RE.search(req.headers.get('User-Agent', '')))

            is_auth_path    = bool(_AUTH_PATH_RE.search(req.path))
            is_auth_failure = response.status_code in (401, 403)
            if is_auth_path or is_auth_failure:
                sentinel._emit(
                    f'Auth event: {req.method} {req.path} → {response.status_code}',
                    layer=LogLayer.SECURITY,
                    level=LogLevel.WARN if is_auth_failure else LogLevel.INFO,
                    is_audit=True,
                    context=mask_context({
                        'authResult':    'success' if response.status_code < 400 else 'failure',
                        'ipAddress':     req.remote_addr, 'userAgent': req.headers.get('User-Agent'),
                        'path': req.path, 'userId': req.headers.get('X-User-Id'),
                        'sessionId':     session_id,
                        'failureReason': f'HTTP {response.status_code}' if is_auth_failure else None,
                    }),
                )

            sentinel._emit(
                f'← {req.method} {req.path} {response.status_code} ({ms:.1f}ms)'
                f'{"[SLOW]" if ms > sentinel._cfg["slow_http_ms"] else ""}'
                f'{"[RATE-LIMITED]" if rate_limit_hit else ""}',
                layer=LogLayer.API_GATEWAY,
                level=(LogLevel.ERROR if response.status_code >= 500
                       else LogLevel.WARN if response.status_code >= 400
                       else LogLevel.INFO),
                context=mask_context({
                    'method': req.method, 'path': req.path,
                    'statusCode': response.status_code, 'durationMs': ms,
                    'sessionId': session_id,
                    'rateLimitHit': rate_limit_hit,
                    'rateLimitRemaining': rate_limit_remaining if rate_limit_remaining >= 0 else None,
                    'responseSizeBytes': res_bytes or None,
                    'corsViolation': cors_violation, 'botSignal': bot_signal,
                }),
            )
            return response

        return app

    # ── FastAPI / ASGI middleware ─────────────────────────────────────────────

    def fastapi_middleware(self, app: Any) -> Any:
        sentinel = self

        class _Middleware:
            def __init__(self, asgi_app):
                self.app = asgi_app

            async def __call__(self, scope, receive, send):
                if scope['type'] != 'http':
                    await self.app(scope, receive, send)
                    return

                start      = time.perf_counter()
                method     = scope.get('method', '')
                path       = scope.get('path', '')
                headers    = {k.decode(): v.decode() for k, v in scope.get('headers', [])}
                origin     = headers.get('origin', '')
                user_agent = headers.get('user-agent', '')
                user_id    = headers.get('x-user-id', '')
                tenant_id  = headers.get('x-tenant-id', '')
                client_ip  = (scope.get('client') or [''])[0]

                body_size = int(headers.get('content-length', 0))
                sentinel._net_bytes_in += body_size

                trace_id, span_id, session_id = sentinel._resolve_request_context(
                    traceparent_header=headers.get('traceparent'),
                    session_id_header=headers.get('x-session-id'),
                    user_id=user_id,
                    tenant_id=tenant_id,
                    ip=client_ip,
                    user_agent=user_agent,
                )

                sentinel._emit(
                    f'→ {method} {path}',
                    layer=LogLayer.API_GATEWAY, level=LogLevel.INFO,
                    context=mask_context({
                        'method': method, 'path': path,
                        'userAgent': user_agent, 'userId': user_id,
                        'sessionId': session_id,
                        'corsOrigin': origin or None,
                        'requestSizeBytes': body_size,
                        **sentinel._sessions.stats(),
                    }),
                )

                status_code = [200]
                res_bytes   = [0]

                async def send_wrapper(message):
                    if message['type'] == 'http.response.start':
                        status_code[0] = message['status']
                        new_headers = list(message.get('headers', []))
                        new_headers.append((
                            b'traceparent',
                            build_traceparent(trace_id, _gen_8hex()).encode(),
                        ))
                        new_headers.append((b'x-session-id', session_id.encode()))
                        message = dict(message)
                        message['headers'] = new_headers
                    elif message['type'] == 'http.response.body':
                        chunk = message.get('body', b'')
                        res_bytes[0] += len(chunk)
                        sentinel._net_bytes_out += len(chunk)
                    await send(message)

                await self.app(scope, receive, send_wrapper)

                ms              = (time.perf_counter() - start) * 1000
                sc              = status_code[0]
                rate_limit_hit  = sc == 429
                cors_violation  = sc == 403 and bool(origin)
                bot_signal      = bool(_BOT_UA_RE.search(user_agent))
                is_auth_path    = bool(_AUTH_PATH_RE.search(path))
                is_auth_failure = sc in (401, 403)

                if is_auth_path or is_auth_failure:
                    sentinel._emit(
                        f'Auth event: {method} {path} → {sc}',
                        layer=LogLayer.SECURITY,
                        level=LogLevel.WARN if is_auth_failure else LogLevel.INFO,
                        is_audit=True,
                        context=mask_context({
                            'authResult':    'success' if sc < 400 else 'failure',
                            'path': path, 'statusCode': sc, 'userAgent': user_agent,
                            'sessionId': session_id,
                            'failureReason': f'HTTP {sc}' if is_auth_failure else None,
                        }),
                    )

                sentinel._emit(
                    f'← {method} {path} {sc} ({ms:.1f}ms)'
                    f'{"[SLOW]" if ms > sentinel._cfg["slow_http_ms"] else ""}'
                    f'{"[RATE-LIMITED]" if rate_limit_hit else ""}',
                    layer=LogLayer.API_GATEWAY,
                    level=LogLevel.ERROR if sc >= 500 else LogLevel.WARN if sc >= 400 else LogLevel.INFO,
                    context=mask_context({
                        'method': method, 'path': path, 'statusCode': sc, 'durationMs': ms,
                        'sessionId': session_id,
                        'rateLimitHit': rate_limit_hit, 'corsViolation': cors_violation,
                        'botSignal': bot_signal,
                        'responseSizeBytes': res_bytes[0] or None,
                    }),
                )

        app.add_middleware(_Middleware)
        return app

         # ── Browser ingest mounters ───────────────────────────────────────────────

    def mount_fastapi_ingest(self, app: Any) -> None:
        """Register /sentinel/ingest on a FastAPI app for browser log ingestion."""
        mount_fastapi_ingest(app, self._writer, self._cfg)

    def mount_flask_ingest(self, app: Any) -> None:
        """Register /sentinel/ingest on a Flask app for browser log ingestion."""
        mount_flask_ingest(app, self._writer, self._cfg)
    # ── print() patch ─────────────────────────────────────────────────────────

    def _patch_print(self) -> None:
        sentinel   = self
        orig_print = builtins.print

        def sentinel_print(*args, **kwargs):
            msg = ' '.join(str(a) for a in args)
            if '[SENTINEL]' in msg:
                orig_print(*args, **kwargs)
                return
            sentinel._emit(mask_pii(msg), layer=LogLayer.BUSINESS_LOGIC, level=LogLevel.INFO)
            orig_print(f'[SENTINEL] {msg}', **kwargs)

        builtins.print = sentinel_print

    # ── logging module patch ──────────────────────────────────────────────────

    def _patch_logging(self) -> None:
        sentinel = self
        _LEVEL_MAP = {
            logging.DEBUG:    LogLevel.DEBUG,
            logging.INFO:     LogLevel.INFO,
            logging.WARNING:  LogLevel.WARN,
            logging.ERROR:    LogLevel.ERROR,
            logging.CRITICAL: LogLevel.FATAL,
        }

        class SentinelHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                sentinel._emit(
                    mask_pii(record.getMessage()),
                    layer=LogLayer.OBSERVABILITY,
                    level=_LEVEL_MAP.get(record.levelno, LogLevel.INFO),
                    context={'logger': record.name, 'module': record.module, 'funcName': record.funcName},
                )

        logging.getLogger().addHandler(SentinelHandler())

    # ── requests patch ────────────────────────────────────────────────────────

    def _patch_requests(self) -> None:
        if not HAS_REQUESTS:
            return
        sentinel  = self
        orig_send = _requests.Session.send

        def patched_send(self_session, request, **kwargs):
            start = time.perf_counter()
            url   = str(request.url)
            try:
                body_bytes = len(request.body) if isinstance(request.body, (bytes, str)) else 0
            except TypeError:
                body_bytes = 0
            sentinel._net_bytes_in += body_bytes

            # Propagate current request's trace context downstream
            current_trace = _ctx_trace_id.get() or sentinel._process_trace_id
            span_id = _gen_8hex()
            request.headers['traceparent'] = build_traceparent(current_trace, span_id)

            sentinel._emit(
                f'→ {request.method} {mask_pii(url)}',
                layer=LogLayer.SERVICE, level=LogLevel.INFO,
                context={'method': request.method, 'path': mask_pii(url), 'requestSizeBytes': body_bytes},
            )
            try:
                response = orig_send(self_session, request, **kwargs)
                ms = (time.perf_counter() - start) * 1000
                sc = response.status_code
                res_bytes = len(response.content) if response.content else 0
                sentinel._net_bytes_out += res_bytes

                rate_limit_hit       = sc == 429
                rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', -1))
                retry_count          = int(request.headers.get('X-Retry-Count', 0))

                if _AUTH_PATH_RE.search(url) or sc in (401, 403):
                    sentinel._emit(
                        f'Auth event: {request.method} {mask_pii(url)} → {sc}',
                        layer=LogLayer.SECURITY,
                        level=LogLevel.WARN if sc >= 400 else LogLevel.INFO,
                        is_audit=True,
                        context=mask_context({
                            'authResult':    'success' if sc < 400 else 'failure',
                            'path':          mask_pii(url), 'statusCode': sc,
                            'failureReason': f'HTTP {sc}' if sc >= 400 else None,
                        }),
                    )

                sentinel._emit(
                    f'← {request.method} {mask_pii(url)} {sc} ({ms:.1f}ms)'
                    f'{"[SLOW]" if ms > sentinel._cfg["slow_http_ms"] else ""}'
                    f'{"[RATE-LIMITED]" if rate_limit_hit else ""}',
                    layer=LogLayer.SERVICE,
                    level=(LogLevel.ERROR if sc >= 500 else LogLevel.WARN if sc >= 400 else LogLevel.INFO),
                    context=mask_context({
                        'method': request.method, 'path': mask_pii(url),
                        'statusCode': sc, 'durationMs': ms,
                        'responseSizeBytes': res_bytes or None,
                        'rateLimitHit': rate_limit_hit,
                        'rateLimitRemaining': rate_limit_remaining if rate_limit_remaining >= 0 else None,
                        'downstreamService': mask_pii(url), 'downstreamStatusCode': sc,
                        'downstreamDurationMs': ms, 'thirdPartyLatencyMs': ms,
                        'retryCount': retry_count or None,
                    }),
                )
                return response
            except Exception as exc:
                ms = (time.perf_counter() - start) * 1000
                sentinel._emit(
                    f'✗ {request.method} {mask_pii(url)} — {exc}',
                    layer=LogLayer.SERVICE, level=LogLevel.ERROR,
                    context={
                        'method': request.method, 'path': mask_pii(url), 'durationMs': ms,
                        'exceptionType': type(exc).__name__, 'stackTrace': traceback.format_exc(),
                    },
                )
                raise

        _requests.Session.send = patched_send

    # ── httpx patch ───────────────────────────────────────────────────────────

    def _patch_httpx(self) -> None:
        if not HAS_HTTPX:
            return
        sentinel  = self
        orig_send = _httpx.Client.send

        def patched_send(self_client, request, **kwargs):
            start   = time.perf_counter()
            url     = str(request.url)
            current_trace = _ctx_trace_id.get() or sentinel._process_trace_id
            span_id = _gen_8hex()
            request.headers['traceparent'] = build_traceparent(current_trace, span_id)

            sentinel._emit(
                f'→ httpx {request.method} {mask_pii(url)}',
                layer=LogLayer.SERVICE, level=LogLevel.INFO,
                context={'method': request.method, 'path': mask_pii(url)},
            )
            try:
                response = orig_send(self_client, request, **kwargs)
                ms = (time.perf_counter() - start) * 1000
                sc = response.status_code
                rate_limit_hit = sc == 429
                sentinel._emit(
                    f'← httpx {request.method} {mask_pii(url)} {sc} ({ms:.1f}ms)'
                    f'{"[RATE-LIMITED]" if rate_limit_hit else ""}',
                    layer=LogLayer.SERVICE,
                    level=LogLevel.ERROR if sc >= 500 else LogLevel.WARN if sc >= 400 else LogLevel.INFO,
                    context=mask_context({
                        'method': request.method, 'path': mask_pii(url),
                        'statusCode': sc, 'durationMs': ms,
                        'rateLimitHit': rate_limit_hit,
                        'downstreamStatusCode': sc, 'thirdPartyLatencyMs': ms,
                    }),
                )
                return response
            except Exception as exc:
                sentinel._emit(
                    f'✗ httpx {request.method} {mask_pii(url)} — {exc}',
                    layer=LogLayer.SERVICE, level=LogLevel.ERROR,
                    context={
                        'method': request.method, 'path': mask_pii(url),
                        'exceptionType': type(exc).__name__,
                        'stackTrace': traceback.format_exc(),
                    },
                )
                raise

        _httpx.Client.send = patched_send

    # ── SQLAlchemy patch ──────────────────────────────────────────────────────

    def _patch_sqlalchemy(self) -> None:
        if not HAS_SQLALCHEMY:
            return
        sentinel  = self
        slow_ms   = self._cfg['slow_query_ms']
        _starts: Dict[int, float] = {}

        @_sa_event.listens_for(_sa.engine.Engine, 'before_cursor_execute')
        def before(conn, cursor, statement, parameters, context, executemany):
            _starts[id(cursor)] = time.perf_counter()

        @_sa_event.listens_for(_sa.engine.Engine, 'after_cursor_execute')
        def after(conn, cursor, statement, parameters, context, executemany):
            start   = _starts.pop(id(cursor), time.perf_counter())
            ms      = (time.perf_counter() - start) * 1000
            is_slow = ms > slow_ms
            stmt_up = statement.strip().upper()
            is_migration = bool(_MIGRATION_RE.match(stmt_up))
            is_commit    = stmt_up.startswith('COMMIT')
            is_rollback  = stmt_up.startswith('ROLLBACK')

            sentinel._emit(
                f'SQLAlchemy{"[SLOW]" if is_slow else ""}: {statement[:120]}',
                layer=LogLayer.DATA_ACCESS,
                level=LogLevel.WARN if is_slow else LogLevel.INFO,
                context={
                    'database':             'sqlalchemy',
                    'queryType':            stmt_up.split()[0] if stmt_up else 'UNKNOWN',
                    'durationMs':           ms,
                    'slowQuery':            is_slow,
                    'slowQueryThresholdMs': slow_ms,
                    'migrationName':        statement[:80] if is_migration else None,
                    'migrationStatus':      'completed' if is_migration else None,
                    'transactionAction':    'commit' if is_commit else 'rollback' if is_rollback else None,
                },
            )

    # ── psycopg2 patch ────────────────────────────────────────────────────────

    def _patch_psycopg2(self) -> None:
        if not HAS_PSYCOPG2:
            return
        sentinel = self
        slow_ms  = self._cfg['slow_query_ms']

        try:
            orig_execute = _psycopg2.extensions.cursor.execute

            def patched_execute(self_cursor, query, vars=None):
                start = time.perf_counter()
                try:
                    result  = orig_execute(self_cursor, query, vars)
                    ms      = (time.perf_counter() - start) * 1000
                    is_slow = ms > slow_ms
                    stmt_up = str(query).strip().upper()
                    is_migration = bool(_MIGRATION_RE.match(stmt_up))
                    is_commit    = stmt_up.startswith('COMMIT')
                    is_rollback  = stmt_up.startswith('ROLLBACK')

                    pool      = getattr(getattr(self_cursor, 'connection', None), '_pool', None)
                    pool_size = getattr(pool, 'maxconn', None)
                    pool_used = getattr(pool, '_used',   None)

                    sentinel._emit(
                        f'psycopg2{"[SLOW]" if is_slow else ""}: {str(query)[:120]}',
                        layer=LogLayer.DATA_ACCESS,
                        level=LogLevel.WARN if is_slow else LogLevel.INFO,
                        context={
                            'database':             'postgres',
                            'queryType':            stmt_up.split()[0] if stmt_up else 'UNKNOWN',
                            'durationMs':           ms,
                            'rowsAffected':         self_cursor.rowcount,
                            'slowQuery':            is_slow,
                            'slowQueryThresholdMs': slow_ms,
                            'migrationName':        str(query)[:80] if is_migration else None,
                            'migrationStatus':      'completed'      if is_migration else None,
                            'transactionAction':    'commit'   if is_commit   else 'rollback' if is_rollback else None,
                            'connectionPoolSize':   pool_size,
                            'connectionPoolUsed':   len(pool_used) if pool_used is not None else None,
                        },
                    )
                    return result
                except Exception as exc:
                    ms  = (time.perf_counter() - start) * 1000
                    msg = str(exc).lower()
                    sentinel._emit(
                        f'psycopg2 error: {exc}',
                        layer=LogLayer.DATA_ACCESS, level=LogLevel.ERROR,
                        context={
                            'database': 'postgres', 'durationMs': ms,
                            'deadlock':      'deadlock' in msg,
                            'lockTimeout':   'lock timeout' in msg,
                            'exceptionType': type(exc).__name__,
                            'stackTrace':    traceback.format_exc(),
                        },
                    )
                    raise

            _psycopg2.extensions.cursor.execute = patched_execute

        except (AttributeError, TypeError) as e:
            if self._cfg['debug']:
                print(
                    f'[SENTINEL] psycopg2 cursor patch skipped (C extension restriction): {e}',
                    file=sys.stderr,
                )

    # ── neo4j patch ───────────────────────────────────────────────────────────

    def _patch_neo4j(self) -> None:
        if not HAS_NEO4J:
            return
        sentinel = self
        slow_ms  = self._cfg['slow_query_ms']
        orig_run = _neo4j.Session.run

        def patched_run(self_session, query, parameters=None, **kwargs):
            start = time.perf_counter()
            try:
                result  = orig_run(self_session, query, parameters, **kwargs)
                ms      = (time.perf_counter() - start) * 1000
                is_slow = ms > slow_ms
                sentinel._emit(
                    f'Neo4j{"[SLOW]" if is_slow else ""}: {str(query)[:120]}',
                    layer=LogLayer.DATA_ACCESS,
                    level=LogLevel.WARN if is_slow else LogLevel.INFO,
                    context={
                        'database': 'neo4j', 'durationMs': ms,
                        'slowQuery': is_slow, 'slowQueryThresholdMs': slow_ms,
                    },
                )
                return result
            except Exception as exc:
                sentinel._emit(
                    f'Neo4j error: {exc}',
                    layer=LogLayer.DATA_ACCESS, level=LogLevel.ERROR,
                    context={
                        'database': 'neo4j',
                        'exceptionType': type(exc).__name__,
                        'stackTrace': traceback.format_exc(),
                    },
                )
                raise

        _neo4j.Session.run = patched_run

    # ── redis patch ───────────────────────────────────────────────────────────

    def _patch_redis(self) -> None:
        if not HAS_REDIS:
            return
        sentinel = self
        _EVICTION_CMDS = {'DEL', 'UNLINK', 'EXPIRE', 'EXPIREAT', 'PEXPIRE', 'PEXPIREAT'}
        orig_execute_command = _redis.StrictRedis.execute_command

        def patched_execute_command(self_redis, *args, **kwargs):
            cmd   = str(args[0]).upper() if args else 'CMD'
            start = time.perf_counter()
            try:
                result = orig_execute_command(self_redis, *args, **kwargs)
                ms = (time.perf_counter() - start) * 1000
                sentinel._emit(
                    f'Redis {cmd} ({ms:.1f}ms)',
                    layer=LogLayer.DATA_ACCESS, level=LogLevel.DEBUG,
                    context={
                        'database': 'redis', 'queryType': cmd, 'durationMs': ms,
                        'cacheHit': result is not None, 'cacheMiss': result is None,
                        'cacheEviction': cmd in _EVICTION_CMDS,
                    },
                )
                return result
            except Exception as exc:
                sentinel._emit(
                    f'Redis {cmd} error: {exc}',
                    layer=LogLayer.DATA_ACCESS, level=LogLevel.ERROR,
                    context={'database': 'redis', 'queryType': cmd, 'exceptionType': type(exc).__name__},
                )
                raise

        _redis.StrictRedis.execute_command = patched_execute_command

    # ── Queue instrumentation ─────────────────────────────────────────────────

    def _patch_queues(self) -> None:
        self._patch_celery()
        self._patch_pika()
        self._patch_aiokafka()

    def _patch_celery(self) -> None:
        if not HAS_CELERY:
            return
        sentinel = self

        @_celery_signals.task_prerun.connect
        def on_task_prerun(task_id, task, args, kwargs, **_):
            task._sentinel_start = time.perf_counter()
            sentinel._emit(
                f'Celery task started: {task.name}',
                layer=LogLayer.INFRASTRUCTURE, level=LogLevel.INFO,
                context={
                    'queueName': getattr(task, 'queue', 'default'),
                    'queueAction': 'consume', 'jobId': task_id, 'jobName': task.name,
                },
            )

        @_celery_signals.task_postrun.connect
        def on_task_postrun(task_id, task, retval, state, **_):
            ms = (time.perf_counter() - getattr(task, '_sentinel_start', time.perf_counter())) * 1000
            sentinel._emit(
                f'Celery task done: {task.name} [{state}] ({ms:.1f}ms)',
                layer=LogLayer.INFRASTRUCTURE,
                level=LogLevel.WARN if state == 'FAILURE' else LogLevel.INFO,
                context={
                    'queueName': getattr(task, 'queue', 'default'),
                    'queueAction': 'process', 'jobId': task_id,
                    'jobName': task.name, 'durationMs': ms, 'jobStatus': state,
                },
            )

        @_celery_signals.task_failure.connect
        def on_task_failure(task_id, exception, traceback_, **_):
            sentinel._emit(
                f'Celery task failed: {exception}',
                layer=LogLayer.INFRASTRUCTURE, level=LogLevel.ERROR,
                context={
                    'jobId': task_id,
                    'exceptionType': type(exception).__name__,
                    'stackTrace': ''.join(traceback.format_tb(traceback_)),
                },
            )

    def _patch_pika(self) -> None:
        if not HAS_PIKA:
            return
        sentinel = self
        orig_pub = _pika.channel.Channel.basic_publish

        def patched_publish(self_ch, exchange, routing_key, body, properties=None, mandatory=False):
            headers = {}
            if properties and properties.headers:
                headers = dict(properties.headers)
            current_trace = _ctx_trace_id.get() or sentinel._process_trace_id
            headers['traceparent'] = build_traceparent(current_trace, _gen_8hex())
            if properties:
                properties.headers = headers
            else:
                properties = _pika.BasicProperties(headers=headers)

            start = time.perf_counter()
            try:
                result = orig_pub(self_ch, exchange, routing_key, body, properties, mandatory)
                ms = (time.perf_counter() - start) * 1000
                sentinel._emit(
                    f'RabbitMQ publish: {exchange or "(default)"}/{routing_key} ({ms:.1f}ms)',
                    layer=LogLayer.INFRASTRUCTURE, level=LogLevel.INFO,
                    context={
                        'queueName': routing_key, 'queueAction': 'publish',
                        'exchange': exchange,
                        'messageBytes': len(body) if body else 0, 'durationMs': ms,
                    },
                )
                return result
            except Exception as exc:
                sentinel._emit(
                    f'RabbitMQ publish error: {exc}',
                    layer=LogLayer.INFRASTRUCTURE, level=LogLevel.ERROR,
                    context={
                        'queueName': routing_key, 'queueAction': 'publish',
                        'exceptionType': type(exc).__name__, 'stackTrace': traceback.format_exc(),
                    },
                )
                raise

        _pika.channel.Channel.basic_publish = patched_publish

        orig_consume = _pika.channel.Channel.basic_consume

        def patched_consume(self_ch, queue, on_message_callback, **kwargs):
            def wrapped_callback(ch, method, properties, body):
                tp = (properties.headers or {}).get('traceparent') if properties else None
                if tp:
                    parsed = parse_traceparent(tp)
                    if parsed:
                        _bind_request_context(
                            trace_id=parsed['trace_id'],
                            span_id=_gen_8hex(),
                        )
                start = time.perf_counter()
                try:
                    on_message_callback(ch, method, properties, body)
                    ms = (time.perf_counter() - start) * 1000
                    sentinel._emit(
                        f'RabbitMQ consume: {queue} ({ms:.1f}ms)',
                        layer=LogLayer.INFRASTRUCTURE, level=LogLevel.INFO,
                        context={
                            'queueName': queue, 'queueAction': 'consume',
                            'durationMs': ms, 'messageBytes': len(body) if body else 0,
                        },
                    )
                except Exception as exc:
                    ms = (time.perf_counter() - start) * 1000
                    sentinel._emit(
                        f'RabbitMQ consume error: {queue} — {exc}',
                        layer=LogLayer.INFRASTRUCTURE, level=LogLevel.ERROR,
                        context={
                            'queueName': queue, 'queueAction': 'consume', 'durationMs': ms,
                            'exceptionType': type(exc).__name__, 'stackTrace': traceback.format_exc(),
                        },
                    )
                    raise

            return orig_consume(self_ch, queue, wrapped_callback, **kwargs)

        _pika.channel.Channel.basic_consume = patched_consume

    def _patch_aiokafka(self) -> None:
        if not HAS_AIOKAFKA:
            return
        sentinel  = self
        orig_send = _aiokafka.AIOKafkaProducer.send

        async def patched_send(self_producer, topic, value=None, key=None, headers=None, **kwargs):
            current_trace = _ctx_trace_id.get() or sentinel._process_trace_id
            span_id   = _gen_8hex()
            tp_header = ('traceparent', build_traceparent(current_trace, span_id).encode())
            headers   = list(headers or []) + [tp_header]
            start     = time.perf_counter()
            try:
                result = await orig_send(self_producer, topic, value=value, key=key, headers=headers, **kwargs)
                ms = (time.perf_counter() - start) * 1000
                sentinel._emit(
                    f'Kafka produce: {topic} ({ms:.1f}ms)',
                    layer=LogLayer.INFRASTRUCTURE, level=LogLevel.INFO,
                    context={
                        'queueName': topic, 'queueAction': 'produce',
                        'messageBytes': len(value) if value else 0, 'durationMs': ms,
                    },
                )
                return result
            except Exception as exc:
                sentinel._emit(
                    f'Kafka produce error: {topic} — {exc}',
                    layer=LogLayer.INFRASTRUCTURE, level=LogLevel.ERROR,
                    context={
                        'queueName': topic, 'queueAction': 'produce',
                        'exceptionType': type(exc).__name__, 'stackTrace': traceback.format_exc(),
                    },
                )
                raise

        _aiokafka.AIOKafkaProducer.send = patched_send

        orig_getone = _aiokafka.AIOKafkaConsumer.getone

        async def patched_getone(self_consumer, *partitions):
            msg = await orig_getone(self_consumer, *partitions)
            tp  = None
            for k, v in (msg.headers or []):
                if k == 'traceparent':
                    tp = v.decode() if isinstance(v, bytes) else v
                    break
            if tp:
                parsed = parse_traceparent(tp)
                if parsed:
                    _bind_request_context(
                        trace_id=parsed['trace_id'],
                        span_id=_gen_8hex(),
                    )
            sentinel._emit(
                f'Kafka consume: {msg.topic}/{msg.partition} offset={msg.offset}',
                layer=LogLayer.INFRASTRUCTURE, level=LogLevel.INFO,
                context={
                    'queueName': msg.topic, 'queueAction': 'consume',
                    'partition': msg.partition, 'offset': msg.offset,
                    'messageBytes': len(msg.value) if msg.value else 0,
                },
            )
            return msg

        _aiokafka.AIOKafkaConsumer.getone = patched_getone

    # ── Process hooks ─────────────────────────────────────────────────────────

    def _hook_process(self) -> None:
        sentinel = self

        def handle_exception(exc_type, exc_value, exc_tb):
            sentinel._emit(
                f'Uncaught exception: {exc_value}',
                layer=LogLayer.SECURITY, level=LogLevel.FATAL,
                context={
                    'exceptionType':        exc_type.__name__,
                    'stackTrace':           ''.join(traceback.format_tb(exc_tb)),
                    'processUptimeSeconds': time.time() - sentinel._process_start,
                    'processExitCode':      1,
                },
            )
            sentinel._writer.flush()
            sys.__excepthook__(exc_type, exc_value, exc_tb)

        sys.excepthook = handle_exception

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                orig_handler = signal.getsignal(sig)

                def make_handler(s, oh):
                    def handler(signum, frame):
                        sentinel._emit(
                            f'Process signal: {s.name}',
                            layer=LogLayer.INFRASTRUCTURE, level=LogLevel.WARN,
                            context={
                                'containerEvent':       'stop',
                                'containerName':        sentinel.service_name,
                                'processUptimeSeconds': time.time() - sentinel._process_start,
                                **sentinel._sessions.stats(),
                            },
                        )
                        sentinel._writer.flush()
                        if callable(oh):
                            oh(signum, frame)
                        else:
                            sys.exit(0)
                    return handler

                signal.signal(sig, make_handler(sig, orig_handler))
            except (ValueError, OSError):
                pass

    # ── Infrastructure vitals ─────────────────────────────────────────────────

    def _start_vitals(self) -> None:
        sentinel = self

        def vitals_loop():
            while True:
                time.sleep(30)
                try:
                    sentinel._emit_vitals()
                except Exception:
                    pass

        threading.Thread(target=vitals_loop, daemon=True).start()

        def disk_loop():
            while True:
                time.sleep(60)
                try:
                    sentinel._emit_disk_vitals()
                except Exception:
                    pass

        threading.Thread(target=disk_loop, daemon=True).start()

    def _emit_vitals(self) -> None:
        """
        FIX (v4.0): Use psutil.cpu_percent(interval=0.1) directly — accurate,
        non-blocking, no manual delta math. Also adds diskUsedPercent,
        diskUsedBytes, memoryTotalBytes as requested.
        """
        ctx: Dict[str, Any] = {
            'containerName':        self.service_name,
            'processUptimeSeconds': time.time() - self._process_start,
            'networkInBytes':       self._net_bytes_in,
            'networkOutBytes':      self._net_bytes_out,
            'host':                 os.getenv('HOSTNAME', socket.gethostname()),
            **self._sessions.stats(),
        }

        level = LogLevel.INFO
        msg   = f'Process vitals: uptime={ctx["processUptimeSeconds"]:.0f}s'

        if HAS_PSUTIL:
            # CPU — direct call, no manual delta
            cpu_pct = _psutil.cpu_percent(interval=0.1)

            mem  = _psutil.virtual_memory()
            swap = _psutil.swap_memory()
            disk = _psutil.disk_usage('/')
            proc = _psutil.Process(os.getpid())
            p_mem = proc.memory_info()

            ctx.update({
                # CPU
                'cpuPercent':           cpu_pct,
                'cpuCoreCount':         _psutil.cpu_count(logical=True) or os.cpu_count() or 1,
                # Memory
                'memoryUsedBytes':      p_mem.rss,
                'memoryTotalBytes':     mem.total,
                'memoryAvailableBytes': mem.available,
                'swapUsedBytes':        swap.used,
                # Disk (as requested)
                'diskUsedPercent':      round(disk.percent, 1),
                'diskUsedBytes':        disk.used,
                'diskTotalBytes':       disk.total,
            })

            level = LogLevel.WARN if cpu_pct > 85 else LogLevel.INFO
            msg   = (
                f'Process vitals: cpu={cpu_pct}% '
                f'rss={p_mem.rss // 1024 // 1024}MB '
                f'mem_avail={mem.available // 1024 // 1024}MB '
                f'disk={disk.percent}%'
            )
        else:
            try:
                import resource as _resource
                usage = _resource.getrusage(_resource.RUSAGE_SELF)
                ctx['memoryUsedBytes'] = usage.ru_maxrss * 1024
            except Exception:
                pass

        self._emit(msg, layer=LogLayer.INFRASTRUCTURE, level=level, context=ctx)

    def _emit_disk_vitals(self) -> None:
        if not HAS_PSUTIL:
            return
        try:
            disk = _psutil.disk_usage('/')
            pct  = round(disk.percent, 1)
            self._emit(
                f'Disk vitals: {pct}% used ({disk.used // 1024 // 1024 // 1024}GB / {disk.total // 1024 // 1024 // 1024}GB)',
                layer=LogLayer.INFRASTRUCTURE,
                level=LogLevel.WARN if pct > 85 else LogLevel.INFO,
                context={
                    'diskUsedBytes':   disk.used,
                    'diskTotalBytes':  disk.total,
                    'diskUsedPercent': pct,
                    'containerName':   self.service_name,
                },
            )
        except Exception:
            pass

    # ── TLS certificate expiry monitor ────────────────────────────────────────

    def _start_cert_monitor(self) -> None:
        sentinel = self

        def check_all():
            for hostname in sentinel._cfg['cert_check_hosts']:
                try:
                    ctx_ssl = ssl.create_default_context()
                    conn    = ctx_ssl.wrap_socket(
                        socket.create_connection((hostname, 443), timeout=5),
                        server_hostname=hostname,
                    )
                    cert       = conn.getpeercert()
                    conn.close()

                    expiry_str = cert.get('notAfter', '')
                    expiry_dt  = datetime.datetime.strptime(
                        expiry_str, '%b %d %H:%M:%S %Y %Z'
                    ).replace(tzinfo=datetime.timezone.utc)
                    days_left  = (expiry_dt - datetime.datetime.now(datetime.timezone.utc)).days

                    issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                    issuer      = issuer_dict.get('organizationName') or issuer_dict.get('commonName') or 'unknown'

                    level = (
                        LogLevel.FATAL if days_left < 7  else
                        LogLevel.ERROR if days_left < 14 else
                        LogLevel.WARN  if days_left < 30 else
                        LogLevel.INFO
                    )

                    sentinel._emit(
                        f'TLS cert: {hostname} expires in {days_left} days',
                        layer=LogLayer.INFRASTRUCTURE, level=level,
                        context={'certDomain': hostname, 'certExpiryDays': days_left, 'certIssuer': issuer},
                    )
                except Exception as exc:
                    sentinel._emit(
                        f'TLS cert check failed: {hostname} — {exc}',
                        layer=LogLayer.INFRASTRUCTURE, level=LogLevel.ERROR,
                        context={'certDomain': hostname, 'exceptionType': type(exc).__name__},
                    )

        def monitor_loop():
            check_all()
            interval = sentinel._cfg['cert_check_interval']
            while True:
                time.sleep(interval)
                check_all()

        threading.Thread(target=monitor_loop, daemon=True).start()


# ── Factory ───────────────────────────────────────────────────────────────────

def init_sentinel(service_name: str = 'python-service', **kwargs) -> SentinelPython:
    """
    One-liner initialisation (manual mode — still works as before)::

        sentinel = init_sentinel(
            "my-service",
            clickhouse_host="http://ch:8123",
            otlp_endpoint="http://otel-collector:4318",
            health_port=9090,
            debug=True,
            log_level="INFO",
            sampling_rate=0.1,
            cert_check_hosts=["api.example.com"],
            slow_function_ms=300,
            disk_buffer_dir="/var/log/sentinel",
            disk_buffer_max_mb=500,
            session_ttl=1800,
        )

    In auto-init mode (the package installs a sitecustomize.py) you
    don't call this at all — the SDK boots itself from env vars.

    Keyword args
    ------------
    clickhouse_host, clickhouse_database, clickhouse_table,
    clickhouse_user, clickhouse_password,
    batch_size, slow_query_ms, slow_http_ms, slow_function_ms,
    debug, sampling_rate (0.0–1.0),
    cert_check_hosts (list[str]), cert_check_interval (seconds, default 21600),
    otlp_endpoint (str)             — OTLP/HTTP base URL for OTel export,
    health_port (int, default 9090) — serves /health + /ready + /sessions,
    log_level (str, default "DEBUG") — also reads LOG_LEVEL env var,
    disk_buffer_dir (str)           — directory for disk buffer,
    disk_buffer_max_mb (int)        — max buffer size in MB,
    audit_log_path (str)            — path for audit NDJSON log,
    session_ttl (int, default 1800) — idle seconds before session expires,
    enabled (bool)                  — kill switch; also reads SENTINEL_ENABLED env,
    """
    agent = SentinelPython(service_name, **kwargs)
    agent.hook()
    return agent



# ── Module-level singleton (populated by auto-init or manual init) ─────────────
#
# After init_sentinel() or auto-init, you can import this directly:
#   from sentinel_sdk.python.agent import sentinel
#   sentinel.audit(...)
#
sentinel: Optional[SentinelPython] = None
