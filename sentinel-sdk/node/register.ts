/* ============================================================
   SENTINEL SDK — Zero-Config Auto-Register  v3.2
   
   HOW TO USE (zero code changes in your app):
   
   Option A — Node CLI flag (recommended):
     node --require sentinel-sdk/register  ./your-app.js
   
   Option B — NODE_OPTIONS env var (works for any runner):
     NODE_OPTIONS="--require sentinel-sdk/register" npm start
     NODE_OPTIONS="--require sentinel-sdk/register" ts-node src/index.ts
   
   Option C — PM2 ecosystem.config.js:
     node_args: "--require sentinel-sdk/register"
   
   Option D — Docker CMD / ENTRYPOINT:
     CMD ["node", "--require", "sentinel-sdk/register", "dist/index.js"]
   
   All config comes from environment variables — no code needed:
     SENTINEL_SERVICE_NAME        (default: package.json name or "node-service")
     SENTINEL_ENABLED             (default: "true")
     CLICKHOUSE_HOST              (default: "http://localhost:8123")
     CLICKHOUSE_DATABASE          (default: "sentinel")
     CLICKHOUSE_TABLE             (default: "logs")
     CLICKHOUSE_USER
     CLICKHOUSE_PASSWORD
     SENTINEL_BATCH_SIZE          (default: 50)
     SENTINEL_FLUSH_INTERVAL_MS   (default: 2000)
     SENTINEL_SLOW_QUERY_MS       (default: 200)
     SENTINEL_SLOW_HTTP_MS        (default: 1000)
     SENTINEL_DEBUG               (default: "false")
     SENTINEL_SAMPLING_RATE       (default: "1.0")
     SENTINEL_CERT_HOSTS          (comma-separated hostnames)
     SENTINEL_CERT_CHECK_INTERVAL_MS
     OTEL_EXPORTER_OTLP_ENDPOINT
     SENTINEL_HEALTH_PORT         (default: 9090)
     LOG_LEVEL                    (DEBUG|INFO|WARN|ERROR|FATAL)
     SENTINEL_DISK_BUFFER_DIR
     SENTINEL_DISK_BUFFER_MAX_MB  (default: 500)
     SENTINEL_AUDIT_LOG_PATH
     SERVICE_VERSION / APP_VERSION / npm_package_version
   ============================================================ */

import path   from 'path';
import fs     from 'fs';
import { SentinelNode, type SentinelNodeConfig } from './node-agent.js';

/* ── Read service name from package.json if not set ────────── */
function _detectServiceName(): string {
  if (process.env.SENTINEL_SERVICE_NAME) return process.env.SENTINEL_SERVICE_NAME;
  try {
    // Walk up from CWD looking for package.json
    let dir = process.cwd();
    for (let i = 0; i < 5; i++) {
      const pkgPath = path.join(dir, 'package.json');
      if (fs.existsSync(pkgPath)) {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        if (pkg.name) return pkg.name;
      }
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  } catch { /* ignore */ }
  return 'node-service';
}

function _parseEnv(): SentinelNodeConfig {
  const certHosts = process.env.SENTINEL_CERT_HOSTS
    ? process.env.SENTINEL_CERT_HOSTS.split(',').map((h) => h.trim()).filter(Boolean)
    : [];

  return {
    serviceName:         _detectServiceName(),
    clickhouseHost:      process.env.CLICKHOUSE_HOST,
    clickhouseDatabase:  process.env.CLICKHOUSE_DATABASE,
    clickhouseTable:     process.env.CLICKHOUSE_TABLE,
    clickhouseUser:      process.env.CLICKHOUSE_USER,
    clickhousePassword:  process.env.CLICKHOUSE_PASSWORD,
    batchSize:           process.env.SENTINEL_BATCH_SIZE       ? Number(process.env.SENTINEL_BATCH_SIZE)       : undefined,
    flushInterval:       process.env.SENTINEL_FLUSH_INTERVAL_MS ? Number(process.env.SENTINEL_FLUSH_INTERVAL_MS) : undefined,
    slowQueryMs:         process.env.SENTINEL_SLOW_QUERY_MS    ? Number(process.env.SENTINEL_SLOW_QUERY_MS)    : undefined,
    slowHttpMs:          process.env.SENTINEL_SLOW_HTTP_MS     ? Number(process.env.SENTINEL_SLOW_HTTP_MS)     : undefined,
    debug:               process.env.SENTINEL_DEBUG === 'true',
    samplingRate:        process.env.SENTINEL_SAMPLING_RATE    ? Number(process.env.SENTINEL_SAMPLING_RATE)    : undefined,
    certCheckHosts:      certHosts,
    certCheckIntervalMs: process.env.SENTINEL_CERT_CHECK_INTERVAL_MS ? Number(process.env.SENTINEL_CERT_CHECK_INTERVAL_MS) : undefined,
    otlpEndpoint:        process.env.OTEL_EXPORTER_OTLP_ENDPOINT,
    healthPort:          process.env.SENTINEL_HEALTH_PORT      ? Number(process.env.SENTINEL_HEALTH_PORT)      : undefined,
    diskBufferDir:       process.env.SENTINEL_DISK_BUFFER_DIR,
    diskBufferMaxMb:     process.env.SENTINEL_DISK_BUFFER_MAX_MB ? Number(process.env.SENTINEL_DISK_BUFFER_MAX_MB) : undefined,
    auditLogPath:        process.env.SENTINEL_AUDIT_LOG_PATH,
    enabled:             process.env.SENTINEL_ENABLED !== 'false',
  };
}

/* ── Boot immediately — this runs at require() time ────────── */
// We instantiate synchronously so all patches are in place before
// any application module loads. The async writer.init() is fired
// in the background; the patch hooks don't depend on it being done.

const _cfg  = _parseEnv();
const _node = new SentinelNode(_cfg);

// hook() is async (ClickHouse DDL) but the monkey-patches it installs
// on http/https/fs/console are all synchronous. We fire and forget so
// the app process isn't blocked. Any records emitted before init()
// resolves are queued in-memory and flushed once it resolves.
_node.hook().catch((err) => {
  // Don't crash the host application under any circumstances
  if (_cfg.debug) console.error('[SENTINEL] auto-register hook error:', err);
});

/* Expose the singleton so advanced users can call sentinel.audit() etc.
   from their own code without importing SentinelNode directly:
     import sentinel from 'sentinel-sdk/register';
     sentinel.audit('user deleted', { userId });
*/
export default _node;
