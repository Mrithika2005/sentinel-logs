#!/usr/bin/env node

// univ-sentinel CLI
// Usage: npx --yes github:Mrithika2005/univ-sentinel
// Run inside your project root — auto-patches main.py and app.jsx

import fs from "fs";
import path from "path";
import { execSync } from "child_process";

const SENTINEL_PORT = process.env.SENTINEL_PORT || "4318";
const SENTINEL_URL = `http://localhost:${SENTINEL_PORT}/sentinel/ingest`;

const COLORS = {
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  cyan: (s) => `\x1b[36m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
};

const log = {
  info: (s) => console.log(COLORS.cyan(`[sentinel] ${s}`)),
  ok: (s) => console.log(COLORS.green(`[sentinel] ✓ ${s}`)),
  warn: (s) => console.log(COLORS.yellow(`[sentinel] ⚠ ${s}`)),
  err: (s) => console.log(COLORS.red(`[sentinel] ✗ ${s}`)),
};

// ── Python patch ──────────────────────────────────────────────────────────────

const PYTHON_SNIPPET = `
import logging as _logging
import uuid as _uuid
from datetime import datetime as _datetime, timezone as _timezone

_SENTINEL_URL = "${SENTINEL_URL}"
_SENTINEL_SERVICE = "finapp-backend"

def _send_to_sentinel(level, message, context={}):
    try:
        import requests as _requests
        _requests.post(_SENTINEL_URL, json=[{
            "timestamp": _datetime.now(_timezone.utc).isoformat(),
            "record_id": str(_uuid.uuid4()),
            "trace_id": str(_uuid.uuid4()),
            "span_id":  str(_uuid.uuid4()),
            "service":  _SENTINEL_SERVICE,
            "env":      "development",
            "layer":    "business_logic",
            "level":    level,
            "message":  message,
            "context":  context,
        }], timeout=2)
    except Exception:
        pass

class _SentinelHandler(_logging.Handler):
    def emit(self, record):
        if record.name.startswith(("urllib3", "requests", "httpx")):
            return
        _send_to_sentinel(
            level=record.levelname,
            message=self.format(record),
            context={"module": record.module, "funcName": record.funcName},
        )

_logging.basicConfig(level=_logging.DEBUG)
_logging.getLogger().addHandler(_SentinelHandler())
# ── /sentinel-sdk ──
`;

const PYTHON_MARKER = "# ── /sentinel-sdk ──";

function patchPython(filePath) {
  let src = fs.readFileSync(filePath, "utf-8");

  if (src.includes(PYTHON_MARKER)) {
    log.warn(`${filePath} already patched — skipping`);
    return;
  }

  // inject after the last top-level import block
  const lines = src.split("\n");
  let lastImportLine = 0;
  for (let i = 0; i < lines.length; i++) {
    if (/^(import |from )/.test(lines[i])) lastImportLine = i;
  }

  lines.splice(lastImportLine + 1, 0, PYTHON_SNIPPET);
  fs.writeFileSync(filePath, lines.join("\n"), "utf-8");
  log.ok(`Patched ${filePath}`);
}

// ── JS/JSX patch ──────────────────────────────────────────────────────────────

const JS_SNIPPET = `
// ── sentinel-sdk ──
const __sentinelUrl = "${SENTINEL_URL}";
function __sentinelLog(level, message, context = {}) {
  fetch(__sentinelUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify([{
      timestamp:  new Date().toISOString(),
      record_id:  crypto.randomUUID(),
      trace_id:   crypto.randomUUID(),
      span_id:    crypto.randomUUID(),
      service:    "finapp-frontend",
      env:        "development",
      layer:      "ui",
      level,
      message,
      context,
    }]),
  }).catch(() => {});
}
if (typeof window !== "undefined") {
  window.addEventListener("error", (e) =>
    __sentinelLog("ERROR", e.message, { filename: e.filename, lineno: e.lineno }));
  window.addEventListener("unhandledrejection", (e) =>
    __sentinelLog("ERROR", \`Unhandled promise: \${e.reason}\`, {}));
}
// ── /sentinel-sdk ──
`;

const JS_MARKER = "// ── /sentinel-sdk ──";

function patchJS(filePath) {
  let src = fs.readFileSync(filePath, "utf-8");

  if (src.includes(JS_MARKER)) {
    log.warn(`${filePath} already patched — skipping`);
    return;
  }

  // inject after the last import line
  const lines = src.split("\n");
  let lastImportLine = 0;
  for (let i = 0; i < lines.length; i++) {
    if (/^import /.test(lines[i])) lastImportLine = i;
  }

  lines.splice(lastImportLine + 1, 0, JS_SNIPPET);
  fs.writeFileSync(filePath, lines.join("\n"), "utf-8");
  log.ok(`Patched ${filePath}`);
}

// ── File finder ───────────────────────────────────────────────────────────────

function findFiles(dir, matcher, results = []) {
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (["node_modules", ".git", "__pycache__", ".venv", "dist"].includes(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) findFiles(full, matcher, results);
    else if (matcher(entry.name)) results.push(full);
  }
  return results;
}

// ── Main ──────────────────────────────────────────────────────────────────────

console.log(COLORS.bold("\n  univ-sentinel — auto-patch\n"));

const cwd = process.cwd();
log.info(`Scanning: ${cwd}`);

// Find main.py files
const pyFiles = findFiles(cwd, (n) => n === "main.py");
if (pyFiles.length === 0) {
  log.warn("No main.py found — skipping Python patch");
} else {
  pyFiles.forEach(patchPython);
}

// Find app.jsx / app.tsx / App.jsx / App.tsx
const jsFiles = findFiles(cwd, (n) => /^[Aa]pp\.[jt]sx?$/.test(n));
if (jsFiles.length === 0) {
  log.warn("No App.jsx/App.tsx found — skipping JS patch");
} else {
  jsFiles.forEach(patchJS);
}

if (pyFiles.length === 0 && jsFiles.length === 0) {
  log.err("Nothing to patch. Run this from your project root.");
  process.exit(1);
}

console.log("");
log.ok("Done! Make sure the Sentinel server is running:");
console.log(COLORS.cyan(`\n  npx --yes github:Mrithika2005/univ-sentinel\n`));
log.ok(`Then check: http://localhost:${SENTINEL_PORT}/sentinel/health\n`);
