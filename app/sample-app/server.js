'use strict';

/**
 * Minimal HTTP service for the deployment demo.
 *
 * There is nothing interesting about the application itself -- it exists so
 * that CodeDeploy has something real to ship, health-check and roll back. Two
 * things about it do matter to the surrounding architecture:
 *
 *   1. /health is the contract. The ALB target group polls it, and the
 *      ValidateService lifecycle hook polls it on the green fleet before any
 *      production traffic is shifted. It returns 200 only when the process is
 *      genuinely ready to serve.
 *
 *   2. Logging never emits request bodies, query strings or headers. In a
 *      system handling ePHI, an application log is the easiest place to leak
 *      PHI into a store with weaker controls than the database it came from.
 *      Log the shape of a request, not its contents.
 *
 * Configuration arrives via the environment, written by the AfterInstall hook
 * from Parameter Store. No credentials, endpoints or keys are compiled in.
 */

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const PORT = Number(process.env.APP_PORT || 8080);
const RELEASE = process.env.RELEASE_ID || 'local';
const LOG_DIR = path.join(__dirname, 'logs');
const LOG_FILE = path.join(LOG_DIR, 'application.log');

fs.mkdirSync(LOG_DIR, { recursive: true });
const logStream = fs.createWriteStream(LOG_FILE, { flags: 'a' });

// Structured, single-line JSON so the CloudWatch agent can ship it as-is and
// CloudWatch Logs Insights can query it without a custom parser.
function log(level, event, fields = {}) {
  const record = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    event,
    host: os.hostname(),
    release: RELEASE,
    ...fields,
  });
  logStream.write(record + '\n');
  process.stdout.write(record + '\n');
}

// Flipped to false on SIGTERM so the load balancer drains this instance before
// the process exits. Without it, a blue/green cutover or a scale-in would drop
// in-flight requests.
let ready = true;
const startedAt = Date.now();

const server = http.createServer((req, res) => {
  const started = process.hrtime.bigint();

  res.on('finish', () => {
    const durationMs = Number(process.hrtime.bigint() - started) / 1e6;
    // Note what was requested and how it went -- never the payload.
    log('info', 'request', {
      method: req.method,
      route: req.url.split('?')[0],
      status: res.statusCode,
      duration_ms: Number(durationMs.toFixed(2)),
    });
  });

  const route = req.url.split('?')[0];

  if (route === '/health') {
    const body = {
      status: ready ? 'ok' : 'draining',
      release: RELEASE,
      uptime_s: Math.floor((Date.now() - startedAt) / 1000),
    };
    res.writeHead(ready ? 200 : 503, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
    return;
  }

  if (route === '/') {
    res.writeHead(200, {
      'content-type': 'application/json',
      // Defence-in-depth headers. HSTS is meaningful because the ALB
      // terminates TLS and redirects port 80.
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'x-content-type-options': 'nosniff',
      'cache-control': 'no-store',
    });
    res.end(
      JSON.stringify({
        service: 'hipaa-demo-app',
        message: 'Deployed by AWS CodeDeploy. No SSH was involved.',
        release: RELEASE,
        instance: os.hostname(),
      })
    );
    return;
  }

  res.writeHead(404, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ error: 'not found' }));
});

server.listen(PORT, () => log('info', 'listening', { port: PORT }));

// Graceful shutdown: report unhealthy first so the ALB stops sending new
// requests, wait out one health-check interval, then close.
process.on('SIGTERM', () => {
  log('info', 'sigterm_received');
  ready = false;
  setTimeout(() => {
    server.close(() => {
      log('info', 'shutdown_complete');
      process.exit(0);
    });
  }, 5000);
});
