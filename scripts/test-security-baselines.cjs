// File Name: test-security-baselines.cjs
// Version: v0.1.1 | Created: 2026-09-14 | Last Modified: 2026-09-15
// Author: Alice Endelgard | Organization: Alvestrasza Corporation
// Description: Fresh loopback-only Security browser fixture with automatic helper cleanup.
const { spawn } = require("node:child_process");
const http = require("node:http");
const net = require("node:net");
const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const web = path.join(root, "apps/web-console");
const backend = path.join(root, "services/control-plane");
const output = path.join(root, "build/security-baseline-e2e", new Date().toISOString().replace(/[:.]/g, "-"));
const python = process.env.IPMS_TEST_PYTHON || path.join(backend, process.platform === "win32" ? ".venv/Scripts/python.exe" : ".venv/bin/python");
const standalone = path.join(web, ".next/standalone");
const env = {
  ...process.env,
  PYTHONPATH: path.join(backend, "src"),
  DJANGO_SETTINGS_MODULE: "ipms_control_plane.settings.e2e",
  IPMS_E2E_DATABASE: path.join(output, "fixture.sqlite3"),
  IPMS_ALLOWED_HOSTS: "127.0.0.1,localhost,testserver",
  IPMS_CSRF_TRUSTED_ORIGINS: "http://127.0.0.1:3116",
  IPMS_PUBLIC_ORIGIN: "http://127.0.0.1:3116",
  IPMS_CONTROL_PLANE_URL: "http://127.0.0.1:3116",
  IPMS_NATIVE_CONSOLE_KEY_FILE: "",
  IPMS_SECURITY_GPO_ARTIFACT_DIR: path.join(root, "build/security-gpo-packages"),
  HOSTNAME: "127.0.0.1", PORT: "3117", TZ: "UTC",
};
const children = [];
const logs = [];

function run(command, args, cwd, background) {
  const log = background ? fs.openSync(path.join(output, background + ".log"), "w") : null;
  if (log !== null) logs.push(log);
  const child = spawn(command, args, { cwd, env, windowsHide: true, stdio: log !== null ? ["ignore", log, log] : "inherit" });
  if (background) {
    children.push(child);
    child.on("error", (error) => console.error(error.message));
    return child;
  }
  return new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("exit", code => code === 0 ? resolve() : reject(new Error(`Fixture command exited ${code}`)));
  });
}

async function ready(url) {
  for (let attempt = 0; attempt < 60; attempt++) {
    try { const response = await fetch(url, { signal: AbortSignal.timeout(1000) }); if (response.ok) return; } catch {}
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  throw new Error(`Fixture failed to start: ${url}`);
}

const front = http.createServer((req, res) => {
  // Test-only transport fault. No middleware is added to the product.
  if (req.url.startsWith("/api/v1/security/") && (req.headers.cookie || "").split(";").some(value => value.trim() === "fixture_security_outage=1")) {
    res.writeHead(503, { "Content-Type": "application/json" });
    res.end('{"error":"fixture_unavailable"}');
    return;
  }
  const port = req.url.startsWith("/api/v1/") ? 8117 : 3117;
  const upstream = http.request({ hostname: "127.0.0.1", port, path: req.url, method: req.method, headers: { ...req.headers, host: "127.0.0.1:3116", "x-forwarded-proto": "http" } }, reply => { res.writeHead(reply.statusCode, reply.headers); reply.pipe(res); });
  upstream.on("error", () => { if (!res.headersSent) res.writeHead(502); res.end("Fixture upstream unavailable"); });
  req.pipe(upstream);
});

(async () => {
  try {
    if (!fs.existsSync(path.join(standalone, "server.js"))) throw new Error("Build the Web Console standalone output first.");
    for (const port of [8117, 3117]) await new Promise((resolve, reject) => {
      const probe = net.createServer(); probe.once("error", reject); probe.listen(port, "127.0.0.1", () => probe.close(resolve));
    });
    await new Promise((resolve, reject) => { front.once("error", reject); front.listen(3116, "127.0.0.1", resolve); });
    fs.mkdirSync(output, { recursive: true });
    fs.cpSync(path.join(web, ".next/static"), path.join(standalone, ".next/static"), { recursive: true });
    if (fs.existsSync(path.join(web, "public"))) fs.cpSync(path.join(web, "public"), path.join(standalone, "public"), { recursive: true });
    await run(python, [path.join(web, "tests/fixtures/seed-security.py")], backend);
    run(python, ["manage.py", "runserver", "127.0.0.1:8117", "--noreload"], backend, "backend");
    run(process.execPath, [path.join(standalone, "server.js")], standalone, "frontend");
    await ready("http://127.0.0.1:8117/api/v1/health/live/");
    await ready("http://127.0.0.1:3117/en/login");
    console.log(`Synthetic evidence directory: ${output}`);
    await run(process.execPath, ["node_modules/@playwright/test/cli.js", "test", "--config=playwright.security.config.ts", `--output=${path.join(output, "results")}`], web);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
  finally {
    front.closeAllConnections(); front.close();
    await Promise.all(children.map(child => new Promise(resolve => {
      if (child.exitCode !== null || !child.pid) return resolve();
      child.once("exit", resolve); child.kill();
    })));
    for (const fd of logs) fs.closeSync(fd);
    console.log("Isolated fixture helpers stopped.");
  }
})();
