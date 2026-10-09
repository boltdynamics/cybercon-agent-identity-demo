"""Local web UI for the CyberCon agent identity demo.

A tiny stdlib HTTP server (no extra dependencies) that lets a presenter click a
button to run each scenario and watch the agent's tool calls and the audit
trail appear live. Enforcement is unchanged — this only drives the same
`collect_offline_steps` path and renders the result.

Run:  python web.py   then open http://localhost:8000
"""

from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import agent
import secrets_service as svc

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("acme.web")

HOST = "localhost"
PORT = 8000

# The single-page UI. Kept inline so the demo is one `python web.py` away.
PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Acme Financial — Agent Identity Demo</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; font: 16px/1.5 -apple-system, Segoe UI, Roboto, sans-serif;
         background: #0d1117; color: #e6edf3; }
  header { padding: 20px 28px; border-bottom: 1px solid #30363d; }
  h1 { margin: 0; font-size: 20px; }
  .sub { color: #8b949e; font-size: 13px; margin-top: 4px; }
  .task { margin: 20px 28px; padding: 14px 16px; background: #161b22;
          border: 1px solid #30363d; border-radius: 8px; font-size: 14px; }
  .controls { display: flex; gap: 12px; margin: 0 28px 16px; }
  button { font: inherit; padding: 10px 18px; border-radius: 8px; cursor: pointer;
           border: 1px solid #30363d; color: #e6edf3; background: #21262d; }
  button:hover { border-color: #58a6ff; }
  button.danger { background: #3d1a1a; border-color: #6e2a2a; }
  button.safe { background: #16281b; border-color: #2a5a35; }
  button.ghost { background: transparent; }
  .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 16px;
          margin: 0 28px 28px; }
  .panel { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
           overflow: hidden; }
  .panel h2 { margin: 0; padding: 12px 16px; font-size: 14px;
              border-bottom: 1px solid #30363d; }
  .steps, .audit { padding: 12px 16px; font: 13px/1.5 ui-monospace, Menlo, monospace; }
  .step { padding: 8px 0; border-bottom: 1px dashed #21262d; }
  .reveal { animation: fadein 0.4s ease-out; }
  @keyframes fadein { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
  #speed { font: inherit; background: #21262d; color: #e6edf3;
           border: 1px solid #30363d; border-radius: 6px; padding: 2px 6px; }
  .call { color: #79c0ff; }
  .thought { color: #c9a0ff; font-style: italic; margin-bottom: 4px; }
  .diagnosis { margin: 10px 0 2px; padding: 10px 12px; border-radius: 6px;
               background: #0f2a2f; border: 1px solid #1f6feb; color: #cde9ff;
               font-family: -apple-system, Segoe UI, sans-serif; }
  .ok { color: #3fb950; font-weight: 600; }
  .deny { color: #f85149; font-weight: 600; }
  .secret { color: #d29922; word-break: break-all; }
  .reason { color: #8b949e; }
  .mode-tag { display: inline-block; padding: 2px 8px; border-radius: 10px;
              font-size: 12px; margin-left: 8px; }
  .mode-unrestricted { background: #3d1a1a; color: #ffa198; }
  .mode-secured { background: #16281b; color: #56d364; }
  .empty { color: #8b949e; }
  .live-toggle { font-size: 13px; color: #8b949e; display: flex; align-items: center;
                 gap: 6px; margin-left: 4px; }
  .status { margin: 0 28px 16px; font-size: 13px; min-height: 18px; }
  .status .live { color: #58a6ff; }
  .status .scripted { color: #8b949e; }
  .status .warn { color: #d29922; }
  .govern { margin-top: -6px; align-items: center; }
  .govern-label { color: #8b949e; font-size: 13px; }
  .state { margin: 0 28px 16px; font-size: 13px; color: #8b949e; min-height: 18px; }
  .state .revoked { color: #f85149; }
  .state .jit { color: #d29922; }
</style>
</head>
<body>
<header>
  <h1>Acme Financial — AI Agent Identity Demo <span id="modeTag"></span></h1>
  <div class="sub">The same agent, the same task, two security models. Enforcement lives in code, not in the model.</div>
</header>

<div class="task" id="task">loading task…</div>

<div class="controls">
  <button class="danger" onclick="run('unrestricted')">▶ Run UNRESTRICTED</button>
  <button class="safe" onclick="run('secured')">▶ Run SECURED</button>
  <label class="live-toggle"><input type="checkbox" id="liveToggle"> Use live Claude</label>
  <label class="live-toggle">Speed
    <select id="speed">
      <option value="3" selected>Very slow</option>
      <option value="2">Slow</option>
      <option value="1">Normal</option>
      <option value="0.4">Fast</option>
      <option value="0.01">Instant</option>
    </select>
  </label>
  <button class="ghost" onclick="clearLog()">Clear audit log</button>
</div>
<div class="controls govern">
  <span class="govern-label">Govern (live controls):</span>
  <button class="ghost" onclick="revoke()">⛔ Revoke finance_app_db</button>
  <button class="ghost" onclick="verifyNow()">🔁 Re-verify DB login now</button>
  <button class="ghost" onclick="resetAccess()">↺ Reset access state</button>
</div>
<div class="status" id="status"></div>
<div class="state" id="state"></div>

<div class="cols">
  <div class="panel">
    <h2>Agent actions</h2>
    <div class="steps" id="steps"><span class="empty">Run a scenario to see the agent's tool calls.</span></div>
  </div>
  <div class="panel">
    <h2>Audit trail (enforced by the access layer)</h2>
    <div class="audit" id="audit"><span class="empty">No decisions recorded yet.</span></div>
  </div>
</div>

<script>
async function loadTask() {
  const r = await fetch('/api/task');
  const d = await r.json();
  document.getElementById('task').textContent = '🧑‍💼 Business task: ' + d.task;
}

function esc(s) { return String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

// Build the HTML for one agent step (thought + tool call + result).
function stepHtml(s) {
  if (s.tool === 'diagnosis') {
    return `<div class="diagnosis">🩺 ${esc(s.result.summary || '')}</div>`;
  }
  const thought = s.thought ? `<div class="thought">💭 ${esc(s.thought)}</div>` : '';
  const args = Object.keys(s.args).length ? JSON.stringify(s.args) : '';
  let line = `<span class="call">${esc(s.tool)}(${esc(args)})</span>`;
  const res = s.result;
  if (s.tool === 'request_secret') {
    if (res.allowed) {
      const val = res.secret ? JSON.stringify(res.secret) : '';
      line += ` → <span class="ok">ALLOWED</span> <span class="secret">${esc(val)}</span>`;
    } else {
      line += ` → <span class="deny">DENIED</span> <span class="reason">${esc(res.reason)}</span>`;
    }
  } else if (res.error) {
    line += ` → <span class="deny">error:</span> <span class="reason">${esc(res.error)}</span>`;
  } else {
    line += ` → <span class="reason">ok</span>`;
  }
  return `<div class="step reveal">${thought}${line}</div>`;
}

// Build the HTML for one audit record.
function auditHtml(r) {
  const decision = r.decision || r.result || 'logged';
  const cls = (decision === 'allow' || decision === 'granted_no_policy') ? 'ok'
            : (decision === 'deny') ? 'deny' : 'reason';
  const t = (r.timestamp || '').slice(11, 19);
  return `<div class="step reveal">${esc(t)} [${esc(r.mode)}] ${esc(r.secret_id)} → `
       + `<span class="${cls}">${esc(decision.toUpperCase())}</span> `
       + `<span class="reason">${esc(r.reason || '')}</span></div>`;
}

function setMode(mode) {
  const tag = document.getElementById('modeTag');
  tag.textContent = mode.toUpperCase();
  tag.className = 'mode-tag mode-' + mode;
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// Pacing (ms). The speed control scales these so you can slow down for a crowd.
function delays() {
  const factor = parseFloat(document.getElementById('speed').value);
  return { step: 900 * factor, secret: 1500 * factor, diagnosis: 700 * factor };
}

let running = false;

// Reveal steps one at a time, pausing between them, and fill the audit panel
// as each secret decision is reached — so the audience follows the agent live.
async function run(mode) {
  if (running) return;            // ignore clicks while a run is animating
  running = true;
  setMode(mode);

  const live = document.getElementById('liveToggle').checked;
  const status = document.getElementById('status');
  const stepsEl = document.getElementById('steps');
  const auditEl = document.getElementById('audit');
  status.innerHTML = live ? '<span class="live">Calling live Claude…</span>' : '';
  stepsEl.innerHTML = '';
  auditEl.innerHTML = '<span class="empty">Waiting for the first access decision…</span>';

  const r = await fetch('/api/run?mode=' + mode + (live ? '&live=true' : ''), { method: 'POST' });
  const d = await r.json();

  // Report which engine actually ran, and surface any fallback note.
  if (d.source === 'live') {
    status.innerHTML = '<span class="live">● live Claude drove this run</span>';
  } else if (d.note) {
    status.innerHTML = '<span class="warn">⚠ ' + esc(d.note) + '</span>';
  } else {
    status.innerHTML = '<span class="scripted">● scripted run (no live model)</span>';
  }

  const t = delays();
  const audit = (d.audit || []).slice();
  let auditShown = 0;

  // Walk the steps. The first step shows instantly; every later step waits,
  // pausing longer on secret requests for dramatic effect.
  let first = true;
  for (const s of d.steps) {
    if (!first) {
      await sleep(s.tool === 'request_secret' ? t.secret
                : s.tool === 'diagnosis' ? t.diagnosis : t.step);
    }
    first = false;

    if (auditEl.querySelector('.empty')) auditEl.innerHTML = '';
    stepsEl.insertAdjacentHTML('beforeend', stepHtml(s));
    stepsEl.lastElementChild.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    // When a secret decision happens, reveal the matching audit line too.
    if (s.tool === 'request_secret' && auditShown < audit.length) {
      auditEl.insertAdjacentHTML('beforeend', auditHtml(audit[auditShown++]));
      auditEl.lastElementChild.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  renderState(d.state);
  running = false;
}

// Show current revocations and any live JIT token with its remaining seconds.
function renderState(st) {
  const el = document.getElementById('state');
  if (!st) { el.innerHTML = ''; return; }
  const parts = [];
  if (st.revoked && st.revoked.length) {
    parts.push('<span class="revoked">⛔ revoked: ' + esc(st.revoked.join(', ')) + '</span>');
  }
  const jit = st.jit_remaining || {};
  for (const [sid, secs] of Object.entries(jit)) {
    parts.push('<span class="jit">⏱ JIT ' + esc(sid) + ': ' + secs + 's left (ttl ' + st.ttl_seconds + 's)</span>');
  }
  el.innerHTML = parts.length ? parts.join(' &nbsp;·&nbsp; ')
    : 'Access state: clean (no revocations, no active JIT tokens).';
}

// Append the latest audit records that aren't already shown.
function appendNewAudit(records) {
  const auditEl = document.getElementById('audit');
  if (auditEl.querySelector('.empty')) auditEl.innerHTML = '';
  const shown = auditEl.querySelectorAll('.step').length;
  records.slice(shown).forEach(r => {
    auditEl.insertAdjacentHTML('beforeend', auditHtml(r));
  });
  if (auditEl.lastElementChild) auditEl.lastElementChild.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Live revoke: the next secured run (or Re-verify) will deny this secret.
async function revoke() {
  const r = await fetch('/api/revoke?secret_id=finance_app_db', { method: 'POST' });
  const d = await r.json();
  appendNewAudit(d.audit);
  renderState(d.state);
  document.getElementById('status').innerHTML =
    '<span class="warn">⛔ Access revoked. Re-verify or run SECURED to see it denied.</span>';
}

// Re-request the DB secret right now — shows JIT expiry or a revocation taking effect.
async function verifyNow() {
  const r = await fetch('/api/verify?secret_id=finance_app_db', { method: 'POST' });
  const d = await r.json();
  appendNewAudit(d.audit);
  renderState(d.state);
  const res = d.result;
  const status = document.getElementById('status');
  if (res.allowed) {
    status.innerHTML = '<span class="live">🔁 Re-verify: finance_app_db ALLOWED (JIT token still valid).</span>';
  } else {
    status.innerHTML = '<span class="warn">🔁 Re-verify: finance_app_db DENIED — ' + esc(res.reason) + '</span>';
  }
}

async function resetAccess() {
  const r = await fetch('/api/reset-access', { method: 'POST' });
  const d = await r.json();
  renderState(d.state);
  document.getElementById('status').innerHTML = '<span class="scripted">↺ Access state reset.</span>';
}

async function clearLog() {
  const r = await fetch('/api/clear', { method: 'POST' });
  const d = await r.json();
  document.getElementById('audit').innerHTML = '<span class="empty">No decisions recorded yet.</span>';
  document.getElementById('steps').innerHTML = '<span class="empty">Audit log cleared. Run a scenario.</span>';
  renderState(d.state);
}

loadTask();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    """Serves the single page plus a small JSON API for runs and the audit log."""

    def log_message(self, *args):  # noqa: D401 - quiet the default access log
        return

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: dict) -> None:
        self._send(200, json.dumps(payload).encode("utf-8"), "application/json")

    def do_GET(self) -> None:
        # Serve the page or the static task text.
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        elif self.path == "/api/task":
            self._json({"task": agent.TASK})
        else:
            self._send(404, b"not found", "text/plain")

    def _run_scenario(self, mode: str, want_live: bool) -> tuple[list, str, str]:
        """Run one scenario, preferring live LLM when asked, else scripted.

        Returns (steps, source, note) where source is "live" or "scripted" and
        note explains any fallback. Live failures silently degrade to scripted
        so the demo never breaks on stage.
        """

        # Scripted is the default and the fallback target.
        if not want_live:
            logger.info("[web] scripted run: %s", mode)
            return agent.collect_offline_steps(mode), "scripted", ""

        # Try the real model; fall back to scripted on any LiveUnavailable.
        try:
            logger.info("[web] live run: %s", mode)
            return agent.collect_live_steps(mode), "live", ""
        except agent.LiveUnavailable as exc:
            logger.info("[web] live unavailable (%s) — falling back to scripted", exc)
            note = f"Live model unavailable ({exc}); showing scripted run instead."
            return agent.collect_offline_steps(mode), "scripted", note

    def _secret_id_from_path(self) -> str:
        """Pull a secret_id query param, defaulting to the in-scope DB secret."""

        if "secret_id=" in self.path:
            return self.path.split("secret_id=", 1)[1].split("&", 1)[0]
        return "finance_app_db"

    def do_POST(self) -> None:
        # Drive a scenario run, manage the audit log, or exercise JIT/revocation.
        if self.path.startswith("/api/run"):
            mode = "secured" if "mode=secured" in self.path else "unrestricted"
            want_live = "live=true" in self.path
            # A fresh run clears stale JIT tokens so timing starts from zero,
            # but keeps revocations so a revoke persists across runs.
            if mode == "secured":
                svc.clear_jit_grants()
            # Snapshot the log length BEFORE the run so we return only the
            # audit records this run produced, not the whole cumulative log.
            before = len(svc.read_audit_log())
            steps, source, note = self._run_scenario(mode, want_live)
            new_audit = svc.read_audit_log()[before:]
            self._json(
                {
                    "mode": mode,
                    "source": source,
                    "note": note,
                    "steps": steps,
                    "audit": new_audit,
                    "state": svc.access_state_summary(),
                }
            )
        elif self.path == "/api/clear":
            svc.clear_audit_log()
            logger.info("[web] audit log cleared")
            self._json({"ok": True, "state": svc.access_state_summary()})
        elif self.path.startswith("/api/revoke"):
            # Live revocation: flip the agent's access off for one secret.
            secret_id = self._secret_id_from_path()
            svc.revoke_access(secret_id)
            logger.info("[web] revoked access: %s", secret_id)
            self._json(
                {
                    "ok": True,
                    "revoked": secret_id,
                    "audit": svc.read_audit_log(),
                    "state": svc.access_state_summary(),
                }
            )
        elif self.path.startswith("/api/verify"):
            # Re-request the DB secret now (used to show JIT expiry live).
            secret_id = self._secret_id_from_path()
            result = agent.tools.request_secret(secret_id, "secured")
            logger.info(
                "[web] verify %s -> allowed=%s", secret_id, result.get("allowed")
            )
            self._json(
                {
                    "result": result,
                    "audit": svc.read_audit_log(),
                    "state": svc.access_state_summary(),
                }
            )
        elif self.path == "/api/reset-access":
            svc.reset_access_state()
            logger.info("[web] access state reset (revocations + JIT cleared)")
            self._json({"ok": True, "state": svc.access_state_summary()})
        else:
            self._send(404, b"not found", "text/plain")


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    logger.info("Demo UI running at http://%s:%s  (Ctrl+C to stop)", HOST, PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("\nshutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
