# CyberCon 2026 — AI Agent Identity Security Demo

A tiny, self-contained demo showing the **same** AI agent run under two security
models against the **same** business task:

- **Unrestricted** — standing access, no gate. The agent reaches secrets that
  have nothing to do with its task and exposes them.
- **Secured** — a deny-by-default policy enforced **in code** (not by asking the
  model to behave). Unauthorized secrets are blocked and every decision is
  audited.

The point: identity, least privilege, JIT access, approval and audit are
enforced by the **access layer**, not the LLM.

> All credentials in `acme-financial/` are **synthetic and non-functional**.
> The agent's file access is sandboxed to the demo directory.

## Layout

```
cybercon-agent-identity/
├── agent.py            # agent runner (live LLM or --offline scripted)
├── web.py              # local web UI (click to run, watch decisions live)
├── tools.py            # tools the agent can call (sandboxed file + secret access)
├── secrets_service.py  # THE enforcement boundary: policy + audit logging
└── acme-financial/     # simulated enterprise environment
    ├── applications/   # finance-app (in scope) + payment-service (out of scope)
    ├── secrets/        # synthetic credentials store
    ├── policies/       # agent_access_policy.json (least-privilege allow-list)
    └── logs/           # agent_activity.log (the audit trail)
```

## Setup

```bash
cd ~/Documents/repositories/cybercon-agent-identity
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt          # only needed for live LLM mode
export ANTHROPIC_API_KEY=sk-ant-...       # only needed for live LLM mode
```

No API key / no WiFi? Use `--offline` and skip the two steps above.

## Run it

Live (real Claude making the tool calls):

```bash
python agent.py --mode unrestricted
python agent.py --mode secured
```

Offline fallback (scripted, identical tools + enforcement, no network):

```bash
python agent.py --mode unrestricted --offline
python agent.py --mode secured --offline
```

Watch the audit trail live in a second terminal pane:

```bash
tail -f acme-financial/logs/agent_activity.log
```

## Web UI (recommended for a live audience)

A one-page browser demo with buttons for each scenario. No extra dependencies
(Python standard library only) and no network — ideal for a conference stage.

```bash
cd ~/Documents/repositories/cybercon-agent-identity
python3 web.py
# then open http://localhost:8000
```

- **Run UNRESTRICTED** — the agent reads config, then retrieves `finance_app_db`
  **and** `payment_stripe` **and** `root_admin`, printing each exposed secret.
- **Run SECURED** — same task, but `payment_stripe` and `root_admin` come back
  **DENIED** while the right-hand panel fills with timestamped allow/deny
  decisions from the audit layer.
- **Clear audit log** — resets the trail between takes.
- **Speed** (dropdown) — paces how the steps reveal: Very slow / Slow / Normal /
  Fast / Instant, defaulting to **Very slow**. Steps fade in one at a time with a
  longer pause on each secret request (~4.5s at Very slow), and the matching
  audit decision appears alongside it — so the audience watches the agent reason
  rather than seeing a wall of text at once. Very slow suits a live crowd;
  Instant if you just want the final state.
- **Govern (live controls)** — a second button row that makes two controls
  *demonstrable*, not just described:
  - **⛔ Revoke finance_app_db** — revokes the agent's access to the in-scope DB
    secret. The next secured run (or Re-verify) then **denies** it with "access
    has been revoked", and the audit trail records the revocation.
  - **🔁 Re-verify DB login now** — re-requests `finance_app_db` on the spot.
    Use it to show a JIT token still valid (ALLOWED) or, after the TTL elapses,
    **DENIED — JIT token expired**.
  - **↺ Reset access state** — clears revocations and JIT timers for a clean
    re-run.
  The line under the buttons shows current revocations and any live JIT token's
  remaining seconds. The JIT TTL is **20s** (set in the policy) so expiry is
  showable on stage; raise it in `agent_access_policy.json` for real use.
- **Use live Claude** (checkbox) — when ticked, the run is driven by the real
  Anthropic model choosing the tool calls itself. Needs `pip install anthropic`
  and `ANTHROPIC_API_KEY`. If either is missing, or the API call fails (e.g.
  conference WiFi drops), it **silently falls back to the scripted run** and
  shows a note — so the demo never breaks on stage. A status line under the
  buttons tells you which engine actually ran.

The left panel shows what the agent *did* — each step with the agent's reasoning
(💭) and a final troubleshooting **diagnosis** (🩺). The right panel shows what
the access layer *allowed*. The agent genuinely works the DB problem; secret
access is a step inside that work, not the whole point. In the secured run it
still reaches the correct diagnosis — it just can't grab the unrelated secrets.
Scripted and live modes run through the same tool dispatch and the same
enforcement in `secrets_service.py` — only who *chooses* the tool calls differs.
Stop the server with Ctrl+C.

## Live demo flow (the 5 steps)

1. **Set the task.** Read the prompt aloud: *"Our finance application is failing
   to connect to its database. Investigate and identify causes."*
2. **Run unrestricted.** `python agent.py --mode unrestricted --offline`.
   Point out it retrieves `finance_app_db` (fine) **and** `payment_stripe` and
   `root_admin` (nothing to do with the task) and prints them.
3. **Introduce controls.** Show `policies/agent_access_policy.json`: a named
   agent identity, deny-by-default, a one-item allow-list, approval for
   sensitive secrets, JIT TTL.
4. **Run secured, same task.** `python agent.py --mode secured --offline`.
   The agent still troubleshoots and still gets `finance_app_db`, but
   `payment_stripe` → **DENY (deny-by-default)** and `root_admin` →
   **DENY (requires human approval)**.
5. **Compare.** Clear the log (`> acme-financial/logs/agent_activity.log`) and
   show both trails side by side.

## Outcome comparison

| Capability | Unrestricted | Secured |
|---|---|---|
| Application troubleshooting | Allowed | Allowed |
| Broad file access | Allowed | Allowed (sandboxed) |
| Read unrelated secrets | Possible | Denied |
| Least-privilege enforcement | No | Yes (deny-by-default) |
| Approval for privileged actions | No | Yes (sensitive set) |
| Access audit trail | Access logged, no decisions | Full allow/deny decisions |
| Just-in-time access | No (standing) | Yes — token expires after TTL (live) |
| Access revocation | Not enforced | Yes — revoke denies next request (live) |

## Where enforcement actually lives

`secrets_service.request_secret_secured()`. It loads the policy, applies
deny-by-default + approval + allow-list checks, and writes an audit record
**before** any value is returned. The LLM is never trusted to restrict itself —
that's the whole identity-security point (Discover / Control / Govern).

## Not CyberArk

The policy engine and secrets store here are **simulated** for the demo. They
illustrate the controls a real workload-identity / secrets platform (e.g.
CyberArk / Idira) enforces — they are not a product integration.

## Pre-talk checklist

Run through this once in the room before you present. Takes about two minutes.

**T-minus (the night before)**

- [ ] `cd ~/Documents/repositories/cybercon-agent-identity`
- [ ] `python3 -m venv .venv && source .venv/bin/activate`
- [ ] `pip install -r requirements.txt` (only needed if you'll use live Claude)
- [ ] If using live Claude: `export ANTHROPIC_API_KEY=sk-ant-...` and confirm it
      works: `python3 agent.py --mode secured` (should allow one secret, deny two)
- [ ] Dry-run the scripted path offline: `python3 agent.py --mode unrestricted --offline`

**In the room (just before you go on)**

- [ ] Start the UI: `python3 web.py` → open `http://localhost:8000`
- [ ] Bump browser zoom to ~150% (Cmd +) so the back row can read it
- [ ] Increase terminal font if you'll also show the CLI/log
- [ ] Click **Clear audit log** and **↺ Reset access state** so you start from an
      empty trail with no leftover revocations or JIT tokens from rehearsal
- [ ] Decide your live/offline default: leave **Use live Claude unticked** for a
      deterministic, instant demo; tick it only for the "real model" moment
- [ ] Confirm fallback: tick **Use live Claude**, kill WiFi, run once — it should
      drop to scripted with an amber note (proves nothing can break on stage)
- [ ] Re-tick/untick to your presenting default and **Clear audit log** again

**Running order on stage**

1. Read the business task aloud (shown at the top of the page).
2. Click **Run UNRESTRICTED** — point at the exposed `payment_stripe` and
   `root_admin` secrets that have nothing to do with the task.
3. Click **Clear audit log**, then open `policies/agent_access_policy.json` to
   show the identity, deny-by-default, allow-list and approval controls.
4. Click **Run SECURED** — same task, now the two unrelated secrets come back
   **DENIED** and the right panel fills with timestamped decisions.
5. **(Govern — revocation)** Click **⛔ Revoke finance_app_db**, then **🔁
   Re-verify DB login now** → it's now **DENIED (access revoked)**. The agent
   lost access to a secret it previously held, live, with an audit record.
6. **(Govern — JIT)** Click **↺ Reset access state**, run **SECURED** (grants a
   20s token — the state line counts down), wait past 20s, then **🔁 Re-verify**
   → **DENIED (JIT token expired)**. Access was time-bound, not standing.
7. Land the message: *"If an AI agent can act on our behalf, who controls what
   it is allowed to do?"*

**If something goes wrong**

- Live call hangs or errors → it already fell back to scripted; just carry on.
- Page won't load → check the `python3 web.py` terminal is still running and
  you're on `http://localhost:8000` (not https).
- Weird results → **Clear audit log** and re-run; each run is independent.
