# Tripwire — Design Spec

**Date:** 2026-07-25
**Status:** Approved, moving to implementation plan

## 1. Summary

Tripwire is a Linux host-intrusion canary. It plants decoy Claude Code / Codex
credential files under `/etc` — never in the real credential locations — watches
them with fanotify permission events, and when a non-allowlisted process opens
one it **holds** the read (looking like slow I/O), attributes the reader down to
the su/sudo-surviving login user, and runs a configurable action ladder:
alert → (freeze/kill) → poweroff. Ships as `.deb` + `.rpm`.

The token is worthless, so the point is not to protect a secret — it is to
detect that someone is reading credential files they should never touch, notify
a human on a different device before the host dies, and optionally halt the
intrusion.

## 2. Goals / Non-goals

**Goals**
- Detect any open of a decoy credential file.
- Attribute the reader: exe, cmdline, uid, `CapEff`, and `loginuid`/`auid`
  (survives su/sudo), plus session, cgroup, and ancestor chain.
- Hold the read so the action ladder can complete before the token is returned.
- Fan out alerts to multiple sinks and confirm delivery before destructive
  actions.
- Configurable action ladder, fully testable with destructive actions stubbed.
- Never brick the host: fail-open, no boot loop, documented escape hatches.
- Install from `.deb` / `.rpm` with sane, safe defaults.

**Non-goals (v1)**
- No hosted apt/yum repo, AUR, or Homebrew formulas.
- No external canarytoken-service registration; fingerprinting is local.
- No Windows/macOS support.
- Not a general FIM/HIDS — bait files only, not arbitrary watch rules.

## 3. Target profiles

One package, two shipped config profiles; posture is config, not code.

- **workstation** — personal dev machine. May arm destructive actions after
  `tripwire test` passes. Local desktop notification enabled.
- **server** — headless/fleet. Installs **alert-only**; poweroff/kill require an
  explicit `tripwire arm` after config edit. Central alerting (webhook/ntfy).

Install default for **both** is alert-only. Arming destructive actions is always
a deliberate post-install step.

## 4. Architecture

Single static Go binary (`golang.org/x/sys/unix` for fanotify; nfpm is Go-native
so build and packaging share one toolchain). Two entry points from one binary:

- `tripwired` — the daemon, runs as root under systemd.
- `tripwire` — CLI: `status`, `test`, `arm`, `disarm`, `reset`, `verify`.

### Packages

| Package | Responsibility |
|---|---|
| `internal/bait` | generate, place, refresh, and re-verify decoy files |
| `internal/watch` | `Watcher` interface; fanotify backend + inotify fallback |
| `internal/attrib` | `/proc/<pid>` snapshot → identity; auditd enrichment |
| `internal/policy` | snapshot → `Verdict{Benign, Hostile}` |
| `internal/action` | ordered, configurable action runner; the hold |
| `internal/alert` | `Sink` interface + 4 impls; fan-out with delivery confirmation |
| `internal/state` | tripped-state persistence across reboot |
| `internal/config` | load/validate YAML config; profile defaults |

Each package is independently testable. Destructive effects sit behind
interfaces (`PowerOffer`, `Killer`, `Sink`) so tests assert on recorders.

## 5. Detection & attribution

### Marks
Per-inode `FAN_MARK_ADD` on each bait file (`FAN_CLASS_CONTENT`,
`FAN_OPEN_PERM`) — not mount-wide, so the rest of `/etc` sees no overhead.
Inode marks die if a bait file is replaced, so the daemon also holds an inotify
watch on each parent directory for `IN_CREATE`/`IN_MOVED_TO` and re-marks.

### Event loop ordering
1. Event arrives; the reading process is **blocked** in `open()` by the
   permission event.
2. Snapshot `/proc/<pid>/` while it is guaranteed alive: `exe`, `cmdline`,
   `status` (`Uid`, `CapEff`), **`loginuid`** (= `auid`, survives su/sudo, no
   auditd required), `sessionid`, `cgroup`, ppid chain, and **`starttime`**
   (`/proc/<pid>/stat` field 22, for PID-reuse guarding later).
3. Evaluate policy → verdict.
4. **Benign** → respond `FAN_ALLOW` immediately, no hold, no actions.
5. **Hostile** → enter the hold + action ladder (§7). The response is deferred.

Auditd enrichment (if `auditd` is running) attaches the matching audit record but
is never a dependency — `loginuid` from `/proc` already gives the login user.

### Fallback
Where fanotify is unavailable (old kernels, restricted containers), degrade to
inotify: detection still works ("it was opened") but there is **no attribution
and no hold** — every read looks identical. Logged prominently at startup.

## 6. Policy

Allowlist rules match on any combination of: `exe`, `uid`, `loginuid`,
`CapEff` mask, systemd unit / cgroup, and ancestor process. Default ships:

- Allowlist only the daemon's own PID.
- A commented block for the usual benign readers: `updatedb`, `etckeeper`,
  `aide`, `rkhunter`, and a placeholder for the site backup agent.

**Documented limitation:** matching on `exe` path alone is weak — an attacker can
drop a binary at `/usr/bin/updatedb`. Docs push toward `exe` **+** `loginuid`
together.

## 7. The hold + action ladder

### The hold
Because content is unreadable until `open()` returns, deferring the
`FAN_ALLOW`/`FAN_DENY` response makes the read hang like slow I/O — no `EACCES`
tell — and gates the token behind the full pipeline. Ordering becomes:
snapshot → hostile verdict → **hold** → run ladder to completion → then respond
(or never, if the host powered off first).

`hold` config, default tied to the ladder:
- `kill` or `poweroff` in ladder → hold until those actions complete, capped by
  `hold_max` (default **15s**, safely under `hung_task_timeout_secs`=120).
- alert-only → short fixed hold (default **3s**) guaranteeing alert-before-token,
  then allow.
- `hold: 0` → immediate allow (no hold).

Benign/allowlisted readers are **never** held.

### Hold safety properties
- **Fail-open on daemon death.** If `tripwired` dies while holding, the kernel
  closes the fanotify fd and auto-allows pending events — a hold can never
  permanently wedge path access. Daemon runs `Restart=always`; its own death is
  an alertable condition.
- **Interruptible wait.** fanotify permission waits take signals: our own
  `SIGKILL` lands mid-hold (kill isn't blocked by the hold), and an attacker who
  `Ctrl-C`s the hung `open()` merely abandons it — we've already alerted.
- **`hung_task` noise.** 15s cap stays clear of the 120s warning; cosmetic even
  if hit.

### Actions (ordered list; default `[alert, poweroff]`)

Config is an ordered list. `actions: [alert]` = pure canary (testing mode).

**`alert`** — fan out to all configured sinks, block until ≥1 confirms delivery
or `alert_timeout` (default 10s). journald always fires regardless of config.

**`freeze`** (implicit pre-step when `kill` is present) — at the hostile verdict,
before the list runs, `SIGSTOP` the reader then stop its descendants leaf-first.
Halts exfiltration with no `EACCES` tell and pins the tree so it can't fork away
during alerting. No freeze if `kill` is absent.

**`kill`** — `SIGKILL`, leaf-first. Scope config, default `tree`:

| Scope | Kills |
|---|---|
| `pid` | reader only |
| `tree` *(default)* | reader + descendants walked from `/proc` |
| `session` | everything sharing the reader's `sessionid` (whole SSH login) |
| `loginuid` | every process with the same `auid` (follows su/sudo hops) |

Kill guardrails:
- **PID-reuse guard** — re-verify recorded `starttime` immediately before
  signaling each PID; skip on mismatch.
- **`loginuid` scope refuses to run when `auid` is unset** (`4294967295`) —
  unset auid matches nearly every daemon; hard refusal, logged, no downgrade.
- Never signal PID 1, kernel threads, the daemon, or any daemon ancestor.
- **`max_kill` ceiling** (default 50): if the resolved set is larger, log the
  full set, kill nothing, continue the ladder.
- Every killed PID (pid, exe, cmdline, uid, auid) goes into the incident payload.

**`poweroff`** — default graceful `systemctl poweroff`. `poweroff: {mode: hard}`
opts into sync + SysRq emergency poweroff.

**Ordering guidance:** keep `alert` first (`[alert, kill, poweroff]`) so the
notification — the thing you can't recover after the host dies — goes out first.
The freeze already stopped the bleeding, so the ~1–2s from putting `kill` first
isn't worth risking the alert flush.

## 8. Alerting

`Sink` interface; four impls fanned out concurrently; ladder waits for ≥1
confirmed delivery or `alert_timeout`.

- **Generic HTTP webhook** — single POST, JSON incident payload; HTTP 2xx =
  confirmation. Covers Slack/Discord/Teams/PagerDuty/homegrown via URL + headers.
- **ntfy** — first-class preset with priority/tags; push to phone/desktop
  (self-hostable). The alert most likely to reach a *different* device before the
  host powers off.
- **Email** — local MTA or direct SMTP. Durable/archivable; weak delivery
  confirmation (handoff ≠ sent).
- **journald + `notify-send`** — structured journal record **always** written
  regardless of other sinks (the post-reboot forensic record), plus desktop
  notification into the graphical session (workstation profile).

Incident payload includes: timestamp, host, bait file, install fingerprint,
reader identity (exe/cmdline/uid/auid/session/cgroup/ancestors), verdict,
actions taken, and any killed PIDs.

## 9. Anti-brick guarantees

- Tripped state written to `/var/lib/tripwire/` **before** poweroff.
- On boot in tripped state the daemon starts **alert-only** and refuses to
  re-arm destructive actions until `tripwire reset`. No boot loop.
- `tripwire.disable=1` on the kernel cmdline → daemon exits at startup. Escape
  hatch for a physically-present admin, alongside `systemctl mask` from rescue.
- `tripwire test` drives the full pipeline with poweroff/kill stubbed — prove
  the alert path works before `tripwire arm`.
- Fail-open hold behavior (§7) means the daemon can never wedge file access.

## 10. Bait surface

Four files, mode `0600 root:root`, shaped like a system-wide managed install
(plausible on a server, nowhere near `~/.claude/` or `~/.codex/`):

- `/etc/claude-code/credentials.json`
- `/etc/anthropic/claude.credentials.json`
- `/etc/codex/auth.json`
- `/etc/openai/codex-auth.json`

Contents mirror the real files' JSON schema with structurally-valid,
non-functional tokens carrying a **per-install fingerprint** — if one surfaces
elsewhere, you know which host leaked. Expiry timestamps are refreshed
periodically (an expired-2023 token is a tell).

### Staying out of indexes
- `PRUNEPATHS` in `/etc/updatedb.conf`.
- `/etc/.gitignore` for **etckeeper** — which would otherwise both commit fake
  creds to a git repo *and* trip the wire every run.
- Exclusion hints for AIDE / rkhunter baselines.
- **Bait is generated in `postinst`, not shipped as packaged files** — so it
  appears in neither dpkg `md5sums` nor the rpm manifest, and
  `rpm -qf /etc/codex/auth.json` returns *not owned by any package*, exactly like
  a hand-configured credential file.

## 11. Packaging

`nfpm` → `.deb` + `.rpm` from one YAML, attached to GitHub Releases.
- `postinst`: generate bait, install systemd unit, write default (alert-only)
  config, add index exclusions.
- `prerm`: remove bait, unmark, remove exclusions.
- Install is **alert-only**; arming destructive actions is a deliberate
  `tripwire arm` after `tripwire test`.

Covers Debian/Ubuntu/RHEL/Fedora/SUSE. Install verbs:
`apt install ./tripwire.deb` / `dnf install ./tripwire.rpm`.

## 12. Testing

- Table-driven policy tests (benign vs hostile across match dimensions).
- `PowerOffer`/`Killer`/`Sink` interfaces → recorder assertions, no real effects
  in unit tests.
- Hold logic tested with a fake watcher: verify response is deferred until
  actions complete and released on stub-daemon-death.
- Integration tests in a privileged container (fanotify needs `CAP_SYS_ADMIN`).
- Package-install smoke tests across debian/ubuntu/rocky/fedora images —
  including the `rpm -qf` "not owned" assertion.
- One throwaway VM test that actually powers off — proves state persistence and
  no boot loop.

## 13. Decisions on record

1. Package installs **alert-only**; arming destructive actions requires an
   explicit config edit + `tripwire arm` after `tripwire test` passes.
2. Graceful poweroff is the default flavor; hard SysRq cut is opt-in.
3. Per-install token fingerprinting in v1; external canarytoken service is not.
4. `hold` folded in: default 15s (destructive ladder) / 3s (alert-only) / 0
   (opt-out); fail-open on daemon death; benign readers never held.
5. `kill` action with `freeze` pre-step; default scope `tree`; `loginuid` scope
   refuses on unset `auid`; PID-reuse guard via `starttime`; `max_kill`=50.
