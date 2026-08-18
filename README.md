# Tripwire

The canary that brings down the coalmine.

Traditional canary tokens are helpful for alerting you to a compromise,
particularly one that is trying to exfiltrate your credentials. Tripwire not only notifies you, but actually stops the attack by shutting down your system.

You see, it is rather hard to keep hacking a system that is off, regardless of how good the attacker is. Some downtime is generally worth stopping an intrusion.

Tripwire does not rely on an attempt to use the credential, as traditional canaries often do - merely reading it is enough. Tripwire uses fanotify to identify the triggering user and process, and avoids triggering on benign process reads such as updatedb. As such, it is currently Linux-only.

## More specifically:

Tripwire plants decoy credential files under `/etc` — Claude Code, Codex, AWS,
GCP, npm, pip, and GitHub, and never in the real credential locations that the
tools themselves load — and watches them with fanotify
permission events. When a process that is not on the allowlist opens one,
Tripwire **holds the read** (it looks like slow I/O, not a denial), attributes
the reader down to the login user that survives `su`/`sudo`, and runs a
configurable ladder: **alert → freeze → kill → poweroff**.

The token is worthless. The point is not to protect a secret — it is to learn
that someone is reading credential files they should never touch, to tell a
human on a *different device* before the host dies, and optionally to stop the
intrusion where it stands.

```
$ cat /etc/codex/auth.json     # attacker, on a compromised host
                               # ... hangs for ~1.5s, like a slow disk
{
  "OPENAI_API_KEY": "sk-proj-tw-789470fd5eb018ea-0000000000000000000000",
  "last_refresh": "2026-08-12T12:00:00Z",
  "tokens": {
    "access_token": "tw-789470fd5eb018ea.0000000000000000",
    "account_id": "tw-789470fd5eb018ea",
    "refresh_token": "tw-789470fd5eb018ea.1111111111111111"
  }
}
```

Meanwhile, before that output appeared:

```json
{"time":"2026-08-14T06:06:26Z","host":"web-01","bait_path":"/etc/codex/auth.json",
 "verdict":"hostile","exe":"/usr/bin/cat","cmdline":"cat /etc/codex/auth.json",
 "uid":0,"auid":1000,"session_id":3,"cgroup":"0::/user.slice/.../session-3.scope",
 "ancestors":["bash","sudo","sshd"],"planned_actions":["alert","poweroff"]}
```

Note `auid: 1000` next to `uid: 0`. The reader escalated to root; the login
identity is still recorded.

## Requirements

- Linux with fanotify permission events (kernel 2.6.37+; effectively any modern
  distro). Tripwire needs `CAP_SYS_ADMIN` — the shipped systemd unit grants it.
- systemd, for the service unit and for graceful poweroff.
- Where fanotify is unavailable (restricted containers, hardened kernels),
  Tripwire degrades to inotify: reads are still **detected**, but there is no
  attribution and no hold, and destructive actions are disabled automatically.

## Install

Build the packages with `VERSION=0.1.0 make package` (see
[Building from source](#building-from-source)), then install the one for your
distro:

```sh
# Debian / Ubuntu
sudo apt install ./dist/tripwire_0.1.0_amd64.deb

# RHEL / Rocky / Fedora / SUSE
sudo dnf install ./dist/tripwire-0.1.0-1.x86_64.rpm
```

Both are verified on install by a smoke test across debian:12, ubuntu:24.04,
rockylinux:9, and fedora:41.

The install is **alert-only**. It never powers anything off until you
deliberately arm it. Installing:

- generates nine decoy credential files (they are *generated*, not shipped, so
  `rpm -qf` and `dpkg -S` report them as owned by no package — exactly what a
  hand-configured credential file looks like);
- writes `/etc/tripwire/config.yaml` from the server profile, if absent;
- excludes the decoy directories from `updatedb` and `etckeeper`, which would
  otherwise read the bait on a schedule and trip the wire every night;
- enables and starts `tripwired.service`.

Verify:

```sh
tripwire status
tripwire verify
```

## Arming

Arming is deliberately three steps, and the daemon stays alert-only until all
three are done. A destructive ladder sitting in `config.yaml` does nothing on
its own.

**1. Configure a sink that reaches another device.** Edit
`/etc/tripwire/config.yaml`:

```yaml
sinks:
  ntfy: { url: "https://ntfy.sh/your-topic", priority: urgent, tags: "rotating_light" }
```

**2. Prove the alert actually reaches you.**

```sh
$ tripwire test
test: sending a synthetic incident to 2 sink(s), no kill/poweroff
  OK   journal: confirmed
  OK   ntfy: confirmed
test: at least one sink confirmed delivery
```

This drives the real fan-out with the real sinks and the real payload — only the
destructive actions are left out. `tripwire arm` refuses until this passes.

**3. Choose the ladder and arm it.**

```sh
sudo sed -i 's/^actions: \[alert\]/actions: [alert, poweroff]/' /etc/tripwire/config.yaml
sudo tripwire arm
sudo systemctl restart tripwired
```

```
$ tripwire status
Profile:     server
Posture:     ARMED: alert -> poweroff
Hold:        15s
Kill scope:  tree (max 50)
Decoys:      4
Sinks:       ntfy, journal
Fingerprint: tw-6b4c9a241b536047
Last test:   2026-08-14T01:13:42-04:00 (delivered=true)
```

`tripwire disarm` drops back to alert-only at any time.

## Commands

| Command | Does |
|---|---|
| `tripwire status` | posture, arm state, decoy count, and whether the wire has tripped |
| `tripwire verify` | confirms every decoy is present and mode 0600 |
| `tripwire test` | sends a synthetic incident through the real sinks; records the result |
| `tripwire arm [--force]` | enables the configured destructive actions; `--force` skips the passing-test requirement |
| `tripwire disarm` | back to alert-only |
| `tripwire reset` | clears a tripped record so the host can be armed again |
| `tripwire regenerate` | rewrites the decoys, re-running LLM generation where configured |

`TRIPWIRE_CONFIG` and `TRIPWIRE_FINGERPRINT` override the CLI's default paths,
and `tripwired -config <path>` does the same for the daemon — useful for trying a
change against a scratch config before committing to it.

## Configuration

`/etc/tripwire/config.yaml`. The shipped file is commented; this is the full
surface.

```yaml
profile: server           # server | workstation (workstation adds notify-send)

actions: [alert]          # ordered ladder: alert, kill, poweroff
                          # freeze is implicit whenever kill is present

hold: 15s                 # how long a hostile read is stalled in open().
                          # Omit to derive: 3s alert-only, 15s destructive.
                          # 0s answers immediately.
alert_timeout: 10s        # how long the ladder waits for delivery confirmation

bait:                     # the decoys — created here, watched here, removed here
  - /etc/claude-code/credentials.json
  - /etc/anthropic/claude.credentials.json
  - /etc/codex/auth.json
  - /etc/openai/codex-auth.json
  - /etc/aws/credentials
  - /etc/gcloud/service-account.json
  - /etc/npm/npmrc
  - /etc/pip/pip.conf
  - /etc/gh/hosts.yml
  # Long form, for paths whose name does not reveal the schema:
  # - { path: /srv/app/config/creds.json, kind: codex }
  #   auto | claude | codex | aws | gcp | npm | pip | github | llm

llm:                      # optional; only used by `kind: llm` entries. See below.
  # provider: anthropic
  # model: claude-opus-5

kill:
  scope: tree             # pid | tree | session | loginuid
  max_kill: 50            # refuse to kill if the resolved set is larger
poweroff:
  mode: graceful          # graceful (systemctl) | hard (sync + SysRq)

sinks:
  webhook: { url: "https://example.com/hook", headers: { Authorization: "Bearer ..." } }
  ntfy:    { url: "https://ntfy.sh/your-topic", priority: urgent, tags: "rotating_light" }
  email:   { to: you@example.com, from: tripwire@localhost, smtp_addr: "" }
  journal: true           # always on; false only disables the desktop notification

allow: []                 # see below
state_dir: /var/lib/tripwire
```

### Kill scopes

| Scope | Kills |
|---|---|
| `pid` | the reader only |
| `tree` *(default)* | the reader and its descendants, leaf-first |
| `session` | everything sharing the reader's audit session — the whole SSH login |
| `loginuid` | every process with the same `auid`, following `su`/`sudo` hops |

Guardrails, all of them refusals rather than best-effort:

- `session` and `loginuid` **refuse to run** when the reader's session or `auid`
  is unset (`4294967295`). That sentinel is shared by every system daemon, so
  matching it would resolve to nearly the whole machine.
- Each PID's start time is re-verified immediately before signalling, so a PID
  recycled since the snapshot is skipped.
- PID 1, kernel threads, the daemon, and the daemon's own ancestors are never
  signalled.
- If the resolved set exceeds `max_kill`, Tripwire logs the whole set and kills
  **nothing**, then continues down the ladder.

### Allowlist

Anything not matched is hostile — the default is deny. Within one rule every
field set must match; any single rule matching makes the read benign. A rule
with no fields set matches nothing, so a half-written rule cannot accidentally
allowlist the world.

```yaml
allow:
  - { exe: /usr/bin/updatedb, loginuid: 4294967295, comment: "mlocate, system context" }
  - { exe: /usr/bin/aide, unit: aide.service, comment: "integrity baseline" }
  - { ancestor: backupd, cap_eff: "0000000000000004", comment: "backup agent w/ CAP_DAC_READ_SEARCH" }
```

| Field | Matches |
|---|---|
| `exe` | resolved executable path |
| `uid` | real uid |
| `loginuid` | audit login uid (`auid`), survives `su`/`sudo` |
| `unit` | substring of the cgroup path, e.g. a systemd unit name |
| `ancestor` | exe or comm of any process in the parent chain |
| `cap_eff` | hex capability mask; the reader must hold **every** bit in it |

Matching on `exe` alone is weak — an attacker can drop a binary at
`/usr/bin/updatedb`. Pair it with `loginuid`, `unit`, or `cap_eff`.

If you run AIDE, rkhunter, or a backup agent over `/etc`, see
`/usr/share/tripwire/exclusions.txt` for the exclusion snippets. Excluding the
decoys is usually better than allowlisting the tool.

## Why the read hangs

A file's contents are unreadable until `open()` returns, so deferring the
fanotify response gates the token behind the whole pipeline: snapshot → verdict
→ hold → ladder → respond. To the reader it looks like slow I/O — there is no
`EACCES` to tell them they were caught.

The hold is a **cap, not a floor**: the reader is released the moment the ladder
finishes. In practice a hostile read is held for as long as the alert takes to
be confirmed — typically a second or two — and never longer than `hold`.

Only an **off-host** confirmation can end the wait. journald confirms instantly
and never leaves the machine, so if a local confirmation were enough, a
`poweroff` could beat the notification off the box.

Benign readers are never held at all.

## Safety properties

Tripwire can power your host off, so every failure mode is designed to fail
toward availability.

- **Fail-open.** If `tripwired` dies mid-hold, the kernel closes the fanotify
  group and auto-allows every pending read. A hold can never permanently wedge
  access to a path. This is covered by an integration test that closes the group
  while a reader is blocked and asserts the read completes.
- **No boot loop.** The trip is written to `/var/lib/tripwire/tripped.json`
  *before* any destructive action, with the file and its directory fsynced. On
  the next boot a tripped host comes up **alert-only** and refuses to re-arm
  until `tripwire reset`.
- **Escape hatch.** Boot with `tripwire.disable=1` on the kernel command line and
  the daemon exits at startup. `systemctl mask tripwired` from a rescue shell
  works too.
- **Alert-only by default,** at install and after every trip.
- **No attribution, no destruction.** On the inotify fallback there is no reader
  identity, so destructive actions are disabled regardless of config.
- **The daemon never opens a decoy.** Doing so would deadlock it against its own
  permission event. Refreshes write a temp file and rename, so the marked inode
  is never opened.

## Decoys

Nine files, mode `0600 root:root`, shaped like a system-wide managed install:

| Path | Shape |
|---|---|
| `/etc/claude-code/credentials.json` | Claude Code OAuth credentials |
| `/etc/anthropic/claude.credentials.json` | Claude Code OAuth credentials |
| `/etc/codex/auth.json` | Codex CLI / OpenAI API key |
| `/etc/openai/codex-auth.json` | Codex CLI / OpenAI API key |
| `/etc/aws/credentials` | AWS shared credentials (INI) |
| `/etc/gcloud/service-account.json` | GCP service account key |
| `/etc/npm/npmrc` | npm registry auth token |
| `/etc/pip/pip.conf` | pip index URL with a PyPI token |
| `/etc/gh/hosts.yml` | GitHub CLI OAuth token (YAML) |

Contents mirror the real credential schemas — including their real syntax, so
the npmrc is an npmrc and not JSON — with structurally valid but non-functional
tokens of the right widths. Each carries a per-install fingerprint derived from
`/etc/machine-id` (`tw-` plus 16 hex chars), so a token surfacing anywhere else
names the host it leaked from. Where the format has an expiry it is refreshed
every 12 hours — a token that expired in 2023 announces itself as bait.

None of these paths is one the real client reads: npm loads `$PREFIX/etc/npmrc`,
pip loads `/etc/pip.conf`, the AWS SDK loads `~/.aws/credentials`, and `gh` loads
`~/.config/gh/hosts.yml`. A decoy sitting where the tool would load it would hand
a dead token to every build on the host, so the bait lives one directory over —
plausible to someone reading `/etc`, invisible to the tooling.

Marks are per-inode, so the daemon also watches each parent directory and
re-marks a decoy that is replaced underneath it.

### Moving or adding decoys

`bait:` in `config.yaml` is the single source of truth: the installer creates
exactly those paths, the daemon watches and refreshes them, and uninstall removes
them. To put decoys somewhere else, edit `bait:` and re-run:

```sh
sudo tripwire _place-bait      # creates any configured decoy that is missing
sudo systemctl restart tripwired
```

Each entry is either a bare path or a mapping:

```yaml
bait:
  - /etc/codex/auth.json                                # kind: auto (the default)
  - { path: /srv/app/config/creds.json, kind: codex }   # explicit schema
  - { path: /srv/app/config/keys.json,  kind: claude }
  - { path: /srv/deploy/.credentials,   kind: aws }
```

A bare path — or `kind: auto` — infers the schema from the filename: `codex` or
`openai` gets the Codex shape, `aws` the AWS one, `gcloud`/`gcp`/`google` the
GCP one, `npm`, `pip`/`pypi`, and `github`/`gh` theirs, and anything that names
no service at all falls back to the Claude shape. Name a `kind` when the path
does not give it away, or when you want the inference overridden:

| `kind` | Writes |
|---|---|
| `claude` | Claude Code OAuth credentials (JSON) |
| `codex` | Codex CLI / OpenAI API key (JSON) |
| `aws` | AWS shared credentials (INI) |
| `gcp` | GCP service account key (JSON) |
| `npm` | npmrc with a registry auth token |
| `pip` | pip.conf with a PyPI token in the index URL |
| `github` | gh CLI hosts.yml (YAML) |
| `llm` | whatever the model writes — see below |

Unknown kinds are rejected at startup rather than silently defaulted, and writing
the config back out keeps bare paths bare.

### Generated decoys (`kind: llm`)

The built-in templates are fixed shapes. `kind: llm` instead asks a language
model to write the file, so a decoy can match whatever the host plausibly runs —
a CI service account, an internal gateway's credential file, a vendor SDK's
config — rather than one of the shipped schemas.

The model is asked for the syntax the path implies, taken from the schema that
would otherwise have been used: JSON where the template writes JSON, the
service's own INI or YAML otherwise.

It is off unless you ask for it. `auto` never selects it, and a `kind: llm` entry
with no `llm:` section is a config error rather than a silent fallback.

```yaml
bait:
  - { path: /srv/jenkins/.secrets/ai-gateway.json, kind: llm }

llm:
  provider: anthropic              # anthropic | openai-compatible
  model: claude-opus-5
  api_key_env: ANTHROPIC_API_KEY   # default per provider
  guidance: "a Jenkins build host that calls an internal AI gateway"
```

```sh
sudo ANTHROPIC_API_KEY=sk-ant-... tripwire regenerate
```

| Field | Meaning |
|---|---|
| `provider` | `anthropic` (Messages API) or `openai-compatible` (`/chat/completions` — OpenAI, vLLM, Ollama, LiteLLM, OpenRouter, most gateways) |
| `model` | Model id, e.g. `claude-opus-5` or `gpt-4o` |
| `api_key_env` | Env var holding the key. Defaults to `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` |
| `api_key_file` | File holding the key, whitespace trimmed |
| `api_key` | Inline key — discouraged; `config.yaml` is 0644 on a normal install |
| `base_url` | Self-hosted or proxied endpoint. A keyless local endpoint is allowed |
| `timeout` | Per-request timeout, default 30s |
| `max_tokens` | Default 8192 |
| `effort` | Anthropic only, sent only when set — not every model accepts it |
| `guidance` | One line about the host; the strongest lever on what the decoy looks like |

**The daemon never calls an LLM.** Generation runs only in the CLI —
`tripwire _place-bait` at install and `tripwire regenerate` on demand — so the
root process holding `CAP_SYS_ADMIN` makes no outbound requests and never needs
an API key. The consequence is that generated decoys are not refreshed on the
daemon's 12-hour timer the way template decoys are. If you want them rewritten
periodically, run `tripwire regenerate` from a systemd timer or cron with the key
in that unit's environment.

**Generation failures are never fatal.** A decoy that doesn't exist can't trip,
so an unreachable provider, a refusal, a truncated response, non-JSON output, or
output missing the install fingerprint all fall back to the template schema
inferred from the path. `tripwire _place-bait` reports the fallback and keeps
going — an install is never broken by an API outage — while `tripwire regenerate`
treats it as an error, since you asked for generation explicitly.

Every generated file is checked before it is written: it must be a non-empty JSON
object, under 64 KB, and must embed the install fingerprint. That last check is
the load-bearing one — a decoy token that can't be traced back to the host it
leaked from isn't worth planting. The no-clobber rule applies here too.

**What this does not do:** the model is asked for structurally plausible,
non-functional values, but nothing can guarantee it never reproduces a
credential-shaped string it saw in training. The fingerprint check means anything
Tripwire writes is traceable to your host; treat generated decoys as bait to be
reviewed once (`cat` one after generating), not as content you never look at.

**Tripwire never overwrites a file it did not write.** Placement checks each
target for the `tw-` fingerprint first, so pointing `bait:` at a real file by
mistake costs you an error message rather than the file. The same check governs
uninstall: an unrecognized file at a configured path is left alone.

Pick paths that are plausible for the host. The value of a decoy is that no
legitimate process has any reason to open it, so somewhere your actual tooling
never walks is worth more than somewhere realistic-but-busy.

## Building from source

Needs Go 1.25+, and [nfpm](https://github.com/goreleaser/nfpm) for packaging.

```sh
make build            # dist/tripwired, dist/tripwire
make test             # unit tests
make vet
VERSION=0.1.0 make package    # dist/*.deb and dist/*.rpm
```

Tests:

```sh
make test             # unit tests; run anywhere Linux
make integration      # fanotify tests; privileged container, needs Docker
make package && make smoke    # install across debian/ubuntu/rocky/fedora
```

`make integration` covers what unit tests cannot reach: real permission events,
the hold, fail-open on group close, and one end-to-end test that asserts a
hostile read stays blocked until the incident has actually been delivered
off-host. `make smoke` asserts, among other things, that the decoys end up owned
by no package.

The one thing no automated test covers is a real `poweroff`.
[`test/e2e/README.md`](test/e2e/README.md) is the manual VM procedure for it —
run it on a throwaway VM before arming a host you care about.

## Limitations

- Linux only. fanotify permission events have no Windows or macOS equivalent.
- Not a general-purpose FIM/HIDS. Tripwire watches bait files, not arbitrary
  paths.
- Fingerprinting is local; there is no hosted canarytoken service to register
  with.
- An attacker with root can stop the daemon — but stopping it is itself visible,
  and the alert has already gone out by the time a `poweroff` would land.
- Nothing here defends against reading the *real* credentials. The decoys are a
  detection surface, not protection.

## License

MIT — see [LICENSE](LICENSE).
