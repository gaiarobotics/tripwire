# Tripwire end-to-end VM test

Goal: prove that an armed trip alerts, powers the host off, persists its state,
and comes back **alert-only** with no boot loop. No unit test can cover this —
it ends with a machine actually turning itself off.

**Use a throwaway VM you can destroy.** This test deliberately powers the machine
off from a background daemon. Do not run it on anything you care about, and do
not run it on a host you can only reach over SSH unless you can power it back on
out-of-band (cloud console, hypervisor, IPMI).

Everything below is verified by automated tests except the poweroff itself and
the two escape hatches — those need real hardware or a real VM.

## 0. Prerequisites

A VM with systemd and a kernel that supports fanotify permission events (any
modern distro). Build the packages on your workstation first:

```sh
VERSION=0.1.0 make package     # dist/*.deb and dist/*.rpm
```

Copy the package to the VM, plus a way to receive an alert off-host. An
[ntfy](https://ntfy.sh) topic is the quickest: pick an unguessable topic name and
subscribe on your phone before you start.

## 1. Install

```sh
sudo apt install ./tripwire_0.1.0_amd64.deb     # or: sudo dnf install ./tripwire-0.1.0-1.x86_64.rpm
```

Confirm the safe default — nothing destructive is configured or armed:

```sh
$ tripwire status
Profile:     server
Posture:     alert-only (no destructive actions configured)
Hold:        3s
Kill scope:  tree (max 50)
Decoys:      9
Sinks:       journal
Fingerprint: tw-...
Last test:   never run

$ tripwire verify
  OK   /etc/claude-code/credentials.json
  OK   /etc/anthropic/claude.credentials.json
  OK   /etc/codex/auth.json
  OK   /etc/openai/codex-auth.json
  OK   /etc/aws/credentials
  OK   /etc/gcloud/service-account.json
  OK   /etc/npm/npmrc
  OK   /etc/pip/pip.conf
  OK   /etc/gh/hosts.yml
```

## 2. Prove the alert reaches you, before arming anything

Edit `/etc/tripwire/config.yaml`:

```yaml
sinks:
  ntfy: { url: "https://ntfy.sh/your-unguessable-topic", priority: urgent, tags: "rotating_light" }
  journal: true
```

```sh
$ sudo tripwire test
test: sending a synthetic incident to 2 sink(s), no kill/poweroff
  OK   journal: confirmed
  OK   ntfy: confirmed
test: at least one sink confirmed delivery
```

A notification should arrive on your phone. **If it does not, stop here** — the
whole point of the exercise is that the alert outruns the poweroff. `tripwire
arm` refuses until this passes, so a failure here is the design working.

## 3. Arm it

```sh
sudo sed -i 's/^actions: \[alert\]/actions: [alert, poweroff]/' /etc/tripwire/config.yaml
sudo tripwire arm
sudo systemctl restart tripwired
```

```sh
$ tripwire status
Posture:     ARMED: alert -> poweroff
Hold:        15s

$ journalctl -u tripwired -n 5
tripwired: watching 4 decoys, actions=[alert poweroff], hold=15s, attribution=true
```

Both lines matter. `attribution=true` means fanotify came up — if it says
`false`, the daemon fell back to inotify and **disabled the destructive actions
on purpose**, so the poweroff will not happen and this test cannot proceed.

Two checks worth doing here, because they are the guardrails you are relying on:

```sh
# Without `tripwire arm`, a destructive config stays inert:
sudo tripwire disarm && sudo systemctl restart tripwired
journalctl -u tripwired -n 3
#   tripwired: destructive actions configured but not armed; running ALERT-ONLY
#   (run `tripwire test`, then `tripwire arm`)
sudo tripwire arm && sudo systemctl restart tripwired     # re-arm for the real test
```

## 4. Trip it

Open a **second SSH session** first and leave it idle — it is your way back in if
something behaves unexpectedly before the poweroff.

From a normal (non-allowlisted) login:

```sh
cat /etc/codex/auth.json
```

Expected, in order:

1. **`cat` hangs** — the read is held in `open()` while the ladder runs. Expect
   roughly the time your ntfy delivery takes (often a second or two), never more
   than the 15s cap. It looks like slow I/O: no error, no `EACCES`, no hint that
   anything noticed.
2. **A notification arrives on your phone** naming the exe, the uid, and the
   **auid** — your login uid, not root, even if you read the file through sudo.
3. **The VM powers off.** The `cat` never returns.

The ordering is the product: the alert is confirmed off-host *before* the token
is released and before the machine dies.

## 5. Verify no boot loop

Power the VM back on.

```sh
$ journalctl -u tripwired | tail -3
tripwired: prior trip on record; running ALERT-ONLY until `tripwire reset`
tripwired: watching 4 decoys, actions=[alert], hold=3s, attribution=true

$ tripwire status
TRIPPED: /usr/bin/cat read /etc/codex/auth.json at 2026-... (auid=1000)
Destructive actions are disabled until `tripwire reset`.
Posture:     alert-only (tripped; run `tripwire reset`)

$ cat /etc/codex/auth.json      # trip it again
```

The second trip **alerts and the VM stays up**. That is the property that
matters: one intrusion must not turn into a machine that powers itself off on
every boot.

Then clear it and confirm the ladder returns:

```sh
sudo tripwire reset
tripwire status                 # Posture: ARMED: alert -> poweroff
sudo systemctl restart tripwired
```

The tripped record itself is at `/var/lib/tripwire/tripped.json` if you want to
look at what was persisted before the poweroff.

## 6. Verify the escape hatches

**Kernel cmdline.** Reboot with `tripwire.disable=1` appended in GRUB (press `e`
at the boot menu, add it to the `linux` line, Ctrl-X):

```sh
$ journalctl -u tripwired
tripwired: disabled via kernel cmdline (tripwire.disable=1); exiting

$ cat /etc/codex/auth.json      # no alert, no poweroff, no hold
```

**Fail-open on daemon death.** Nothing Tripwire does may permanently wedge access
to a path. With the daemon armed and holding, kill it mid-hold:

```sh
# shell 1
cat /etc/codex/auth.json &
# shell 2, within the hold window
sudo systemctl kill -s SIGKILL tripwired
```

The `cat` returns immediately with the (worthless) token — the kernel auto-allows
every pending read when the fanotify group's fd closes. `Restart=always` brings
the daemon straight back.

**Rescue.** `systemctl mask tripwired` from a rescue shell also works, and holds
nothing while it is down.

## 7. Optional: kill scopes

With `actions: [alert, kill]` and `kill.scope: session`, tripping from an SSH
session terminates that whole login — *including the shell you typed into*. Keep
your second SSH session open and confirm it survives.

With `kill.scope: loginuid` and a reader whose `auid` is unset (a systemd
service, say), the kill must be **refused and logged** rather than quietly
downgraded — an unset auid matches nearly every daemon on the box:

```sh
$ journalctl -u tripwired | grep 'kill refused'
tripwire: kill refused: kill scope loginuid refused: auid is unset (would match system daemons)
```

## What to report back

If anything deviates, the useful evidence is:

- `journalctl -u tripwired --no-pager` since the last boot
- `tripwire status`
- `/var/lib/tripwire/tripped.json`
- how long the `cat` hung, and whether the notification arrived before or after
  the machine went down
