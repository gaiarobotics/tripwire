# Tripwire end-to-end VM test

Goal: prove that an armed trip alerts, powers the host off, persists its state,
and comes back **alert-only** with no boot loop. No unit test can cover this —
it ends with a machine actually turning itself off.

Use a throwaway VM you can destroy. Do not run this on anything you care about.

## Setup

1. Install the package:
   `dnf install -y ./tripwire-*.rpm` (or `apt install ./tripwire_*.deb`).
2. Confirm the safe default: `tripwire status` → `Posture: alert-only`.
3. Configure an **off-host** sink in `/etc/tripwire/config.yaml`, e.g.

   ```yaml
   sinks:
     ntfy: { url: "https://ntfy.sh/your-topic", priority: urgent, tags: "rotating_light" }
   ```

4. Prove the alert reaches you: `tripwire test`
   Expected: `OK   ntfy: confirmed` and a notification on your phone.
   Arming is refused until this passes.

## Arm it

1. Edit `/etc/tripwire/config.yaml` → `actions: [alert, poweroff]`.
2. `tripwire arm` → `armed: alert -> poweroff`.
3. `systemctl restart tripwired`.
4. `tripwire status` → `Posture: ARMED: alert -> poweroff`.
5. `journalctl -u tripwired -n 5` → `watching 4 decoys, actions=[alert poweroff]`.

## Trip it

From a **non-allowlisted** login (an SSH session as a normal user, then sudo):

```
cat /etc/codex/auth.json
```

Expected, in order:

- `cat` hangs — up to the 15s hold cap. It looks like slow I/O: no `EACCES`, no
  error, no hint that anything noticed.
- An ntfy notification arrives on your phone naming the exe, the uid, and the
  **auid** — which is your login uid, not root, even though you read the file
  through sudo.
- The VM powers off. The `cat` never returns.

## Verify no boot loop

1. Power the VM back on.
2. `journalctl -u tripwired` → `prior trip on record; running ALERT-ONLY until
   'tripwire reset'`.
3. `tripwire status` → `TRIPPED: ... read /etc/codex/auth.json at ...`.
4. `cat /etc/codex/auth.json` again → the alert fires and the VM **stays up**.
   This is the property that matters: a tripped host does not power itself off
   on every subsequent boot.
5. `tripwire reset` → `tripwire status` shows the armed ladder again.
6. `systemctl restart tripwired` → destructive actions are live once more.

## Verify the escape hatches

**Kernel cmdline.** Reboot with `tripwire.disable=1` appended in GRUB:

1. `journalctl -u tripwired` → `disabled via kernel cmdline; exiting`.
2. `cat /etc/codex/auth.json` → no alert, no poweroff, no hold.

**Rescue.** From a rescue shell, `systemctl mask tripwired` also works, and the
daemon holds nothing while it is down: any pending read fails open the moment the
process dies. Confirm that directly:

```
# in one shell, with actions: [alert, poweroff] and a hold of 15s
cat /etc/codex/auth.json &
# in another, before the ladder finishes
systemctl kill -s SIGKILL tripwired
```

The `cat` should return immediately with the (worthless) token.

## Verify the kill scopes

With `actions: [alert, kill]` and `kill.scope: session`, tripping from an SSH
session should terminate that whole login — including the shell you typed into —
while leaving other sessions untouched. Keep a second SSH session open as your
way back in, and confirm it survives.

With `kill.scope: loginuid` and a reader whose `auid` is unset (a systemd
service, say), the kill must be **refused** and logged rather than downgraded:

```
journalctl -u tripwired | grep 'kill refused'
tripwire: kill refused: kill scope loginuid refused: auid is unset ...
```
