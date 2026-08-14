#!/bin/sh
# Tripwire post-install: place the bait, keep it out of the indexes that would
# otherwise trip it, and start the daemon ALERT-ONLY.
set -e

CONFDIR=/etc/tripwire
CONF="$CONFDIR/config.yaml"
BAIT_DIRS="claude-code anthropic codex openai"

mkdir -p "$CONFDIR" /var/lib/tripwire
chmod 0700 /var/lib/tripwire || true

# Never clobber an operator's config on upgrade.
if [ ! -f "$CONF" ]; then
    cp /usr/share/tripwire/server.yaml "$CONF"
    chmod 0644 "$CONF"
fi

# Generate the decoys. They are created here rather than shipped in the package,
# so `rpm -qf` / `dpkg -S` report them as owned by no package — exactly like a
# hand-configured credential file. This also writes /etc/tripwire/fingerprint.
/usr/bin/tripwire _place-bait

# Keep the bait out of mlocate's index: updatedb would read every decoy nightly.
if [ -f /etc/updatedb.conf ] && ! grep -q '/etc/codex' /etc/updatedb.conf; then
    if grep -q '^PRUNEPATHS=' /etc/updatedb.conf; then
        sed -i 's#^PRUNEPATHS="#PRUNEPATHS="/etc/codex /etc/openai /etc/claude-code /etc/anthropic #' \
            /etc/updatedb.conf || true
    else
        echo 'PRUNEPATHS="/etc/codex /etc/openai /etc/claude-code /etc/anthropic"' >> /etc/updatedb.conf
    fi
fi

# etckeeper would otherwise commit fake credentials into a git repo *and* trip
# the wire on every run.
if [ -d /etc/.git ] || command -v etckeeper >/dev/null 2>&1; then
    for d in $BAIT_DIRS; do
        grep -qxF "/etc/$d/" /etc/.gitignore 2>/dev/null || echo "/etc/$d/" >> /etc/.gitignore
    done
fi

# AIDE and rkhunter baseline hints. These are printed rather than applied: their
# config files belong to the operator, and a bad edit breaks integrity checking.
cat > /usr/share/tripwire/exclusions.txt <<'EOF'
Tripwire decoys live in /etc/claude-code, /etc/anthropic, /etc/codex, /etc/openai.

Any tool that reads them on a schedule will trip the wire. Exclude them:

  AIDE (/etc/aide.conf or /etc/aide/aide.conf):
    !/etc/claude-code
    !/etc/anthropic
    !/etc/codex
    !/etc/openai

  rkhunter (/etc/rkhunter.conf):
    EXISTWHITELIST=/etc/codex/auth.json
    EXISTWHITELIST=/etc/openai/codex-auth.json
    EXISTWHITELIST=/etc/claude-code/credentials.json
    EXISTWHITELIST=/etc/anthropic/claude.credentials.json

  Backup agents: either exclude those paths, or allowlist the agent in
  /etc/tripwire/config.yaml (prefer matching exe AND loginuid together).
EOF

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable --now tripwired.service || true
fi

cat <<'EOF'

Tripwire installed ALERT-ONLY.

  tripwire status    # posture and decoy count
  tripwire verify    # confirm the decoys are in place
  tripwire test      # prove an alert actually reaches you

Configure a sink that reaches a *different device* in /etc/tripwire/config.yaml
before arming anything destructive. See /usr/share/tripwire/exclusions.txt if you
run AIDE, rkhunter, or a backup agent over /etc.
EOF
