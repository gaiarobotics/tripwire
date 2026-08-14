#!/bin/sh
# Tripwire pre-remove: stop the daemon, remove the bait, and undo the index
# exclusions we added. Runs on upgrade too, so leave everything alone there.
set -e

case "$1" in
    upgrade|failed-upgrade|1) exit 0 ;;  # deb upgrade / rpm upgrade
esac

if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now tripwired.service || true
fi

for f in /etc/claude-code/credentials.json /etc/anthropic/claude.credentials.json \
         /etc/codex/auth.json /etc/openai/codex-auth.json; do
    rm -f "$f" || true
done
# Remove the decoy directories if they are now empty; leave them if the operator
# put something else there.
for d in /etc/claude-code /etc/anthropic /etc/codex /etc/openai; do
    rmdir "$d" 2>/dev/null || true
done

# Undo the updatedb exclusion.
if [ -f /etc/updatedb.conf ]; then
    sed -i 's#/etc/codex /etc/openai /etc/claude-code /etc/anthropic ##; s#PRUNEPATHS="/etc/codex /etc/openai /etc/claude-code /etc/anthropic"##' \
        /etc/updatedb.conf || true
    sed -i '/^$/d' /etc/updatedb.conf || true
fi

# Undo the etckeeper exclusions.
if [ -f /etc/.gitignore ]; then
    sed -i -e '\#^/etc/claude-code/$#d' -e '\#^/etc/anthropic/$#d' \
           -e '\#^/etc/codex/$#d' -e '\#^/etc/openai/$#d' /etc/.gitignore || true
fi

rm -f /usr/share/tripwire/exclusions.txt || true

echo "Tripwire removed. /etc/tripwire and /var/lib/tripwire were left in place."
