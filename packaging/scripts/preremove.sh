#!/bin/sh
# Tripwire pre-remove: stop the daemon, remove the bait, and undo the index
# exclusions we added. Runs on upgrade too, so leave everything alone there.
set -e

case "$1" in
    upgrade|failed-upgrade|1) exit 0 ;;  # deb upgrade / rpm upgrade
esac

# Keep in sync with bait.DefaultDecoys and postinstall.sh.
BAIT_DIRS="claude-code anthropic codex openai aws gcloud npm pip gh"
BAIT_FILES="/etc/claude-code/credentials.json /etc/anthropic/claude.credentials.json
/etc/codex/auth.json /etc/openai/codex-auth.json /etc/aws/credentials
/etc/gcloud/service-account.json /etc/npm/npmrc /etc/pip/pip.conf /etc/gh/hosts.yml"

if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now tripwired.service || true
fi

# Remove the decoys the config actually names, skipping any file Tripwire did
# not write. The binary is still installed at this point (prerm runs before the
# files are removed); the hardcoded list below is the fallback if it is not.
if [ -x /usr/bin/tripwire ]; then
    /usr/bin/tripwire _remove-bait || true
else
    for f in $BAIT_FILES; do
        rm -f "$f" || true
    done
fi
# Remove the decoy directories if they are now empty; leave them if the operator
# put something else there.
for d in $BAIT_DIRS; do
    rmdir "/etc/$d" 2>/dev/null || true
done

# Undo the updatedb exclusion, one path at a time: the list has grown across
# versions, so matching the whole string would leave an older install's entries
# behind.
if [ -f /etc/updatedb.conf ]; then
    for d in $BAIT_DIRS; do
        # Each pattern requires a delimiter after the path, so removing /etc/npm
        # cannot chew the front off an operator's own /etc/npmrc entry.
        sed -i -e "s#/etc/$d ##g" -e "s# /etc/$d\"#\"#g" -e "s#\"/etc/$d\"#\"\"#g" \
            /etc/updatedb.conf || true
    done
    sed -i '/^PRUNEPATHS=""$/d; /^$/d' /etc/updatedb.conf || true
fi

# Undo the etckeeper exclusions.
if [ -f /etc/.gitignore ]; then
    for d in $BAIT_DIRS; do
        sed -i "\#^/etc/$d/\$#d" /etc/.gitignore || true
    done
fi

rm -f /usr/share/tripwire/exclusions.txt || true

echo "Tripwire removed. /etc/tripwire and /var/lib/tripwire were left in place."
