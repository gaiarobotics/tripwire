#!/bin/sh
# Cross-distro package smoke test.
#
# Installs the built package in a container per distro and asserts the things a
# broken package would get wrong: the unit lands, the decoys are generated with
# the right mode, they are owned by NO package, the CLI runs, and removal takes
# the bait back out.
#
# Usage (after `make package`):
#   test/smoke/install_smoke.sh dist/tripwire_0.1.0_amd64.deb dist/tripwire-0.1.0-1.x86_64.rpm
set -e

DEB="$1"
RPM="$2"
DOCKER="${DOCKER:-docker}"

if [ -z "$DEB" ] || [ -z "$RPM" ]; then
    echo "usage: $0 <path/to.deb> <path/to.rpm>" >&2
    exit 2
fi
for f in "$DEB" "$RPM"; do
    [ -f "$f" ] || { echo "missing package: $f" >&2; exit 2; }
done

# assertions runs inside the container after install. $1 is the command that
# reports package ownership of a file (it must fail for an unowned file).
COMMON_ASSERTS='
    set -e
    test -f /lib/systemd/system/tripwired.service || { echo "FAIL: unit file missing"; exit 1; }
    test -x /usr/bin/tripwired || { echo "FAIL: daemon missing"; exit 1; }
    test -f /etc/tripwire/config.yaml || { echo "FAIL: config missing"; exit 1; }
    test -s /etc/tripwire/fingerprint || { echo "FAIL: fingerprint missing"; exit 1; }

    for f in /etc/claude-code/credentials.json /etc/anthropic/claude.credentials.json \
             /etc/codex/auth.json /etc/openai/codex-auth.json /etc/aws/credentials \
             /etc/gcloud/service-account.json /etc/npm/npmrc /etc/pip/pip.conf \
             /etc/gh/hosts.yml; do
        test -f "$f" || { echo "FAIL: decoy $f missing"; exit 1; }
        mode=$(stat -c %a "$f")
        test "$mode" = "600" || { echo "FAIL: decoy $f mode $mode, want 600"; exit 1; }
        grep -q "tw-" "$f" || { echo "FAIL: decoy $f carries no fingerprint"; exit 1; }
    done

    # The decoys must look hand-configured: owned by no package.
    if $OWNERCHECK /etc/codex/auth.json >/dev/null 2>&1; then
        echo "FAIL: decoy is owned by a package; it must be generated, not shipped"
        exit 1
    fi

    # Each format carries the license text where its own convention expects it.
    test -s "$LICENSEPATH" || { echo "FAIL: license text missing at $LICENSEPATH"; exit 1; }
    grep -q "MIT License" "$LICENSEPATH" || { echo "FAIL: $LICENSEPATH is not the MIT text"; exit 1; }

    grep -q "/etc/codex" /etc/updatedb.conf 2>/dev/null || echo "note: updatedb.conf absent, no pruning needed"

    tripwire status > /tmp/status.txt || { echo "FAIL: tripwire status errored"; cat /tmp/status.txt; exit 1; }
    grep -q "alert-only" /tmp/status.txt || { echo "FAIL: install must be alert-only"; cat /tmp/status.txt; exit 1; }
    tripwire verify || { echo "FAIL: tripwire verify"; exit 1; }
'

REMOVE_ASSERTS='
    for f in /etc/codex/auth.json /etc/openai/codex-auth.json /etc/aws/credentials \
             /etc/npm/npmrc /etc/pip/pip.conf /etc/gh/hosts.yml; do
        test ! -f "$f" || { echo "FAIL: $f survived removal"; exit 1; }
    done
    # A decoy npmrc or pip.conf left behind would point real builds at a dead
    # token, so the directories go too when nothing else claimed them.
    for d in /etc/npm /etc/pip /etc/gh /etc/aws /etc/gcloud; do
        test ! -d "$d" || { echo "FAIL: $d survived removal"; exit 1; }
    done
    grep -q "/etc/codex" /etc/updatedb.conf 2>/dev/null && { echo "FAIL: updatedb exclusion survived removal"; exit 1; }
    true
'

run() {
    img="$1"; pkg="$2"; install="$3"; remove="$4"; ownercheck="$5"; licensepath="$6"
    echo "=== $img ==="
    "$DOCKER" run --rm -v "$PWD":/src:ro -w /tmp "$img" sh -c "
        set -e
        export OWNERCHECK='$ownercheck'
        export LICENSEPATH='$licensepath'
        $install /src/$pkg
        $COMMON_ASSERTS
        $remove
        $REMOVE_ASSERTS
        echo 'OK: $img'
    "
}

run debian:12 "$DEB" \
    "apt-get update -qq >/dev/null && apt-get install -y -qq" \
    "apt-get remove -y -qq tripwire >/dev/null" \
    "dpkg -S" /usr/share/doc/tripwire/copyright

run ubuntu:24.04 "$DEB" \
    "apt-get update -qq >/dev/null && apt-get install -y -qq" \
    "apt-get remove -y -qq tripwire >/dev/null" \
    "dpkg -S" /usr/share/doc/tripwire/copyright

run rockylinux:9 "$RPM" \
    "dnf install -y -q" \
    "dnf remove -y -q tripwire >/dev/null" \
    "rpm -qf" /usr/share/licenses/tripwire/LICENSE

run fedora:41 "$RPM" \
    "dnf install -y -q" \
    "dnf remove -y -q tripwire >/dev/null" \
    "rpm -qf" /usr/share/licenses/tripwire/LICENSE

echo "smoke: all distros passed"
