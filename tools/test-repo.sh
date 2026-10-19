#!/bin/sh
# Install Linux Passkey from a make-repo.sh tree on each distribution family,
# with every signature checked, the way the install page tells users to.
#
#   tools/test-repo.sh OUT PACKAGES FINGERPRINT
#
# Needs Docker; the clients reach tools/serve-repo.py over the host network.

set -eu
OUT=$(cd "$1" && pwd)
PACKAGES=$(cd "$2" && pwd)
FPR=$3
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${PORT:-8765}
KEY=http://127.0.0.1:$PORT/linux-passkey
INSTALL="linux-passkey gnome-shell-extension-linux-passkey"

python3 "$HERE/serve-repo.py" "$OUT/tree" "$PACKAGES" "$PORT" 2>/dev/null &
server=$!
trap 'kill $server' EXIT
sleep 1

run() { # image script
    echo "== $1"
    docker run --rm --network host -e KEY="$KEY" -e FPR="$FPR" -e INSTALL="$INSTALL" "$1" sh -euc "$2"
}

run ubuntu:24.04 '
apt-get -qq update && apt-get -qq install -y curl ca-certificates >/dev/null
curl -fsSL $KEY/linux-passkey.gpg -o /usr/share/keyrings/linux-passkey.gpg
echo "deb [signed-by=/usr/share/keyrings/linux-passkey.gpg] $KEY/apt stable main" > /etc/apt/sources.list.d/linux-passkey.list
apt-get -qq update
DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends $INSTALL >/dev/null
passkeyd --version'

run fedora:44 '
curl -fsSL $KEY/rpm/fedora/linux-passkey.repo -o /etc/yum.repos.d/linux-passkey.repo
dnf -q -y --setopt=install_weak_deps=False install $INSTALL >/tmp/dnf.log 2>&1 || { tail -30 /tmp/dnf.log; exit 1; }
rpm -q --qf "%{NAME} %{RSAHEADER:pgpsig}\n" linux-passkey | grep -v "(none)"
passkeyd --version'

run opensuse/tumbleweed '
zypper -q --non-interactive addrepo $KEY/rpm/opensuse/linux-passkey.repo
zypper -q --non-interactive --gpg-auto-import-keys install --no-recommends $INSTALL >/dev/null
passkeyd --version'

run archlinux:latest '
pacman-key --init >/dev/null 2>&1
curl -fsSL $KEY/linux-passkey.asc -o /tmp/linux-passkey.asc
pacman-key --add /tmp/linux-passkey.asc >/dev/null 2>&1 && pacman-key --lsign-key "$FPR" >/dev/null 2>&1
printf "\n[linux-passkey]\nServer = %s\n" $KEY/arch >> /etc/pacman.conf
pacman -Sy --noconfirm $INSTALL >/dev/null
passkeyd --version'

echo "All four installed."
