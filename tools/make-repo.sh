#!/bin/sh
# Build the apt, dnf/zypper and pacman repositories for packages.akileswar.com
# from a release's packages.
#
#   tools/make-repo.sh PACKAGES OUT
#
# PACKAGES holds the .deb, .rpm (Fedora's .fcNN and openSUSE's .opensuse
# builds) and .pkg.tar.zst files. With GPG_FPR set to a secret key in the
# keyring, the RPMs are signed in place, the Arch packages get .sig files and
# every repository's metadata is signed; without it the tree is unsigned, for
# checking the layout.
#
# OUT receives linux-passkey-repo.tar.gz: the repository tree without the
# packages themselves, plus manifest.json and redirects.tsv. The site serves
# the tree under /linux-passkey and redirects each package path to the
# release asset of the same name, so the packages in PACKAGES must be the
# ones attached to the release. Repository tools that run only on Arch
# (repo-add) run in an archlinux container.

set -eu

PACKAGES=$(cd "$1" && pwd)
mkdir -p "$2"
OUT=$(cd "$2" && pwd)
BASE=${BASE:-https://packages.akileswar.com/linux-passkey}
GPG_FPR=${GPG_FPR:-}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION=$(cd "$ROOT" && python3 -c 'import linux_passkey; print(linux_passkey.__version__)')
TAG=${TAG:-v$VERSION}
APT_ARCHES="amd64 arm64 armhf i386 ppc64el riscv64 s390x"

TREE=$OUT/tree
rm -rf "$TREE" "$OUT/linux-passkey-repo.tar.gz"
mkdir -p "$TREE"

gpgsign() { # signs with the release key, if there is one
    [ -n "$GPG_FPR" ] || return 0
    gpg --batch --yes --local-user "$GPG_FPR" "$@"
}

if [ -n "$GPG_FPR" ]; then
    gpg --batch --armor --export "$GPG_FPR" > "$TREE/linux-passkey.asc"
    gpg --batch --export "$GPG_FPR" > "$TREE/linux-passkey.gpg"
fi

# apt: one suite; the packages are Architecture: all, so every index lists them.
apt=$TREE/apt
mkdir -p "$apt/pool/main"
cp "$PACKAGES"/*.deb "$apt/pool/main/"
for arch in $APT_ARCHES; do
    dir=$apt/dists/stable/main/binary-$arch
    mkdir -p "$dir"
    (cd "$apt" && apt-ftparchive packages pool/main) > "$dir/Packages"
    gzip -9nkf "$dir/Packages"
done
(cd "$apt" && apt-ftparchive \
    -o APT::FTPArchive::Release::Origin="Linux Passkey" \
    -o APT::FTPArchive::Release::Label="Linux Passkey" \
    -o APT::FTPArchive::Release::Suite=stable \
    -o APT::FTPArchive::Release::Codename=stable \
    -o APT::FTPArchive::Release::Architectures="$APT_ARCHES" \
    -o APT::FTPArchive::Release::Components=main \
    -o APT::FTPArchive::Release::Description="Linux Passkey from packages.akileswar.com" \
    release dists/stable > dists/stable/Release)
gpgsign --clearsign -o "$apt/dists/stable/InRelease" "$apt/dists/stable/Release"
gpgsign --detach-sign --armor -o "$apt/dists/stable/Release.gpg" "$apt/dists/stable/Release"

# dnf and zypper: Fedora's and openSUSE's builds differ in dependency names.
rpm_repo() { # distro glob
    dir=$TREE/rpm/$1
    mkdir -p "$dir"
    # shellcheck disable=SC2086 # $2 is a glob
    cp "$PACKAGES"/$2 "$dir/"
    if [ -n "$GPG_FPR" ]; then
        rpmsign --define "_gpg_name $GPG_FPR" --define "__gpg $(command -v gpg)" --addsign "$dir"/*.rpm >/dev/null
        cp "$dir"/*.rpm "$PACKAGES/"
    fi
    createrepo_c -q --general-compress-type=gz "$dir"
    gpgsign --detach-sign --armor -o "$dir/repodata/repomd.xml.asc" "$dir/repodata/repomd.xml"
    signed=0; [ -n "$GPG_FPR" ] && signed=1
    cat > "$dir/linux-passkey.repo" <<EOF
[linux-passkey]
name=Linux Passkey
type=rpm-md
baseurl=$BASE/rpm/$1
enabled=1
autorefresh=1
gpgcheck=$signed
repo_gpgcheck=$signed
gpgkey=$BASE/linux-passkey.asc
EOF
}
rpm_repo fedora '*.fc[0-9]*.noarch.rpm'
rpm_repo opensuse '*.opensuse.noarch.rpm'

# pacman: the database and every package signed with detached .sig files.
arch=$TREE/arch
mkdir -p "$arch"
cp "$PACKAGES"/*.pkg.tar.zst "$arch/"
for pkg in "$arch"/*.pkg.tar.zst; do
    gpgsign --detach-sign --no-armor -o "$pkg.sig" "$pkg"
done
docker run --rm -u "$(id -u):$(id -g)" -v "$arch:/repo" archlinux:latest \
    sh -c 'repo-add -q /repo/linux-passkey.db.tar.gz /repo/*.pkg.tar.zst'
# pacman fetches linux-passkey.db and .files; repo-add makes them symlinks.
for db in db files; do
    rm -f "$arch/linux-passkey.$db" "$arch/linux-passkey.$db.tar.gz.old"
    mv "$arch/linux-passkey.$db.tar.gz" "$arch/linux-passkey.$db"
    gpgsign --detach-sign --no-armor -o "$arch/linux-passkey.$db.sig" "$arch/linux-passkey.$db"
done
if [ -n "$GPG_FPR" ]; then
    cp "$arch"/*.pkg.tar.zst.sig "$PACKAGES/"
fi

# The packages leave the tree: the site redirects their paths to the release.
: > "$OUT/redirects.tsv"
(cd "$TREE" && find . -type f \( -name '*.deb' -o -name '*.rpm' -o -name '*.pkg.tar.zst' \) | sort) |
while read -r path; do
    path=${path#./}
    printf '%s\t%s\n' "$path" "$(basename "$path")" >> "$OUT/redirects.tsv"
    rm "$TREE/$path"
done
mv "$OUT/redirects.tsv" "$TREE/redirects.tsv"

FINGERPRINT=$GPG_FPR VERSION=$VERSION TAG=$TAG python3 - "$TREE/manifest.json" <<'EOF'
import datetime, json, os, sys
manifest = {
    "product": "linux-passkey",
    "title": "Linux Passkey",
    "version": os.environ["VERSION"],
    "tag": os.environ["TAG"],
    "repo": "HaythmKenway/Linux-Passkey",
    "fingerprint": os.environ["FINGERPRINT"],
    "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
EOF

tar -czf "$OUT/linux-passkey-repo.tar.gz" -C "$TREE" .
echo "Built $OUT/linux-passkey-repo.tar.gz ($(wc -l < "$TREE/redirects.tsv") packages redirected)"
