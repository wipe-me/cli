#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: publish-package-repositories.sh <artifacts-dir> <repository-dir> <stable|preview>

Updates signed APT and RPM repositories from GoReleaser .deb and .rpm artifacts.
The caller must import the repository signing key into the active GPG keyring.
EOF
}

if [[ $# -ne 3 ]]; then
  usage >&2
  exit 2
fi

artifacts_dir=$1
repository_dir=$2
channel=$3

if [[ "$channel" != "stable" && "$channel" != "preview" ]]; then
  echo "unsupported channel: $channel" >&2
  exit 2
fi

for command in apt-ftparchive createrepo_c dpkg-deb dpkg-scanpackages gpg gzip rpm rpmsign; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "missing required command: $command" >&2
    exit 1
  fi
done

mapfile -t debs < <(find "$artifacts_dir" -maxdepth 1 -type f -name '*.deb' -print | sort)
mapfile -t rpms < <(find "$artifacts_dir" -maxdepth 1 -type f -name '*.rpm' -print | sort)

if [[ ${#debs[@]} -eq 0 || ${#rpms[@]} -eq 0 ]]; then
  echo "expected both .deb and .rpm artifacts in $artifacts_dir" >&2
  exit 1
fi

signing_fingerprint=$(
  gpg --batch --with-colons --list-secret-keys |
    awk -F: '$1 == "fpr" { print $10; exit }'
)

if [[ -z "$signing_fingerprint" ]]; then
  echo "no GPG secret key is available for repository signing" >&2
  exit 1
fi

mkdir -p "$repository_dir/keys"
gpg --batch --yes --export "$signing_fingerprint" \
  >"$repository_dir/keys/wipeme-packages.gpg"
gpg --batch --yes --armor --export "$signing_fingerprint" \
  >"$repository_dir/keys/wipeme-packages.asc"

apt_root="$repository_dir/apt"
apt_pool="$apt_root/pool/$channel/w/wipeme"
mkdir -p "$apt_pool"

for package in "${debs[@]}"; do
  architecture=$(dpkg-deb --field "$package" Architecture)
  case "$architecture" in
    amd64 | arm64) ;;
    *)
      echo "unsupported Debian architecture $architecture in $package" >&2
      exit 1
      ;;
  esac
  cp "$package" "$apt_pool/"
done

for architecture in amd64 arm64; do
  binary_dir="$apt_root/dists/$channel/main/binary-$architecture"
  mkdir -p "$binary_dir"
  (
    cd "$apt_root"
    dpkg-scanpackages \
      --arch "$architecture" \
      --multiversion \
      "pool/$channel/w/wipeme" \
      /dev/null >"dists/$channel/main/binary-$architecture/Packages"
  )
  gzip -9n -c "$binary_dir/Packages" >"$binary_dir/Packages.gz"
done

release_dir="$apt_root/dists/$channel"
apt-ftparchive \
  -o APT::FTPArchive::Release::Origin="Wipe.me" \
  -o APT::FTPArchive::Release::Label="Wipe.me CLI" \
  -o APT::FTPArchive::Release::Suite="$channel" \
  -o APT::FTPArchive::Release::Codename="$channel" \
  -o APT::FTPArchive::Release::Architectures="amd64 arm64" \
  -o APT::FTPArchive::Release::Components="main" \
  -o APT::FTPArchive::Release::Description="Wipe.me CLI $channel packages" \
  release "$release_dir" >"$release_dir/Release"

gpg --batch --yes --armor --detach-sign \
  --local-user "$signing_fingerprint" \
  --output "$release_dir/Release.gpg" \
  "$release_dir/Release"
gpg --batch --yes --clearsign \
  --local-user "$signing_fingerprint" \
  --output "$release_dir/InRelease" \
  "$release_dir/Release"

rpm_root="$repository_dir/rpm/$channel"
for architecture in x86_64 aarch64; do
  mkdir -p "$rpm_root/$architecture"
done

for package in "${rpms[@]}"; do
  architecture=$(rpm -qp --queryformat '%{ARCH}' "$package")
  case "$architecture" in
    x86_64 | aarch64) ;;
    *)
      echo "unsupported RPM architecture $architecture in $package" >&2
      exit 1
      ;;
  esac

  signed_package="$rpm_root/$architecture/$(basename "$package")"
  cp "$package" "$signed_package"
  rpmsign \
    --define "__gpg /usr/bin/gpg" \
    --define "_gpg_name $signing_fingerprint" \
    --define "_gpg_sign_cmd_extra_args --batch --pinentry-mode loopback" \
    --addsign "$signed_package"
done

for architecture in x86_64 aarch64; do
  architecture_root="$rpm_root/$architecture"
  createrepo_c --update "$architecture_root"
  gpg --batch --yes --armor --detach-sign \
    --local-user "$signing_fingerprint" \
    --output "$architecture_root/repodata/repomd.xml.asc" \
    "$architecture_root/repodata/repomd.xml"
done

cat >"$repository_dir/apt/wipeme-$channel.sources" <<EOF
Types: deb
URIs: https://packages.wipe.me/apt
Suites: $channel
Components: main
Signed-By: /usr/share/keyrings/wipeme-packages.gpg
EOF

cat >"$repository_dir/rpm/wipeme-$channel.repo" <<EOF
[wipeme-$channel]
name=Wipe.me CLI ($channel)
baseurl=https://packages.wipe.me/rpm/$channel/\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.wipe.me/keys/wipeme-packages.asc
EOF

echo "updated Wipe.me $channel APT and RPM repositories in $repository_dir"
