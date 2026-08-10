#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

if command -v actionlint >/dev/null 2>&1; then
  exec actionlint -color
fi

actionlint_version="1.7.12"
platform="$(uname -s)_$(uname -m)"

case "$platform" in
  Darwin_arm64)
    archive="actionlint_${actionlint_version}_darwin_arm64.tar.gz"
    expected_sha256="aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f"
    ;;
  Darwin_x86_64)
    archive="actionlint_${actionlint_version}_darwin_amd64.tar.gz"
    expected_sha256="5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644"
    ;;
  Linux_aarch64|Linux_arm64)
    archive="actionlint_${actionlint_version}_linux_arm64.tar.gz"
    expected_sha256="325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6"
    ;;
  Linux_x86_64|Linux_amd64)
    archive="actionlint_${actionlint_version}_linux_amd64.tar.gz"
    expected_sha256="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
    ;;
  *)
    echo "ERROR: no checksum-pinned Actionlint build for $platform" >&2
    exit 1
    ;;
esac

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
archive_path="$temporary_directory/$archive"
release_url="https://github.com/rhysd/actionlint/releases/download/v${actionlint_version}/$archive"

curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  --output "$archive_path" "$release_url"

if command -v sha256sum >/dev/null 2>&1; then
  actual_sha256="$(sha256sum "$archive_path" | awk '{print $1}')"
else
  actual_sha256="$(shasum -a 256 "$archive_path" | awk '{print $1}')"
fi
if [[ "$actual_sha256" != "$expected_sha256" ]]; then
  echo "ERROR: Actionlint archive checksum did not match" >&2
  exit 1
fi

tar -xzf "$archive_path" -C "$temporary_directory" actionlint
"$temporary_directory/actionlint" -color
