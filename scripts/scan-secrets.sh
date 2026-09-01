#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

python3 scripts/validate_repository.py --secrets-only

gitleaks_binary=""
temporary_directory=""
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks_binary="$(command -v gitleaks)"
else
  gitleaks_version="8.30.1"
  platform="$(uname -s)_$(uname -m)"

  case "$platform" in
    Darwin_arm64)
      archive="gitleaks_${gitleaks_version}_darwin_arm64.tar.gz"
      expected_sha256="b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"
      ;;
    Darwin_x86_64)
      archive="gitleaks_${gitleaks_version}_darwin_x64.tar.gz"
      expected_sha256="dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709"
      ;;
    Linux_aarch64|Linux_arm64)
      archive="gitleaks_${gitleaks_version}_linux_arm64.tar.gz"
      expected_sha256="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"
      ;;
    Linux_x86_64|Linux_amd64)
      archive="gitleaks_${gitleaks_version}_linux_x64.tar.gz"
      expected_sha256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
      ;;
    *)
      echo "ERROR: no checksum-pinned Gitleaks build for $platform" >&2
      exit 1
      ;;
  esac

  temporary_directory="$(mktemp -d)"
  trap 'rm -rf "$temporary_directory"' EXIT
  archive_path="$temporary_directory/$archive"
  release_url="https://github.com/gitleaks/gitleaks/releases/download/v${gitleaks_version}/$archive"

  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
    --output "$archive_path" "$release_url"

  if command -v sha256sum >/dev/null 2>&1; then
    actual_sha256="$(sha256sum "$archive_path" | awk '{print $1}')"
  else
    actual_sha256="$(shasum -a 256 "$archive_path" | awk '{print $1}')"
  fi
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    echo "ERROR: Gitleaks archive checksum did not match" >&2
    exit 1
  fi

  tar -xzf "$archive_path" -C "$temporary_directory" gitleaks
  gitleaks_binary="$temporary_directory/gitleaks"
fi

"$gitleaks_binary" dir --config .gitleaks.toml --redact --no-banner .
"$gitleaks_binary" git --config .gitleaks.toml --redact --no-banner .
