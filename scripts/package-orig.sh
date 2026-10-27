#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
  echo "package-orig requires committed source and packaging files" >&2
  exit 1
fi

package_version="$(dpkg-parsechangelog -SVersion)"
upstream_version="${package_version%-*}"
source_name="$(dpkg-parsechangelog -SSource)"
output_path="../${source_name}_${upstream_version}.orig.tar.gz"

git archive --format=tar --prefix="${source_name}-${upstream_version}/" HEAD -- . ':(exclude)debian' ':(exclude)external/ietf/rfc' | gzip -n > "$output_path"
echo "$output_path"
