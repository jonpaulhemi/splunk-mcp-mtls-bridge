#!/usr/bin/env bash
# Build the installable app at the given version, check it with AppInspect, and leave it at
# output/TA-mtls-bridge-<version>.tgz. Needs requirements-build.txt installed.
set -euo pipefail

version="${1:?usage: scripts/build_app.sh VERSION}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "version must look like 1.2.3, not $version" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
# ucc-gen also writes the version into the source globalConfig.json and app.manifest; put them back after.
backup=$(mktemp -d)
cp globalConfig.json package/app.manifest "$backup"
trap 'cp "$backup/globalConfig.json" .; cp "$backup/app.manifest" package/; rm -rf "$backup"' EXIT
rm -rf output
ucc-gen build --source package --ta-version "$version"
ucc-gen package --path output/TA-mtls-bridge -o output

built=$(python -c 'import json; print(json.load(open("output/TA-mtls-bridge/app.manifest"))["info"]["id"]["version"])')
if [[ "$built" != "$version" ]]; then
  echo "the built app.manifest says version $built, not $version" >&2
  exit 1
fi

mv output/TA-mtls-bridge-*.tar.gz "output/TA-mtls-bridge-$version.tgz"
splunk-appinspect inspect "output/TA-mtls-bridge-$version.tgz" --output-file output/appinspect.json --data-format json
python scripts/check_appinspect.py output/appinspect.json
echo "built output/TA-mtls-bridge-$version.tgz"
