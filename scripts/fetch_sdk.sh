#!/usr/bin/env bash
# Download the competition SDK + fixtures via the Kaggle API.
#
# Prereqs:
#   1. pip install kaggle   (handled by `make venv`)
#   2. Kaggle API token at ~/.kaggle/kaggle.json (Account -> Settings -> API -> Create New Token),
#      chmod 600 ~/.kaggle/kaggle.json
#   3. Accept the competition rules on the website (required before the API will serve the data).
#
# The SDK/fixtures are MIT-licensed but must NOT be redistributed to non-participants, so this
# lands them under ./sdk/ which is gitignored.
set -euo pipefail

COMP="ai-agent-security-multi-step-tool-attacks"
DEST="$(cd "$(dirname "$0")/.." && pwd)/sdk"
mkdir -p "$DEST"

if ! command -v kaggle >/dev/null 2>&1; then
  echo "error: kaggle CLI not found. Run 'make venv' (or 'pip install kaggle') and re-run." >&2
  exit 1
fi

echo ">> Downloading competition files to $DEST ..."
kaggle competitions download -c "$COMP" -p "$DEST"

echo ">> Unzipping ..."
cd "$DEST"
for z in *.zip; do
  [ -e "$z" ] || continue
  unzip -o "$z" && rm -f "$z"
done

echo ">> Looking for the SDK wheel ..."
WHEEL="$(find "$DEST" -name 'aicomp_sdk*.whl' | head -n1 || true)"
if [ -n "${WHEEL:-}" ]; then
  echo ">> Installing $WHEEL"
  pip install --force-reinstall "$WHEEL"
else
  echo "warning: no aicomp_sdk wheel found under $DEST — inspect the downloaded files manually." >&2
fi

echo ">> Done. SDK + fixtures are in $DEST (gitignored)."
