#!/usr/bin/env bash
# Apply GitHub About + topics for this project. Requires `gh auth login`.
set -euo pipefail

REPO="${GITHUB_REPOSITORY:-Franski6325/sigmwah}"
DESCRIPTION='Convert Sigma detections (pySigma) into Wazuh 4.x analysisd XML. Honest skips, persistent SIDs, no vendored SigmaHQ rules.'
HOMEPAGE='https://github.com/Franski6325/sigmwah'
TOPICS=(
  sigma
  wazuh
  pysigma
  siem
  detection-engineering
  cybersecurity
  python
  threat-detection
  infosec
  xml
  cli
  mitre-attack
  dfir
  soc
  security
)

if ! command -v gh >/dev/null 2>&1; then
  echo "Install GitHub CLI: https://cli.github.com/" >&2
  exit 1
fi

topic_args=()
for topic in "${TOPICS[@]}"; do
  topic_args+=(--add-topic "$topic")
done

gh repo edit "$REPO" \
  --description "$DESCRIPTION" \
  --homepage "$HOMEPAGE" \
  "${topic_args[@]}"

echo "Updated About + topics on https://github.com/${REPO}"
