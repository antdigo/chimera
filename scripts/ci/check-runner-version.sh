#!/usr/bin/env bash
# Fails when the runner version chimera claims on the broker wire has fallen
# behind GitHub's deprecation window: a self-hosted runner stops receiving
# jobs once a release newer than its version is more than 30 days old (#27,
# docs/gh-protocol.md "Version numbers matter").
#
# The check fails a week before that wall so there is time to bump
# RUNNER_VERSION without an outage. Runs on every PR, every push to main, and
# daily from .github/workflows/runner-version.yml.
#
# Requires: gh (authenticated via GH_TOKEN), python3.

set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OFFICIAL_REPO="actions/runner"
POLICY_DAYS=30
# One week of slack inside the policy window to bump without urgency.
MAX_LAG_DAYS=$((POLICY_DAYS - 7))

version="$(sed -n 's/^pub const RUNNER_VERSION: &str = "\([^"]*\)";$/\1/p' "$REPO_ROOT/src/github.rs")"
if [[ -z "$version" ]]; then
  echo "check-runner-version: RUNNER_VERSION not found in src/github.rs" >&2
  exit 1
fi

echo "chimera claims runner version v$version"

releases_file="$(mktemp)"
trap 'rm -f "$releases_file"' EXIT

# Releases newest-first. A failure here (API outage, rate limit) must fail the
# check, not pass it silently.
gh api "repos/$OFFICIAL_REPO/releases?per_page=100" --paginate \
  --jq '.[] | select(.draft == false and .prerelease == false) | [.tag_name, .published_at] | @tsv' \
  > "$releases_file"

# The release that started our deprecation clock is the newest entry ABOVE
# ours in the newest-first list.
found=false
newer_tag=""
newer_published=""
while IFS=$'\t' read -r tag published; do
  if [[ "$tag" == "v$version" ]]; then
    found=true
    break
  fi
  newer_tag="$tag"
  newer_published="$published"
done < "$releases_file"

if [[ "$found" != true ]]; then
  echo "check-runner-version: v$version is not an official $OFFICIAL_REPO release" >&2
  exit 1
fi

if [[ -z "$newer_tag" ]]; then
  echo "ok: v$version is the newest $OFFICIAL_REPO release"
  exit 0
fi

lag_days="$(python3 - "$newer_published" <<'PY'
import datetime
import sys

published = datetime.datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00"))
lag = datetime.datetime.now(datetime.timezone.utc) - published
print(int(lag.total_seconds() // 86400))
PY
)"

echo "newer release $newer_tag was published ${lag_days}d ago (policy wall: ${POLICY_DAYS}d)"

if (( lag_days > MAX_LAG_DAYS )); then
  cat >&2 <<EOF
check-runner-version: RUNNER_VERSION v$version has fallen behind.
GitHub stops delivering jobs to runners more than $POLICY_DAYS days older
than the newest release ($newer_tag is already ${lag_days} days old).
Bump RUNNER_VERSION in src/github.rs (and the example literals in
docs/gh-protocol.md) to the newest release and merge before the wall.
EOF
  exit 1
fi

echo "ok: v$version is within the deprecation window"
