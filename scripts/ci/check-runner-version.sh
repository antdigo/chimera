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

# Straight from the API, newest published first. Order decisions do NOT live
# here: release-list position is not semver order (backports publish late),
# so the python checker compares versions numerically. A failure here (API
# outage, rate limit) must fail the check, not pass it silently.
gh api "repos/$OFFICIAL_REPO/releases?per_page=100" --paginate \
  --jq '.[] | select(.draft == false and .prerelease == false and .published_at != null) | [.tag_name, .published_at] | @tsv' \
  > "$releases_file"

python3 "$REPO_ROOT/scripts/ci/runner_version_check.py" \
  --releases "$releases_file" \
  --version "$version" \
  --policy-days "$POLICY_DAYS" \
  --max-lag-days "$MAX_LAG_DAYS"
