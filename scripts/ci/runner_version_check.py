#!/usr/bin/env python3
"""Decide whether chimera's RUNNER_VERSION is inside GitHub's runner
deprecation window.

A self-hosted runner stops receiving jobs once a release newer than its
version is more than --policy-days old (docs/gh-protocol.md, "Version
numbers matter"). Given the official actions/runner release list (rows of
`tag<TAB>published_at`, any order) and the version chimera claims, exit
non-zero when the OLDEST release semver-newer than ours is older than
--max-lag-days — a week of slack inside the policy wall.

Release-list position is not semver order (backports publish late), so
versions are compared numerically and the deprecation clock is the earliest
publication among all newer releases. Anything the gate cannot order —
unknown version, malformed tag or timestamp — also fails: it must fail
closed.

Stdlib only; the CI runner needs nothing beyond python3.
"""

import argparse
import datetime
import re
import sys

TAG_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


class GateInputError(ValueError):
    """Release input the gate cannot trust or order."""


def parse_version(text: str) -> tuple[int, ...]:
    match = TAG_RE.match(text)
    if not match:
        raise GateInputError(f"not a X.Y.Z runner version: {text!r}")
    return tuple(int(part) for part in match.groups())


def parse_timestamp(text: str) -> datetime.datetime:
    try:
        parsed = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as err:
        raise GateInputError(f"malformed published_at timestamp: {text!r}") from err
    if parsed.tzinfo is None:
        raise GateInputError(f"published_at without a timezone: {text!r}")
    return parsed


def load_releases(path: str) -> list[tuple[str, datetime.datetime]]:
    releases = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t", 1)
            if len(parts) != 2:
                raise GateInputError(f"malformed release row: {line!r}")
            releases.append((parts[0], parse_timestamp(parts[1])))
    return releases


def evaluate(
    version: str,
    releases: list[tuple[str, datetime.datetime]],
    now: datetime.datetime,
    policy_days: int,
    max_lag_days: int,
) -> tuple[bool, list[str]]:
    """Return (passed, report lines); raises GateInputError on bad input."""
    ours = parse_version(version)

    newer = []
    is_official = False
    for tag, published in releases:
        parsed = parse_version(tag)
        if parsed == ours:
            is_official = True
        elif parsed > ours:
            newer.append((tag, published))

    if not is_official:
        return False, [f"v{version} is not an official actions/runner release"]

    if not newer:
        return True, [f"v{version} is the newest actions/runner release"]

    clock_tag, clock_published = min(newer, key=lambda entry: entry[1])
    lag = now - clock_published
    lag_days = f"{lag.days}d"
    header = f"newer release {clock_tag} was published {lag_days} ago (policy wall: {policy_days}d)"

    # Compare the exact duration, not floored days, so the margin promised by
    # max_lag_days is the margin we keep.
    if lag > datetime.timedelta(days=max_lag_days):
        return False, [
            header,
            f"RUNNER_VERSION v{version} has fallen behind.",
            f"GitHub stops delivering jobs to runners more than {policy_days} days older",
            f"than the newest release ({clock_tag} is already {lag_days} old).",
            "Bump RUNNER_VERSION in src/github.rs (and the example literals in",
            "docs/gh-protocol.md) to the newest release and merge before the wall.",
        ]
    return True, [header, f"v{version} is within the deprecation window"]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--releases", required=True, help="TSV file of tag<TAB>published_at rows")
    parser.add_argument("--version", required=True, help="runner version chimera claims (X.Y.Z)")
    parser.add_argument("--policy-days", type=int, default=30)
    parser.add_argument("--max-lag-days", type=int, default=23)
    args = parser.parse_args(argv)

    try:
        releases = load_releases(args.releases)
        passed, report = evaluate(
            args.version,
            releases,
            datetime.datetime.now(datetime.timezone.utc),
            args.policy_days,
            args.max_lag_days,
        )
    except GateInputError as err:
        print(f"check-runner-version: {err}", file=sys.stderr)
        return 1

    for line in report:
        print(line)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
