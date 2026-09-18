#!/usr/bin/env python3
"""Unit tests for the runner-version freshness gate decision logic.

Run directly (the file's directory lands on sys.path):

    python3 scripts/ci/runner_version_check_test.py
"""

import contextlib
import datetime
import io
import os
import tempfile
import unittest

import runner_version_check as gate


def utc(text):
    return datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))


def rows(*pairs):
    return [(tag, utc(stamp)) for tag, stamp in pairs]


NOW = utc("2023-02-17T12:00:00Z")
POLICY_DAYS = 30
MAX_LAG_DAYS = 23

# Captured shape of the real actions/runner release list around 2023-02-17,
# when the backport v2.299.2 was the claimed version although far newer
# releases had been out for months. Position in this list is not semver
# order, so reading the row above ours (v2.302.0, two days old) as the
# deprecation clock was a false pass — the clock is v2.300.0, the oldest
# semver-newer release.
BACKPORT_HISTORY = [
    ("v2.302.0", "2023-02-15T00:00:00Z"),
    ("v2.301.0", "2023-01-25T00:00:00Z"),
    ("v2.300.0", "2022-12-14T00:00:00Z"),
    ("v2.299.2", "2022-12-01T00:00:00Z"),
    ("v2.299.1", "2022-11-20T00:00:00Z"),
]


def report_text(report):
    return "\n".join(report)


class EvaluateTest(unittest.TestCase):
    def test_backported_version_fails_on_the_oldest_newer_release(self):
        passed, report = gate.evaluate(
            "2.299.2", rows(*BACKPORT_HISTORY), NOW, POLICY_DAYS, MAX_LAG_DAYS
        )
        self.assertFalse(passed)
        self.assertIn("v2.300.0", report_text(report))
        self.assertIn("65d", report_text(report))

    def test_newest_version_passes_even_when_a_backport_sits_above_it(self):
        releases = rows(
            ("v2.299.2", "2023-02-16T00:00:00Z"),
            ("v2.300.0", "2022-12-14T00:00:00Z"),
        )
        passed, report = gate.evaluate("2.300.0", releases, NOW, POLICY_DAYS, MAX_LAG_DAYS)
        self.assertTrue(passed)
        self.assertIn("newest", report_text(report))

    def test_recent_successor_passes(self):
        releases = rows(
            ("v2.303.0", "2023-02-10T00:00:00Z"),
            ("v2.302.0", "2023-02-01T00:00:00Z"),
        )
        passed, _ = gate.evaluate("2.302.0", releases, NOW, POLICY_DAYS, MAX_LAG_DAYS)
        self.assertTrue(passed)

    def test_lag_exactly_at_the_margin_still_passes(self):
        releases = rows(
            ("v2.303.0", "2023-01-25T12:00:00Z"),
            ("v2.302.0", "2022-12-01T00:00:00Z"),
        )
        passed, _ = gate.evaluate("2.302.0", releases, NOW, POLICY_DAYS, MAX_LAG_DAYS)
        self.assertTrue(passed)

    def test_one_second_past_the_margin_fails(self):
        releases = rows(
            ("v2.303.0", "2023-01-25T11:59:59Z"),
            ("v2.302.0", "2022-12-01T00:00:00Z"),
        )
        passed, _ = gate.evaluate("2.302.0", releases, NOW, POLICY_DAYS, MAX_LAG_DAYS)
        self.assertFalse(passed)

    def test_unknown_version_fails(self):
        passed, report = gate.evaluate(
            "2.999.0", rows(*BACKPORT_HISTORY), NOW, POLICY_DAYS, MAX_LAG_DAYS
        )
        self.assertFalse(passed)
        self.assertIn("not an official", report_text(report))

    def test_empty_release_list_fails(self):
        passed, _ = gate.evaluate("2.337.0", [], NOW, POLICY_DAYS, MAX_LAG_DAYS)
        self.assertFalse(passed)

    def test_malformed_tag_raises(self):
        releases = rows(("v2.3x.0", "2023-01-01T00:00:00Z"))
        with self.assertRaises(gate.GateInputError):
            gate.evaluate("2.300.0", releases, NOW, POLICY_DAYS, MAX_LAG_DAYS)

    def test_malformed_claimed_version_raises(self):
        with self.assertRaises(gate.GateInputError):
            gate.evaluate("2.337", rows(*BACKPORT_HISTORY), NOW, POLICY_DAYS, MAX_LAG_DAYS)


class LoadReleasesTest(unittest.TestCase):
    def test_loads_tsv_rows(self):
        with tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False) as handle:
            handle.write("v2.337.0\t2026-08-26T14:33:29Z\n")
            handle.write("\n")
            handle.write("v2.336.0\t2026-07-20T17:45:55Z\n")
            path = handle.name
        self.addCleanup(os.unlink, path)

        releases = gate.load_releases(path)
        self.assertEqual(
            releases,
            [
                ("v2.337.0", utc("2026-08-26T14:33:29Z")),
                ("v2.336.0", utc("2026-07-20T17:45:55Z")),
            ],
        )

    def test_row_without_a_tab_raises(self):
        with tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False) as handle:
            handle.write("v2.337.0 2026-08-26T14:33:29Z\n")
            path = handle.name
        self.addCleanup(os.unlink, path)

        with self.assertRaises(gate.GateInputError):
            gate.load_releases(path)

    def test_malformed_timestamp_raises(self):
        with tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False) as handle:
            handle.write("v2.301.0\tnot-a-date\n")
            path = handle.name
        self.addCleanup(os.unlink, path)

        with self.assertRaises(gate.GateInputError):
            gate.load_releases(path)

    def test_naive_timestamp_raises(self):
        with tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False) as handle:
            handle.write("v2.301.0\t2023-01-01T00:00:00\n")
            path = handle.name
        self.addCleanup(os.unlink, path)

        with self.assertRaises(gate.GateInputError):
            gate.load_releases(path)


class MainTest(unittest.TestCase):
    # main() reads the wall clock, so only time-stable verdicts go through
    # it: history this old fails no matter when the check runs.
    def test_main_fails_on_rotted_history(self):
        with tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False) as handle:
            for tag, stamp in BACKPORT_HISTORY:
                handle.write(f"{tag}\t{stamp}\n")
            path = handle.name
        self.addCleanup(os.unlink, path)

        self.assertEqual(
            gate.main(["--releases", path, "--version", "2.299.2"]), 1
        )

    def test_main_fails_on_unknown_version(self):
        with tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False) as handle:
            for tag, stamp in BACKPORT_HISTORY:
                handle.write(f"{tag}\t{stamp}\n")
            path = handle.name
        self.addCleanup(os.unlink, path)

        self.assertEqual(
            gate.main(["--releases", path, "--version", "2.999.0"]), 1
        )

    def test_main_reports_input_errors_without_a_traceback(self):
        with tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False) as handle:
            handle.write("garbage-row\n")
            path = handle.name
        self.addCleanup(os.unlink, path)

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            exit_code = gate.main(["--releases", path, "--version", "2.300.0"])
        self.assertEqual(exit_code, 1)
        self.assertIn("check-runner-version:", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
