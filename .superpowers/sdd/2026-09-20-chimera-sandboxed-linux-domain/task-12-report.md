# Plan B Task 12 — native qualification handoff, implementation-only

## Delivered

- Added a test/acceptance-feature-only native preflight behind exactly three
  fixture environment variables. It rejects absent/noncanonical resource
  locations, root UID, container markers, non-Debian/non-systemd PID 1,
  non-private or non-empty fixture root, missing executable/helper/cgroup2
  controls, unavailable kernel primitives, invalid single subordinate ranges,
  and Debian package metadata other than RootlessKit 2.3.5.
- Added all 15 Task 12 native case names as ignored, explicit fail-on-selection
  tests. They are **not implemented acceptance assertions**. The fixture
  returns `NotReady` after successful preflight rather than constructing an
  unsafe/unowned domain. Neither a missing fixture nor an incomplete assertion
  can produce a pass.
- Added an operator handoff document and an explicit implementation-only,
  native-gate-pending roadmap status. Public `sandboxed` activation remains
  unchanged and fail-closed.

## Exact blocker and remaining work

The private strict builder does not expose a safe constructor for the retained
`CleanupWorkerConfig` pinned executable/helper authority. Real subordinate-
owned tree teardown therefore cannot be guaranteed by a native test domain.
Task 12's `NativeDomainFixture::kernel/run/snapshot/destroy/assert_no_resources`
methods and the matrix's isolation, resource, crash/recovery, peer-canary, and
zero-resource assertions are **not implemented**. The named cases currently
fail when explicitly selected. A future implementation must add the narrow
constructor, wire the existing production private builder/protocol/destroy/
reconcile paths, and run the exact matrix on dedicated native Debian with
systemd delegation and a bounded dedicated I/O fixture device. Do not mark
Plan B native-qualified from this commit.

## Verification

- Initial Linux RED: `cargo test --features acceptance-tests ... --no-run`
  failed with missing `native_fixture` module before implementation.
- Linux container acceptance compile/filter: **2 preflight tests passed,
  15 native cases ignored**, exit 0. This is compilation evidence only, not
  native isolation evidence.
- Host `cargo build`: exit 0.
- Host `cargo fmt --all -- --check`: exit 0.
- Host `cargo clippy --all-targets --all-features -- -D warnings`: exit 0.
- Host elevated `cargo test --all-targets --all-features -- --test-threads=1`:
  exit 0, library **1094 passed / 23 ignored**, all integration targets green.
- Explicit Linux selection of
  `native_pid_one_private_root_and_control_fd --ignored --exact --nocapture`
  without fixture variables: exit **101**, one test failed with
  `Backend { stage: Launch, category: NotReady }`; zero passed. This is the
  intended fail-not-skip behavior, not a qualified native failure analysis.
- `cargo test sandboxed_profile_is_rejected_before_runtime_start -- --nocapture`:
  **1 passed**, exit 0; the daemon still rejects public sandbox activation
  before runtime start.
- `git diff --check`: exit 0.
- Dedicated native Debian qualification: **NOT QUALIFIED**. The current macOS
  host and Docker Desktop Linux container are not that environment; no native
  command output, case duration or zero-resource inventory is claimed.
