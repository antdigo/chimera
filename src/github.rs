pub mod auth;
pub mod broker;
pub mod registration;

// The runner package version chimera claims to be on every wire surface
// (session body, poll/acknowledge query params, registration bodies,
// User-Agent). GitHub stops delivering jobs to self-hosted runners once a
// release newer than their version is more than 30 days old (#27), so this
// must name a current actions/runner release; CI fails a week before that
// wall (scripts/ci/check-runner-version.sh).
pub const RUNNER_VERSION: &str = "2.337.0";
