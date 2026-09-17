# Runner context compatibility

Chimera identifies every supported execution as a self-hosted runner in the
GitHub Actions expression context:

| Property | Type | Value |
|---|---|---|
| `runner.environment` | string | `"self-hosted"` |
| `runner.labels` | array of strings | `["self-hosted"]` |

`runner.environment` is the standard GitHub runner-context property.
`runner.labels` is a Chimera compatibility extension for existing workflows
that use conditions such as:

```yaml
if: always() && contains(runner.labels, 'self-hosted')
```

The `runner.labels` array is deliberately incomplete. It does not mirror the
labels stored by GitHub and does not include OS, architecture, runner names,
requested `runs-on` values, or custom labels such as `sandbox-prod`. In
particular, offline-imported registrations provide no authoritative local
source for the complete server-side label set. Job assignment has already
happened in GitHub's control plane before Chimera evaluates a step expression.

The two properties are runner-owned. `RUNNER_LABELS` and
`RUNNER_ENVIRONMENT` values supplied through manifest variables, step env, or
`$GITHUB_ENV` do not change expression results. This does not hide or rewrite
those variables inside the step's shell. `vars.RUNNER_LABELS` remains an
independent repository variable.

Host steps, job-container steps, composite substeps, and post-actions use the
same values. A true `always() && contains(...)` condition makes a step eligible
after an ordinary failed step. It cannot guarantee execution after SIGKILL,
runner crash, or every cancellation path; lifecycle cleanup is a separate
responsibility.
