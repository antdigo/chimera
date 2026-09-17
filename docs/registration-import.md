# Import an Existing Official Runner Registration

`chimera import-official` imports an existing persistent, repository-scoped
`github.com` runner identity completely offline. It copies validated local
registration state into Chimera; it does not contact GitHub and it does not
change the server-side agent identity. `--name` is only the local Chimera key.

## Command

Always run the dry-run first:

```text
chimera import-official --source <official-runner-dir> --name <local-name> --root <chimera-root> --dry-run
```

After reviewing its result, run the import:

```text
chimera import-official --source <official-runner-dir> --name <local-name> --root <chimera-root>
```

The outcomes are `eligible`, `imported`, and `already-imported`. Errors are
categorized as `invalid-source`, `unsupported-registration`,
`identity-conflict`, `target-busy`, or `write-failed`.

## Metadata contract

The importer reads these required regular files from the official runner
source directory:

- `.runner`
- `.credentials`
- `.credentials_rsaparams`

It writes these corresponding files under the local Chimera runner storage:

- `runner.json`
- `credentials.json`
- `rsa_params.json`

The supported OAuth metadata keys are `clientId` and `authorizationUrl`, both
required, plus optional `requireFipsCryptography=false`.
`enableAuthMigrationByDefault=false` is recognized as inactive. A value of
`true`, any `authorizationUrlV2` entry, and migration sibling files are
rejected. Any other OAuth metadata key is rejected.

The following non-auth `.runner` fields are known and accepted, but are not
migrated: `poolName`, `skipSessionRecover`, `disableUpdate`,
`monitorSocketAddress`, `useRunnerAdminFlow`, and `IsHostedServer=true`.

An eligible source has all of the following:

- Positive pool and agent IDs, and nonempty agent and work-folder names.
- A UUID `clientId`.
- Exactly the `https://github.com/{owner}/{repo}` repository scope.
- Approved HTTPS endpoints at `actions.githubusercontent.com` or
  `*.actions.githubusercontent.com`.
- The persistent, non-FIPS V2 flow.
- A mathematically consistent RSA private key.

## Local storage and safety contract

`<local-name>` is a local key, not a GitHub agent rename. It must contain from
1 through 128 ASCII characters in `[A-Za-z0-9._-]`, and cannot be `.` or `..`.

The importer opens credential files without following symlinks, requires
regular files, and checks file identity while opening. Existing target
storage is accessed without following symlinks. Credential directories are
created with mode `0700`; the three credential JSON files are created with
mode `0600`, independently of umask. Existing storage must be private and
owned by the effective user. A newly created `config.toml` uses mode `0600`;
an existing configuration retains its mode.

Publication uses private staging storage and an atomic no-replace publish. A
matching completed import reports `already-imported` without duplicate output
or rewrite; a different registration at the same local name, or the same
identity under another local name, is an `identity-conflict`. The importer
never overwrites existing credential files.

A non-dry-run holds an exclusive Chimera root lock for its commit. A second
writer fails with `target-busy`; a dry-run does not create a new root. Do not
try to work around this lock or alter target storage while an import runs.

## Offline limitation and operator checks

The importer cannot determine whether an official runner on another host has
stopped. It does not receive labels, OS, or architecture, and it does not
prove online compatibility. Before the dry-run, the operator confirms that
the source is a Linux/X64 official runner. Labels are verified only in I-09.

The repository's static fixture contains synthetic test-only values,
including fixture UUID, RSA, and OAuth material. They are not operator
credentials and must not be copied into an operational source directory.

## Controlled switch, rollback, and session conflict

1. Confirm that no job is running, then normally stop one authorized official
   runner.
2. Run `import-official` with `--dry-run` and check for `eligible`.
3. Run `import-official` without `--dry-run`. Do not run `config.sh remove`,
   `chimera register`, or `chimera unregister`.
4. Only after separate owner authorization, start Chimera with that one
   identity.
5. Run one job, restart Chimera, run a second job, and verify the previous
   GitHub agent identity and labels.
6. To roll back, stop Chimera and wait for its session to be deleted, then
   start the official runner from the untouched source directory.
7. On a session conflict, do not run two clients and do not delete the
   registration; stop the experiment and investigate the cause.

## Acceptance status before canary

| ID | Status before canary | Evidence |
|---|---|---|
| I-01 | PASS automated | `imports_fixture_and_chimera_loader_preserves_every_field` |
| I-02 | PASS automated | `dry_run_is_offline_and_does_not_create_new_root` |
| I-03 | PASS automated | `repeat_reports_already_imported_without_duplicate_or_rewrite` |
| I-04 | PASS automated | `same_name_or_same_identity_conflict_leaves_target_unchanged` |
| I-05 | PASS automated | `invalid_inputs_fail_before_publish_and_redact_secrets` + source unit matrix |
| I-06 | PASS automated | path/symlink/root tests + `second_writer_is_rejected_without_blocking` |
| I-07 | PASS automated | `every_commit_checkpoint_is_recoverable_and_preserves_invariants` + focused credential/config revalidation and pre-/post-config durability tests |
| I-08 | PASS automated | `umask_zero_still_creates_private_credentials` + `restrictive_umask_still_creates_exact_private_modes` |
| I-09 | NOT RUN — owner authorization required | manual `job → restart → job → rollback` canary |

**«Offline-импорт реализован; online-перенос не подтверждён, пока I-09 не выполнен отдельно.»**
