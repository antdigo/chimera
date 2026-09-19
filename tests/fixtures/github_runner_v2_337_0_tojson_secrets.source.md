# GitHub Runner `secrets` / `toJSON` capture

This fixture is captured output from executing the official GitHub Actions Runner
v2.337.0 code at commit `397b032cbf865e9c3ddfab89d533ec19325e1273`.
It is not transcribed from C# types or authored from Chimera's implementation.

The capture was produced on macOS arm64 with the runner's pinned .NET SDK
8.0.424. A temporary L0 test in the official runner's `src/Test/Test.csproj`:

1. constructed `Variables` with synthetic secret values for quotes, Unicode,
   a newline, and empty strings, plus `system.accessToken`,
   `system.github.token`, and a non-secret variable;
2. called the real `Variables.ToSecretsContext()` implementation;
3. evaluated `toJson(secrets)` through the real `ExpressionParser`,
   `ContextValueNode`, and `ToJson` function; and
4. wrote the returned string directly to this JSON file.

The exact focused command was:

```text
dotnet test src/Test/Test.csproj --framework net8.0 \
  --filter FullyQualifiedName~SecretsToJsonCaptureL0
```

The official test passed with one test executed and no warnings or errors. The
captured file's SHA-256 before copying was
`8db1596abec5f1a551eb4a04f76a5744df68048e922ca1429e4e3fbfa320d10c`.
Object member order comes from the runner's concurrent variable dictionary and
is not contractual, so Chimera's integration test parses both documents before
comparison. It separately checks the raw quote, newline, and Unicode escaping.

Only synthetic values appear in the fixture. The two service credentials and
the public variable were absent from the captured object, as required.
