use super::*;
use crate::job::action::{ActionCache, ActionSource, TrustedActionDirectory};

async fn trust_action_root(root: &std::path::Path) -> TrustedActionDirectory {
    let cache = ActionCache::new(root.join("cache"), reqwest::Client::new());
    cache
        .get_action(
            &ActionSource::Local { path: ".".into() },
            root,
            "fake-token",
        )
        .await
        .unwrap()
}

async fn resolve_test_action(
    tmp: &tempfile::TempDir,
) -> (std::path::PathBuf, TrustedActionDirectory) {
    let workspace = tmp.path().join("workspace");
    let action_dir = workspace.join("actions/test");
    std::fs::create_dir_all(&action_dir).unwrap();
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let source = ActionSource::Local {
        path: "actions/test".into(),
    };
    let resolved = cache
        .get_action(&source, &workspace, "fake-token")
        .await
        .unwrap();
    (workspace, resolved)
}

#[tokio::test]
async fn parse_node_action() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("action.yml"),
        r#"
name: 'Test Action'
inputs:
  token:
    description: 'GitHub token'
    required: true
    default: '${{ github.token }}'
  path:
    description: 'Path to checkout'
    required: false
outputs:
  result:
    description: 'The result'
runs:
  using: 'node20'
  main: 'dist/index.js'
  post: 'dist/cleanup.js'
  post-if: 'always()'
"#,
    )
    .unwrap();

    let trusted = trust_action_root(tmp.path()).await;
    let metadata = load_action_metadata(&trusted).unwrap();
    assert_eq!(metadata.name.as_deref(), Some("Test Action"));
    assert!(metadata.runs.is_node());
    assert!(!metadata.runs.is_composite());
    assert!(!metadata.runs.is_docker());
    assert_eq!(metadata.runs.main.as_deref(), Some("dist/index.js"));
    assert_eq!(metadata.runs.post.as_deref(), Some("dist/cleanup.js"));
    assert!(metadata.runs.pre.is_none());

    assert_eq!(metadata.inputs.len(), 2);
    let token_input = &metadata.inputs["token"];
    assert_eq!(token_input.default.as_deref(), Some("${{ github.token }}"));
}

#[tokio::test]
async fn parse_composite_action() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("action.yml"),
        r#"
name: 'Composite Action'
runs:
  using: 'composite'
  steps:
    - run: echo "step 1"
      shell: bash
    - run: echo "step 2"
      shell: bash
"#,
    )
    .unwrap();

    let trusted = trust_action_root(tmp.path()).await;
    let metadata = load_action_metadata(&trusted).unwrap();
    assert!(metadata.runs.is_composite());
    assert!(!metadata.runs.is_node());
    assert!(metadata.runs.steps.is_some());
    assert_eq!(metadata.runs.steps.as_ref().unwrap().len(), 2);
}

#[tokio::test]
async fn parse_docker_action() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("action.yml"),
        r#"
name: 'Docker Action'
runs:
  using: 'docker'
  image: 'Dockerfile'
"#,
    )
    .unwrap();

    let trusted = trust_action_root(tmp.path()).await;
    let metadata = load_action_metadata(&trusted).unwrap();
    assert!(metadata.runs.is_docker());
    assert_eq!(metadata.runs.image.as_deref(), Some("Dockerfile"));
}

#[tokio::test]
async fn parse_docker_action_full_fields() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("action.yml"),
        r#"
name: 'Full Docker Action'
inputs:
  greeting:
    description: 'Who to greet'
    default: 'World'
runs:
  using: 'docker'
  image: 'docker://node:18-alpine'
  entrypoint: '/entrypoint.sh'
  args:
    - '--name'
    - '${{ inputs.greeting }}'
  pre-entrypoint: '/pre.sh'
  post-entrypoint: '/post.sh'
  env:
    MY_VAR: 'hello'
    ANOTHER: 'world'
"#,
    )
    .unwrap();

    let trusted = trust_action_root(tmp.path()).await;
    let metadata = load_action_metadata(&trusted).unwrap();
    assert!(metadata.runs.is_docker());
    assert_eq!(
        metadata.runs.image.as_deref(),
        Some("docker://node:18-alpine")
    );
    assert_eq!(metadata.runs.entrypoint.as_deref(), Some("/entrypoint.sh"));
    assert_eq!(
        metadata.runs.args.as_deref(),
        Some(&["--name".to_string(), "${{ inputs.greeting }}".to_string()][..])
    );
    assert_eq!(metadata.runs.pre_entrypoint.as_deref(), Some("/pre.sh"));
    assert_eq!(metadata.runs.post_entrypoint.as_deref(), Some("/post.sh"));

    let env = metadata.runs.env.as_ref().unwrap();
    assert_eq!(env.get("MY_VAR").unwrap(), "hello");
    assert_eq!(env.get("ANOTHER").unwrap(), "world");
}

#[tokio::test]
async fn parse_docker_action_minimal() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("action.yml"),
        r#"
name: 'Minimal Docker Action'
runs:
  using: 'docker'
  image: 'alpine:latest'
"#,
    )
    .unwrap();

    let trusted = trust_action_root(tmp.path()).await;
    let metadata = load_action_metadata(&trusted).unwrap();
    assert!(metadata.runs.is_docker());
    assert_eq!(metadata.runs.image.as_deref(), Some("alpine:latest"));
    assert!(metadata.runs.entrypoint.is_none());
    assert!(metadata.runs.args.is_none());
    assert!(metadata.runs.pre_entrypoint.is_none());
    assert!(metadata.runs.post_entrypoint.is_none());
    assert!(metadata.runs.env.is_none());
}

#[tokio::test]
async fn inputs_with_defaults() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("action.yml"),
        r#"
name: 'Defaults'
inputs:
  flavor:
    default: 'vanilla'
  size:
    description: 'size of widget'
runs:
  using: 'node20'
  main: 'index.js'
"#,
    )
    .unwrap();

    let trusted = trust_action_root(tmp.path()).await;
    let metadata = load_action_metadata(&trusted).unwrap();
    assert_eq!(
        metadata.inputs["flavor"].default.as_deref(),
        Some("vanilla")
    );
    assert!(metadata.inputs["size"].default.is_none());
}

#[tokio::test]
async fn pre_and_post_scripts() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("action.yml"),
        r#"
name: 'Full Lifecycle'
runs:
  using: 'node20'
  pre: 'dist/pre.js'
  pre-if: 'always()'
  main: 'dist/main.js'
  post: 'dist/post.js'
  post-if: 'success()'
"#,
    )
    .unwrap();

    let trusted = trust_action_root(tmp.path()).await;
    let metadata = load_action_metadata(&trusted).unwrap();
    assert_eq!(metadata.runs.pre.as_deref(), Some("dist/pre.js"));
    assert_eq!(metadata.runs.pre_if.as_deref(), Some("always()"));
    assert_eq!(metadata.runs.main.as_deref(), Some("dist/main.js"));
    assert_eq!(metadata.runs.post.as_deref(), Some("dist/post.js"));
    assert_eq!(metadata.runs.post_if.as_deref(), Some("success()"));
}

#[tokio::test]
async fn missing_file_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let trusted = trust_action_root(tmp.path()).await;
    let result = load_action_metadata(&trusted);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("no action.yml"));
}

#[tokio::test]
async fn yaml_alternative_extension() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("action.yaml"),
        r#"
name: 'YAML Extension'
runs:
  using: 'node16'
  main: 'index.js'
"#,
    )
    .unwrap();

    let trusted = trust_action_root(tmp.path()).await;
    let metadata = load_action_metadata(&trusted).unwrap();
    assert_eq!(metadata.name.as_deref(), Some("YAML Extension"));
    assert!(metadata.runs.is_node());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn trusted_metadata_keeps_reading_original_action_after_source_root_replacement() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let action_dir = workspace.join("actions/test");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(
        action_dir.join("action.yml"),
        "name: original\nruns:\n  using: node20\n  main: index.js\n",
    )
    .unwrap();
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let source = ActionSource::Local {
        path: "actions/test".into(),
    };
    let trusted = cache
        .get_action(&source, &workspace, "fake-token")
        .await
        .unwrap();

    std::fs::rename(&workspace, tmp.path().join("original-workspace")).unwrap();
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(
        action_dir.join("action.yml"),
        "name: replacement-canary\nruns:\n  using: node20\n  main: canary.js\n",
    )
    .unwrap();

    let metadata = load_action_metadata(&trusted).unwrap();

    assert_eq!(metadata.name.as_deref(), Some("original"));
    assert_eq!(metadata.runs.main.as_deref(), Some("index.js"));
}

#[cfg(all(unix, not(target_os = "linux")))]
#[tokio::test]
async fn trusted_metadata_fails_closed_after_source_root_replacement() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let action_dir = workspace.join("actions/test");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(
        action_dir.join("action.yml"),
        "name: original\nruns:\n  using: node20\n  main: index.js\n",
    )
    .unwrap();
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let source = ActionSource::Local {
        path: "actions/test".into(),
    };
    let trusted = cache
        .get_action(&source, &workspace, "fake-token")
        .await
        .unwrap();

    std::fs::rename(&workspace, tmp.path().join("original-workspace")).unwrap();
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(
        action_dir.join("action.yml"),
        "name: replacement-canary\nruns:\n  using: node20\n  main: canary.js\n",
    )
    .unwrap();

    let error = load_action_metadata(&trusted).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("action directory changed after it was resolved"),
        "{error:#}"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn trusted_metadata_keeps_reading_original_action_after_symlink_root_replacement() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let action_dir = workspace.join("actions/test");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(
        action_dir.join("action.yml"),
        "name: original\nruns:\n  using: node20\n  main: index.js\n",
    )
    .unwrap();
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let source = ActionSource::Local {
        path: "actions/test".into(),
    };
    let trusted = cache
        .get_action(&source, &workspace, "fake-token")
        .await
        .unwrap();

    std::fs::rename(&workspace, tmp.path().join("original-workspace")).unwrap();
    let replacement = tmp.path().join("replacement-workspace");
    let replacement_action = replacement.join("actions/test");
    std::fs::create_dir_all(&replacement_action).unwrap();
    std::fs::write(
        replacement_action.join("action.yml"),
        "name: replacement-canary\nruns:\n  using: node20\n  main: canary.js\n",
    )
    .unwrap();
    symlink(&replacement, &workspace).unwrap();

    let metadata = load_action_metadata(&trusted).unwrap();

    assert_eq!(metadata.name.as_deref(), Some("original"));
    assert_eq!(metadata.runs.main.as_deref(), Some("index.js"));
}

#[cfg(all(unix, not(target_os = "linux")))]
#[tokio::test]
async fn trusted_metadata_fails_closed_after_symlink_root_replacement() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    let action_dir = workspace.join("actions/test");
    std::fs::create_dir_all(&action_dir).unwrap();
    std::fs::write(
        action_dir.join("action.yml"),
        "name: original\nruns:\n  using: node20\n  main: index.js\n",
    )
    .unwrap();
    let cache = ActionCache::new(tmp.path().join("cache"), reqwest::Client::new());
    let source = ActionSource::Local {
        path: "actions/test".into(),
    };
    let trusted = cache
        .get_action(&source, &workspace, "fake-token")
        .await
        .unwrap();

    std::fs::rename(&workspace, tmp.path().join("original-workspace")).unwrap();
    let replacement = tmp.path().join("replacement-workspace");
    let replacement_action = replacement.join("actions/test");
    std::fs::create_dir_all(&replacement_action).unwrap();
    std::fs::write(
        replacement_action.join("action.yml"),
        "name: replacement-canary\nruns:\n  using: node20\n  main: canary.js\n",
    )
    .unwrap();
    symlink(&replacement, &workspace).unwrap();

    let error = load_action_metadata(&trusted).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("action directory changed after it was resolved"),
        "{error:#}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn action_metadata_symlink_is_rejected_without_following_it() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside.yml");
    std::fs::write(
        &outside,
        "name: canary\nruns:\n  using: node20\n  main: canary.js\n",
    )
    .unwrap();
    let (_workspace, trusted) = resolve_test_action(&tmp).await;
    symlink(&outside, trusted.path().join("action.yml")).unwrap();

    let error = load_action_metadata(&trusted).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("action metadata must be a regular file"),
        "{error:#}"
    );
}
