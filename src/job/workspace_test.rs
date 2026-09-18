use super::*;

fn make_workspace() -> (tempfile::TempDir, Workspace) {
    let tmp = tempfile::tempdir().unwrap();
    let work_dir = tmp.path().join("work");
    let tmp_dir = tmp.path().join("tmp");
    let tool_cache = tmp.path().join("tool-cache");

    let ws = Workspace::create(&work_dir, &tmp_dir, &tool_cache, "runner-0", "owner/repo").unwrap();
    (tmp, ws)
}

#[test]
fn creates_all_directories() {
    let (_tmp, ws) = make_workspace();

    assert!(ws.workspace_dir().exists());
    assert!(ws.runner_temp().exists());
    assert!(ws.tool_cache().exists());
    assert!(ws.env_file().exists());
    assert!(ws.path_file().exists());
    assert!(ws.output_file().exists());
    assert!(ws.event_file().exists());

    // Verify workspace path structure
    let ws_str = ws.workspace_dir().to_string_lossy();
    assert!(ws_str.contains("runner-0/repo/repo"));
}

#[test]
fn cleanup_removes_dirs() {
    let (_tmp, ws) = make_workspace();
    assert!(ws.workspace_dir().exists());

    ws.cleanup().unwrap();
    assert!(!ws.workspace_dir().exists());
}

#[test]
fn failed_creation_removes_partial_runner_dirs_without_touching_tool_cache() {
    let root = tempfile::tempdir().unwrap();
    let work_dir = root.path().join("work");
    let tmp_dir = root.path().join("tmp");
    let tool_cache = root.path().join("tool-cache");
    let tool_cache_entry = tool_cache.join("shared-tool");
    std::fs::create_dir_all(&tool_cache).unwrap();
    std::fs::write(&tool_cache_entry, "keep").unwrap();
    std::fs::write(&tmp_dir, "not a directory").unwrap();

    let error = Workspace::create(&work_dir, &tmp_dir, &tool_cache, "runner-0", "owner/repo")
        .err()
        .unwrap();

    assert!(format!("{error:#}").contains("creating runner temp dir"));
    assert!(!work_dir.join("runner-0").exists());
    assert!(!tmp_dir.join("runner-0").exists());
    assert_eq!(std::fs::read_to_string(&tool_cache_entry).unwrap(), "keep");
}

#[test]
fn read_env_file_key_value() {
    let (_tmp, ws) = make_workspace();
    std::fs::write(ws.env_file(), "FOO=bar\nBAZ=qux\n").unwrap();

    let env = ws.read_env_file().unwrap();
    assert_eq!(env["FOO"], "bar");
    assert_eq!(env["BAZ"], "qux");
}

#[test]
fn read_env_file_heredoc() {
    let (_tmp, ws) = make_workspace();
    std::fs::write(ws.env_file(), "MULTI<<EOF\nline1\nline2\nEOF\nSIMPLE=val\n").unwrap();

    let env = ws.read_env_file().unwrap();
    assert_eq!(env["MULTI"], "line1\nline2");
    assert_eq!(env["SIMPLE"], "val");
}

#[test]
fn read_path_file_one_per_line() {
    let (_tmp, ws) = make_workspace();
    std::fs::write(ws.path_file(), "/usr/local/bin\n/opt/bin\n").unwrap();

    let paths = ws.read_path_file().unwrap();
    assert_eq!(paths, vec!["/usr/local/bin", "/opt/bin"]);
}

#[test]
fn read_output_file_case_duplicates_last_write_wins() {
    let (_tmp, ws) = make_workspace();
    std::fs::write(ws.output_file(), "version=old\nVERSION=new\n").unwrap();

    let outputs = ws.read_output_file().unwrap();
    // Outputs live in an OrdinalIgnoreCase dictionary in the official runner:
    // the second write replaces the first (preserving the stored casing), so
    // only one entry survives and any spelling resolves to the last value.
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs["version"], "new");
    assert_eq!(
        crate::utils::find_case_insensitive(&outputs, "VERSION").unwrap(),
        "new"
    );
}

#[test]
fn read_env_file_case_duplicates_stay_distinct() {
    let (_tmp, ws) = make_workspace();
    std::fs::write(ws.env_file(), "version=old\nVERSION=new\n").unwrap();

    let env = ws.read_env_file().unwrap();
    // The env file must stay case-sensitive, mirroring the Linux environment.
    assert_eq!(env["version"], "old");
    assert_eq!(env["VERSION"], "new");
}

#[test]
fn write_event_file_writes_json() {
    let (_tmp, ws) = make_workspace();

    let event = serde_json::json!({
        "pull_request": {
            "number": 42,
            "head": { "ref": "feature-branch" }
        }
    });
    ws.write_event_file(&event).unwrap();

    let content = std::fs::read_to_string(ws.event_file()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["pull_request"]["number"], 42);
}

#[test]
fn empty_files_return_empty_results() {
    let (_tmp, ws) = make_workspace();

    let env = ws.read_env_file().unwrap();
    assert!(env.is_empty());

    let paths = ws.read_path_file().unwrap();
    assert!(paths.is_empty());

    let outputs = ws.read_output_file().unwrap();
    assert!(outputs.is_empty());
}
