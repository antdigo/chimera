use super::catalog::{Reason, required_cases};
use super::driver::*;
use super::report::EvidenceMode;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

fn request() -> DriverRequest {
    DriverRequest {
        schema_version: 1,
        identity: super::report_test::identity(),
        key: required_cases()[0].clone(),
        recipe: Recipe {
            operations: vec![Operation::Observe],
            deadline_ms: 2_000,
        },
    }
}

// Synthetic scripts live only in temporary test directories. They exercise transport,
// never a sandbox or native evidence. The parent launches the script directly.
fn fixture(body: &str, hello_edit: &str) -> (tempfile::TempDir, PinnedDriver) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("driver");
    let script = format!(
        r##"#!/usr/bin/python3
import hashlib,json,sys,time
digest=hashlib.sha256(open(__file__,'rb').read()).hexdigest()
hello={{'schema_version':1,'commit':'a'*40,'binary_digest':digest,'backend':'sandboxed','supported':['S-01']}}
if sys.argv[1]=='--qualification-hello=1':
 {hello_edit}
 print(json.dumps(hello)); sys.exit(0)
r=json.load(sys.stdin)
response={{'schema_version':1,'run_id':r['identity']['run_id'],'commit':r['identity']['commit'],'config_digest':r['identity']['config_digest'],'host_boot_id':r['identity']['host_boot_id'],'driver_digest':digest,'key':r['key'],'observations':[{{'name':'preflight','value':{{'poll_count':0}}}}]}}
{body}
"##
    );
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let driver = PinnedDriver::open_fixture(&path).unwrap();
    (dir, driver)
}

#[tokio::test]
async fn driver_authenticates_identity_without_promoting_raw_observations() {
    let (_dir, driver) = fixture("print(json.dumps(response))", "pass");
    let req = request();
    let authenticated = run_driver(&driver, &req).await.unwrap();
    assert_eq!(authenticated.provenance().identity, req.identity);
    assert_eq!(authenticated.provenance().driver_digest, driver.digest());
    assert_eq!(authenticated.observations()[0].name, "preflight");
    let mut native = req;
    native.identity.mode = EvidenceMode::NativeDebian;
    assert!(run_driver(&driver, &native).await.is_err());
}

#[tokio::test]
async fn driver_rejects_all_response_identity_mismatches_and_untrusted_fields() {
    for edit in [
        "response['run_id']='00000000-0000-4000-8000-000000000099'",
        "response['commit']='d'*40",
        "response['config_digest']='d'*64",
        "response['host_boot_id']='00000000-0000-4000-8000-000000000099'",
        "response['driver_digest']='d'*64",
        "response['key']['case']='no-cgroup-v2'",
        "response['schema_version']=2",
        "response['passed']=True",
        "response['observations']*=2",
        "response['observations'][0]['passed']=True",
        "response['key']['unknown']=True",
    ] {
        let (_dir, driver) = fixture(&format!("{edit}\nprint(json.dumps(response))"), "pass");
        assert_eq!(
            run_driver(&driver, &request()).await.unwrap_err(),
            Reason::ProtocolViolation,
            "{edit}"
        );
    }
}

#[tokio::test]
async fn driver_rejects_bad_hello_and_unknown_versions() {
    for edit in [
        "hello['binary_digest']='d'*64",
        "hello['commit']='d'*40",
        "hello['schema_version']=2",
        "hello['backend']='other'",
        "hello['supported']=[]",
        "hello['supported']*=2",
        "hello['passed']=True",
    ] {
        let (_dir, driver) = fixture("print(json.dumps(response))", edit);
        assert_eq!(
            run_driver(&driver, &request()).await.unwrap_err(),
            Reason::ProtocolViolation,
            "{edit}"
        );
    }
    let hello: DriverHello =
        serde_json::from_str(include_str!("../fixtures/qualification/driver-hello.json")).unwrap();
    assert_eq!(hello.supported.len(), 1);
}

#[tokio::test]
async fn driver_bounds_stdout_stderr_exit_and_json_framing() {
    for body in [
        "print('x'*1048577)",
        "sys.stderr.write('x'*65537); print(json.dumps(response))",
        "print('{')",
        "print(json.dumps(response)); print('{}')",
        "print(json.dumps(response)); sys.exit(1)",
    ] {
        let (_dir, driver) = fixture(body, "pass");
        assert_eq!(
            run_driver(&driver, &request()).await.unwrap_err(),
            Reason::ProtocolViolation,
            "{body}"
        );
    }
}

#[tokio::test]
async fn driver_timeout_includes_process_waiting_on_stdin_without_reply() {
    let (_dir, driver) = fixture("sys.stdin.read(); time.sleep(60)", "pass");
    let mut req = request();
    req.recipe.deadline_ms = 500;
    let start = Instant::now();
    assert_eq!(
        run_driver(&driver, &req).await.unwrap_err(),
        Reason::DeadlineExceeded
    );
    assert!(start.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn driver_rechecks_pinned_bytes_and_rejects_symlink_or_writable_binary() {
    let (dir, driver) = fixture("print(json.dumps(response))", "pass");
    let path = dir.path().join("driver");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(PinnedDriver::open_fixture(&link).is_err());
    assert!(PinnedDriver::open_fixture(std::path::Path::new("relative")).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o722)).unwrap();
    assert!(PinnedDriver::open_fixture(&path).is_err());
    assert!(run_driver(&driver, &request()).await.is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(&path, b"different bytes").unwrap();
    assert!(run_driver(&driver, &request()).await.is_err());
}

#[tokio::test]
async fn driver_invalid_request_is_rejected_before_execution() {
    let (_dir, driver) = fixture("print(json.dumps(response))", "pass");
    let mut req = request();
    req.recipe.deadline_ms = 0;
    assert_eq!(
        run_driver(&driver, &req).await.unwrap_err(),
        Reason::InvalidConfig
    );
    req.recipe.deadline_ms = 2_000;
    req.key.case = "not-allowlisted".into();
    assert_eq!(
        run_driver(&driver, &req).await.unwrap_err(),
        Reason::InvalidConfig
    );
}

#[test]
fn driver_digest_is_computed_from_opened_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("binary");
    std::fs::write(&path, b"abc").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let pinned = PinnedDriver::open_fixture(&path).unwrap();
    assert_eq!(
        pinned.digest(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(PinnedDriver::open_fixture(dir.path()).is_err());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn driver_linux_uses_open_descriptor_after_parent_directory_is_renamed() {
    let (dir, _fixture) = fixture("print(json.dumps(response))", "pass");
    let pinned = PinnedDriver::open(&dir.path().join("driver")).unwrap();
    let destination = tempfile::tempdir().unwrap();
    std::fs::rename(dir.path(), destination.path().join("moved")).unwrap();
    // Fixture-labelled request ensures this descriptor test is not native evidence.
    assert!(run_driver(&pinned, &request()).await.is_ok());
}

#[tokio::test]
async fn driver_hello_output_and_runtime_are_bounded_too() {
    for hello in [
        "print('x'*1048577); sys.exit(0)",
        "sys.stderr.write('x'*65537)",
    ] {
        let (_dir, driver) = fixture("print(json.dumps(response))", hello);
        assert_eq!(
            run_driver(&driver, &request()).await.unwrap_err(),
            Reason::ProtocolViolation
        );
    }
    let (_dir, driver) = fixture("print(json.dumps(response))", "time.sleep(60)");
    let mut req = request();
    req.recipe.deadline_ms = 500;
    assert_eq!(
        run_driver(&driver, &req).await.unwrap_err(),
        Reason::DeadlineExceeded
    );
}

#[tokio::test]
async fn driver_deadline_also_bounds_rehashing_without_blocking_the_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("large-driver");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(128 * 1024 * 1024).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let pinned = PinnedDriver::open_fixture(&path).unwrap();
    let mut req = request();
    req.recipe.deadline_ms = 1;
    let start = Instant::now();
    assert_eq!(
        run_driver(&pinned, &req).await.unwrap_err(),
        Reason::DeadlineExceeded
    );
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "rehashing blocked deadline: {:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn driver_rejects_late_ready_result_at_absolute_deadline() {
    // Polling Ready must not defeat expiration, including when validation or
    // a completed recheck makes the exchange Ready after its last await.
    let expired = tokio::time::Instant::now() - Duration::from_millis(1);
    let result = complete_before_deadline(expired, std::future::ready(Ok(()))).await;
    assert_eq!(result, Err(Reason::DeadlineExceeded));
}

#[tokio::test]
async fn driver_rejects_duplicate_fact_keys_before_value_decoding() {
    let mut accepted = Vec::new();
    for (name, facts) in [
        ("direct", r#"{"poll_count":1,"poll_count":0}"#),
        ("nested", r#"{"nested":{"poll_count":1,"poll_count":0}}"#),
        ("array", r#"{"samples":[{"allowed":false,"allowed":true}]}"#),
        ("escaped", r#"{"same":1,"\u0073ame":2}"#),
    ] {
        let body = format!(
            "print(json.dumps(response).replace('{{\"poll_count\": 0}}', {}))",
            serde_json::to_string(facts).unwrap()
        );
        let (_dir, driver) = fixture(&body, "pass");
        match run_driver(&driver, &request()).await {
            Err(Reason::ProtocolViolation) => {}
            other => accepted.push(format!("{name}: {other:?}")),
        }
    }
    assert!(
        accepted.is_empty(),
        "duplicate facts accepted: {accepted:?}"
    );
}

#[tokio::test]
async fn driver_preserves_unique_nested_facts_and_object_local_key_scope() {
    let (_dir, driver) = fixture(
        "response['observations'][0]['value']={'samples':[{'count':1},{'count':2}],'fraction':0.5,'negative':-1,'label':'synthetic','empty':None,'enabled':True}; print(json.dumps(response))",
        "pass",
    );
    let authenticated = run_driver(&driver, &request()).await.unwrap();
    assert_eq!(
        authenticated.observations()[0].value,
        serde_json::json!({
            "samples": [{"count": 1}, {"count": 2}], "fraction": 0.5,
            "negative": -1, "label": "synthetic", "empty": null, "enabled": true,
        })
    );
}
