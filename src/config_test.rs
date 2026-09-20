use super::*;
use tempfile::TempDir;

fn test_credentials() -> RunnerCredentials {
    let key = crate::testing::test_private_key();
    let rsa_params = private_key_to_rsa_params(&key).unwrap();

    RunnerCredentials {
        info: RunnerInfo {
            agent_id: 42,
            agent_name: "test-runner".into(),
            pool_id: 1,
            server_url: "https://pipelines.actions.githubusercontent.com/abc/".into(),
            server_url_v2: "https://broker.actions.githubusercontent.com".into(),
            git_hub_url: "https://github.com/org/repo".into(),
            work_folder: "_work".into(),
            use_v2_flow: true,
        },
        oauth: OAuthCredentials {
            scheme: "OAuth".into(),
            client_id: "client-id-123".into(),
            authorization_url: "https://vstoken.actions.githubusercontent.com/abc".into(),
        },
        rsa_params,
    }
}

#[test]
fn rsa_key_roundtrip() {
    let key = crate::testing::test_private_key();

    let params = private_key_to_rsa_params(&key).unwrap();
    let reconstructed = rsa_params_to_private_key(&params).unwrap();

    assert_eq!(key.n(), reconstructed.n());
    assert_eq!(key.e(), reconstructed.e());
    assert_eq!(key.d(), reconstructed.d());
}

#[test]
fn rsa_validation_rejects_inconsistent_derived_parameters() {
    type FieldSelector = fn(&mut RsaParameters) -> &mut String;

    let key = crate::testing::test_private_key();
    let params = private_key_to_rsa_params(&key).unwrap();

    let corruptions: [(&str, FieldSelector); 3] = [
        ("dp", |value| &mut value.dp),
        ("dq", |value| &mut value.dq),
        ("inverseQ", |value| &mut value.inverse_q),
    ];

    for (field, select) in corruptions {
        let mut invalid = params.clone();
        *select(&mut invalid) = BASE64.encode([1_u8]);

        let error = rsa_params_to_private_key(&invalid).unwrap_err();

        assert!(error.to_string().contains(field), "got: {error:#}");
    }
}

#[test]
fn runner_credentials_have_structural_equality() {
    let credentials = test_credentials();

    assert_eq!(credentials.clone(), credentials);
}

#[test]
fn credentials_save_load_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let runners_dir = tmp.path().join("runners");

    let creds = test_credentials();
    let original_key = rsa_params_to_private_key(&creds.rsa_params).unwrap();

    save_runner_credentials(&runners_dir, "test-runner", &creds).unwrap();
    let loaded = load_runner_credentials(&runners_dir, "test-runner").unwrap();

    assert_eq!(loaded.info.agent_id, 42);
    assert_eq!(loaded.info.agent_name, "test-runner");
    assert_eq!(loaded.oauth.client_id, "client-id-123");

    // Verify RSA key survives roundtrip through files
    let loaded_key = rsa_params_to_private_key(&loaded.rsa_params).unwrap();
    assert_eq!(original_key.n(), loaded_key.n());
}

#[test]
fn config_load_save_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.toml");

    let config = ChimeraConfig {
        daemon: DaemonConfig {
            log_format: "json".into(),
            shutdown_timeout_secs: 300,
        },
        execution: ExecutionConfig {
            profile: ExecutionProfile::Sandboxed,
            max_active_domains: std::num::NonZeroUsize::new(40).unwrap(),
            resources: None,
        },
        runners: vec!["runner-0".into(), "runner-1".into()],
        ..Default::default()
    };

    save_config(&config_path, &config).unwrap();
    let loaded = load_config(&config_path).unwrap();

    assert_eq!(loaded.runners.len(), 2);
    assert_eq!(loaded.runners[0], "runner-0");
    assert_eq!(loaded.daemon.log_format, "json");
    assert_eq!(loaded.execution.profile, ExecutionProfile::Sandboxed);
    assert_eq!(loaded.execution.max_active_domains.get(), 40);
}

#[test]
fn load_config_creates_default_file_when_missing() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.toml");

    assert!(!config_path.exists());
    let config = load_config(&config_path).unwrap();
    assert!(config_path.exists());

    assert!(config.runners.is_empty());
    assert_eq!(config.daemon.log_format, "text");
    assert_eq!(config.daemon.shutdown_timeout_secs, 300);
    assert_eq!(config.cache.max_gb, 10);
    assert_eq!(config.cache.cache_port, 9999);
    assert_eq!(config.execution.profile, ExecutionProfile::TrustedHost);
    assert_eq!(config.execution.max_active_domains.get(), 1);

    // Verify the written file contains all sections
    let contents = std::fs::read_to_string(&config_path).unwrap();
    assert!(contents.contains("[daemon]"));
    assert!(contents.contains("[cache]"));
    assert!(contents.contains("[execution]"));
    assert!(contents.contains("profile = \"trusted-host\""));
    assert!(contents.contains("max_active_domains = 1"));
    assert!(contents.contains("log_format"));
    assert!(contents.contains("shutdown_timeout_secs"));
    assert!(contents.contains("max_gb"));
    assert!(contents.contains("cache_port"));
}

#[test]
fn optional_config_load_does_not_create_missing_file() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.toml");

    let config = load_config_if_exists(&config_path).unwrap();

    assert!(config.is_none());
    assert!(!config_path.exists());
}

#[cfg(unix)]
#[test]
fn optional_config_load_rejects_symlink() {
    use std::os::unix::fs::symlink;

    let tmp = TempDir::new().unwrap();
    let outside = tmp.path().join("outside.toml");
    std::fs::write(&outside, "runners = []\n").unwrap();
    let config_path = tmp.path().join("config.toml");
    symlink(&outside, &config_path).unwrap();

    assert!(load_config_if_exists(&config_path).is_err());
    assert_eq!(std::fs::read_to_string(outside).unwrap(), "runners = []\n");
}

#[test]
fn path_construction() {
    let paths = ChimeraPaths::new(PathBuf::from("/home/user/.chimera"));
    assert_eq!(
        paths.config_file(),
        PathBuf::from("/home/user/.chimera/config.toml")
    );
    assert_eq!(
        paths.runners_dir(),
        PathBuf::from("/home/user/.chimera/runners")
    );
    assert_eq!(
        paths.runner_dir("r0"),
        PathBuf::from("/home/user/.chimera/runners/r0")
    );
    assert_eq!(paths.work_dir(), PathBuf::from("/home/user/.chimera/work"));
    assert_eq!(
        paths.tool_cache_dir(),
        PathBuf::from("/home/user/.chimera/tool-cache")
    );
    assert_eq!(
        paths.pid_file(),
        PathBuf::from("/home/user/.chimera/chimera.pid")
    );
    assert_eq!(
        paths.state_file(),
        PathBuf::from("/home/user/.chimera/state.json")
    );
    assert_eq!(
        paths.job_resources_dir(),
        PathBuf::from("/home/user/.chimera/job-resources")
    );
}

#[test]
fn missing_credentials_file_errors() {
    let tmp = TempDir::new().unwrap();
    let result = load_runner_credentials(tmp.path(), "nonexistent");
    assert!(result.is_err());
}

#[test]
fn public_key_xml_format() {
    let key = crate::testing::test_private_key();
    let xml = public_key_to_xml(&key);

    assert!(xml.starts_with("<RSAKeyValue>"));
    assert!(xml.ends_with("</RSAKeyValue>"));
    assert!(xml.contains("<Modulus>"));
    assert!(xml.contains("<Exponent>"));
}

#[test]
fn jwt_signing_survives_key_roundtrip() {
    use crate::github::auth::create_jwt;
    use rsa::pss::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use sha2::Sha256;

    // Generate key, save params, reconstruct (same as register -> start flow)
    let original_key = crate::testing::test_private_key();
    let params = private_key_to_rsa_params(&original_key).unwrap();
    let reconstructed = rsa_params_to_private_key(&params).unwrap();

    // Sign JWT with reconstructed key
    let token = create_jwt(&reconstructed, "test-client", "https://example.com/token").unwrap();

    // Verify with original public key
    let parts: Vec<&str> = token.split('.').collect();
    let message = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2])
        .unwrap();

    let verifying_key = VerifyingKey::<Sha256>::new(original_key.to_public_key());
    let signature = Signature::try_from(sig_bytes.as_slice()).unwrap();
    verifying_key
        .verify(message.as_bytes(), &signature)
        .expect("JWT signed with roundtripped key should verify with original public key");
}
