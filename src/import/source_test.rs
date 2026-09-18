use std::io;
use std::path::Path;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rsa::traits::PublicKeyParts;
use serde_json::json;

use crate::config::rsa_params_to_private_key;
use crate::import::test_support::{
    copy_fixture, fixture_credentials, fixture_path, mutate_json, prepend_utf8_bom,
};

use super::*;

const OFFICIAL_SOURCE_FILES: [&str; 3] = [".runner", ".credentials", ".credentials_rsaparams"];

fn assert_category(source: &Path, category: &str) -> String {
    let error = match read_official_registration(source) {
        Ok(_) => panic!("source was unexpectedly accepted"),
        Err(error) => error,
    };
    assert_eq!(error.category(), category);
    format!("{error:#}")
}

fn set_runner_value(source: &Path, key: &str, value: serde_json::Value) {
    mutate_json(source, ".runner", |runner| {
        runner
            .as_object_mut()
            .unwrap()
            .insert(key.to_owned(), value);
    });
}

fn remove_runner_value(source: &Path, key: &str) {
    mutate_json(source, ".runner", |runner| {
        runner.as_object_mut().unwrap().remove(key);
    });
}

fn set_auth_value(source: &Path, key: &str, value: serde_json::Value) {
    mutate_json(source, ".credentials", |credentials| {
        credentials["data"]
            .as_object_mut()
            .unwrap()
            .insert(key.to_owned(), value);
    });
}

#[test]
fn reads_supported_v2_registration_without_changing_identity() {
    let registration = read_official_registration(&fixture_path()).unwrap();

    assert_eq!(registration.credentials.info.agent_id, 42);
    assert_eq!(registration.credentials.info.agent_name, "official-runner");
    assert_eq!(registration.credentials.info.pool_id, 1);
    assert_eq!(
        registration.credentials.info.server_url,
        "https://pipelines.actions.githubusercontent.com/tenant-id"
    );
    assert_eq!(
        registration.credentials.info.server_url_v2,
        "https://broker.actions.githubusercontent.com"
    );
    assert_eq!(
        registration.credentials.info.git_hub_url,
        "https://github.com/example/repository"
    );
    assert_eq!(registration.credentials.info.work_folder, "_work");
    assert!(registration.credentials.info.use_v2_flow);
    assert_eq!(registration.credentials.oauth.scheme, "OAuth");
    assert_eq!(registration.identity.scope, "github.com/example/repository");

    let key = rsa_params_to_private_key(&registration.credentials.rsa_params).unwrap();
    assert_eq!(key.n().to_bytes_be(), [0x0c, 0xa1]);
    assert_eq!(key.e().to_bytes_be(), [0x11]);
}

#[test]
fn reads_registration_with_utf8_bom_prefix_on_each_source_file() {
    let expected = fixture_credentials();

    for name in OFFICIAL_SOURCE_FILES {
        let source = copy_fixture();
        prepend_utf8_bom(source.path(), name);

        let registration = read_official_registration(source.path()).unwrap();

        assert_eq!(registration.credentials, expected, "BOM in {name}");
    }
}

#[test]
fn reads_registration_with_utf8_bom_prefix_on_all_source_files() {
    let expected = fixture_credentials();
    let source = copy_fixture();
    for name in OFFICIAL_SOURCE_FILES {
        prepend_utf8_bom(source.path(), name);
    }

    let registration = read_official_registration(source.path()).unwrap();

    assert_eq!(registration.credentials, expected);
}

#[test]
fn rejects_malformed_json_behind_utf8_bom_prefix() {
    let source = copy_fixture();
    prepend_utf8_bom(source.path(), ".runner");
    std::fs::write(source.path().join(".credentials"), b"\xEF\xBB\xBF{").unwrap();

    assert_category(source.path(), "invalid-source");
}

#[test]
fn rejects_missing_required_file() {
    let source = copy_fixture();
    std::fs::remove_file(source.path().join(".runner")).unwrap();

    assert_category(source.path(), "invalid-source");
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_required_file() {
    let source = copy_fixture();
    let credentials = source.path().join(".credentials");
    std::fs::remove_file(&credentials).unwrap();
    std::os::unix::fs::symlink(fixture_path().join(".credentials"), credentials).unwrap();

    assert_category(source.path(), "invalid-source");
}

#[test]
fn rejects_malformed_json_and_base64_without_echoing_values() {
    let malformed = copy_fixture();
    std::fs::write(malformed.path().join(".runner"), "{").unwrap();
    assert_category(malformed.path(), "invalid-source");

    let invalid_base64 = copy_fixture();
    mutate_json(invalid_base64.path(), ".credentials_rsaparams", |rsa| {
        rsa["d"] = json!("not-base64-SECRET_RSA");
    });
    let diagnostic = assert_category(invalid_base64.path(), "invalid-source");
    assert!(!diagnostic.contains("SECRET_RSA"));
}

#[test]
fn rejects_csharp_pascal_case_rsa_field_names() {
    let source = copy_fixture();
    mutate_json(source.path(), ".credentials_rsaparams", |rsa| {
        let object = rsa.as_object_mut().unwrap();
        let pascal_case: serde_json::Map<String, serde_json::Value> = object
            .iter()
            .map(|(key, value)| {
                let renamed = match key.as_str() {
                    "d" => "D",
                    "dp" => "DP",
                    "dq" => "DQ",
                    "exponent" => "Exponent",
                    "inverseQ" => "InverseQ",
                    "modulus" => "Modulus",
                    "p" => "P",
                    "q" => "Q",
                    other => unreachable!("fixture uses only official RSA keys: {other}"),
                };
                (renamed.to_owned(), value.clone())
            })
            .collect();
        *object = pascal_case;
    });

    assert_category(source.path(), "invalid-source");
}

#[test]
fn rejects_unknown_rsa_fields_alongside_valid_ones() {
    for extra_key in ["D", "e", "SECRET_EXTRA_RSA_FIELD"] {
        let source = copy_fixture();
        mutate_json(source.path(), ".credentials_rsaparams", |rsa| {
            rsa[extra_key] = json!("c2VjcmV0");
        });

        let diagnostic = assert_category(source.path(), "invalid-source");
        assert!(!diagnostic.contains("c2VjcmV0"), "extra key {extra_key}");
    }
}

#[test]
fn rejects_zero_agent_or_pool_id() {
    for field in ["agentId", "poolId"] {
        let source = copy_fixture();
        set_runner_value(source.path(), field, json!(0));

        assert_category(source.path(), "invalid-source");
    }
}

#[test]
fn rejects_non_oauth_and_unknown_auth_metadata_without_echoing_values() {
    let non_oauth = copy_fixture();
    mutate_json(non_oauth.path(), ".credentials", |credentials| {
        credentials["scheme"] = json!("PAT");
    });
    assert_category(non_oauth.path(), "unsupported-registration");

    let unknown_metadata = copy_fixture();
    set_auth_value(
        unknown_metadata.path(),
        "SECRET_AUTH_KEY",
        json!("SECRET_CLIENT_ID"),
    );
    let diagnostic = assert_category(unknown_metadata.path(), "unsupported-registration");
    assert!(!diagnostic.contains("SECRET_AUTH_KEY"));
    assert!(!diagnostic.contains("SECRET_CLIENT_ID"));
}

#[test]
fn accepts_fips_required_and_explicitly_non_fips_registrations() {
    let expected = fixture_credentials();

    for value in ["True", "true", "False", "false"] {
        let source = copy_fixture();
        set_auth_value(source.path(), "requireFipsCryptography", json!(value));

        let registration = read_official_registration(source.path()).unwrap();

        assert_eq!(registration.credentials.oauth, expected.oauth, "value {value}");
    }
}

#[test]
fn rejects_auth_migration_without_echoing_values() {
    let migration_enabled = copy_fixture();
    set_auth_value(
        migration_enabled.path(),
        "enableAuthMigrationByDefault",
        json!("true"),
    );
    assert_category(migration_enabled.path(), "unsupported-registration");

    let migration_url = copy_fixture();
    set_auth_value(
        migration_url.path(),
        "authorizationUrlV2",
        json!("SECRET_AUTH_URL"),
    );
    let diagnostic = assert_category(migration_url.path(), "unsupported-registration");
    assert!(!diagnostic.contains("SECRET_AUTH_URL"));

    let empty_migration_url = copy_fixture();
    set_auth_value(empty_migration_url.path(), "authorizationUrlV2", json!(""));
    assert_category(empty_migration_url.path(), "unsupported-registration");

    for sibling in [".runner_migrated", ".credentials_migrated"] {
        let source = copy_fixture();
        std::fs::write(source.path().join(sibling), []).unwrap();
        assert_category(source.path(), "unsupported-registration");
    }
}

#[test]
fn rejects_ephemeral_jit_legacy_and_ghes() {
    let ephemeral = copy_fixture();
    set_runner_value(ephemeral.path(), "ephemeral", json!(true));
    assert_category(ephemeral.path(), "unsupported-registration");

    let empty_repository = copy_fixture();
    set_runner_value(empty_repository.path(), "gitHubUrl", json!(""));
    assert_category(empty_repository.path(), "unsupported-registration");

    let missing_repository = copy_fixture();
    remove_runner_value(missing_repository.path(), "gitHubUrl");
    assert_category(missing_repository.path(), "unsupported-registration");

    let legacy_flow = copy_fixture();
    set_runner_value(legacy_flow.path(), "useV2Flow", json!(false));
    assert_category(legacy_flow.path(), "unsupported-registration");

    let missing_v2_flow = copy_fixture();
    remove_runner_value(missing_v2_flow.path(), "useV2Flow");
    assert_category(missing_v2_flow.path(), "unsupported-registration");

    let missing_v2_url = copy_fixture();
    remove_runner_value(missing_v2_url.path(), "serverUrlV2");
    assert_category(missing_v2_url.path(), "unsupported-registration");

    let unhosted_server = copy_fixture();
    set_runner_value(unhosted_server.path(), "IsHostedServer", json!(false));
    assert_category(unhosted_server.path(), "unsupported-registration");

    let ghes = copy_fixture();
    set_runner_value(
        ghes.path(),
        "gitHubUrl",
        json!("https://ghe.example/org/repo"),
    );
    assert_category(ghes.path(), "unsupported-registration");

    let organization_scope = copy_fixture();
    set_runner_value(
        organization_scope.path(),
        "gitHubUrl",
        json!("https://github.com/org"),
    );
    assert_category(organization_scope.path(), "unsupported-registration");
}

#[test]
fn rejects_non_https_or_non_actions_endpoints() {
    for (file, field) in [
        (".runner", "serverUrl"),
        (".runner", "serverUrlV2"),
        (".credentials", "authorizationUrl"),
    ] {
        for url in [
            "http://pipelines.actions.githubusercontent.com/tenant-id",
            "https://example.invalid/tenant-id",
        ] {
            let source = copy_fixture();
            if file == ".runner" {
                set_runner_value(source.path(), field, json!(url));
            } else {
                set_auth_value(source.path(), field, json!(url));
            }

            assert_category(source.path(), "unsupported-registration");
        }
    }
}

#[test]
fn rejects_unsafe_endpoint_components_without_echoing_values() {
    for (file, field, value) in [
        (
            ".runner",
            "serverUrl",
            "https://pipelines.actions.githubusercontent.com:443/tenant-id",
        ),
        (
            ".runner",
            "serverUrl",
            "https://SECRET_URL_USER@pipelines.actions.githubusercontent.com/tenant-id",
        ),
        (
            ".runner",
            "serverUrl",
            "https://pipelines.actions.githubusercontent.com/tenant-id?query=1",
        ),
        (
            ".runner",
            "serverUrl",
            "https://pipelines.actions.githubusercontent.com/tenant-id#fragment",
        ),
        (
            ".runner",
            "serverUrl",
            "https://pipelines.actions.githubusercontent.com/",
        ),
        (
            ".runner",
            "serverUrlV2",
            "https://broker.actions.githubusercontent.com:443",
        ),
        (
            ".runner",
            "serverUrlV2",
            "https://user@broker.actions.githubusercontent.com",
        ),
        (
            ".runner",
            "serverUrlV2",
            "https://broker.actions.githubusercontent.com?query=1",
        ),
        (
            ".runner",
            "serverUrlV2",
            "https://broker.actions.githubusercontent.com#fragment",
        ),
        (
            ".credentials",
            "authorizationUrl",
            "https://vstoken.actions.githubusercontent.com:443/tenant-id",
        ),
        (
            ".credentials",
            "authorizationUrl",
            "https://user@vstoken.actions.githubusercontent.com/tenant-id",
        ),
        (
            ".credentials",
            "authorizationUrl",
            "https://vstoken.actions.githubusercontent.com/tenant-id?query=1",
        ),
        (
            ".credentials",
            "authorizationUrl",
            "https://vstoken.actions.githubusercontent.com/tenant-id#fragment",
        ),
        (
            ".credentials",
            "authorizationUrl",
            "https://vstoken.actions.githubusercontent.com/",
        ),
    ] {
        let source = copy_fixture();
        if file == ".runner" {
            set_runner_value(source.path(), field, json!(value));
        } else {
            set_auth_value(source.path(), field, json!(value));
        }

        let diagnostic = assert_category(source.path(), "unsupported-registration");
        assert!(!diagnostic.contains("SECRET_URL_USER"));
    }
}

#[test]
fn rejects_default_port_in_repository_url() {
    let source = copy_fixture();
    set_runner_value(
        source.path(),
        "gitHubUrl",
        json!("https://github.com:443/example/repository"),
    );

    assert_category(source.path(), "unsupported-registration");
}

#[test]
fn rejects_invalid_auth_boolean_strings_without_echoing_values() {
    for field in ["requireFipsCryptography", "enableAuthMigrationByDefault"] {
        let source = copy_fixture();
        set_auth_value(source.path(), field, json!("SECRET_INVALID_BOOL"));

        let diagnostic = assert_category(source.path(), "invalid-source");
        assert!(!diagnostic.contains("SECRET_INVALID_BOOL"));
    }
}

#[test]
fn rejects_invalid_client_id_without_echoing_values() {
    let source = copy_fixture();
    set_auth_value(source.path(), "clientId", json!("SECRET_CLIENT_ID"));

    let diagnostic = assert_category(source.path(), "invalid-source");
    assert!(!diagnostic.contains("SECRET_CLIENT_ID"));
}

#[test]
fn rejects_empty_runner_name_or_work_folder() {
    for field in ["agentName", "workFolder"] {
        let source = copy_fixture();
        set_runner_value(source.path(), field, json!(""));

        assert_category(source.path(), "invalid-source");
    }
}

#[test]
fn lowercases_identity_scope_without_rewriting_repository_url() {
    let source = copy_fixture();
    let repository_url = "https://github.com/Example/Repository";
    set_runner_value(source.path(), "gitHubUrl", json!(repository_url));

    let registration = read_official_registration(source.path()).unwrap();

    assert_eq!(registration.identity.scope, "github.com/example/repository");
    assert_eq!(registration.credentials.info.git_hub_url, repository_url);
}

#[test]
fn accepts_inactive_auth_migration_flag() {
    let expected = fixture_credentials();
    let source = copy_fixture();
    set_auth_value(
        source.path(),
        "enableAuthMigrationByDefault",
        json!("false"),
    );

    let registration = read_official_registration(source.path()).unwrap();

    assert_eq!(registration.credentials.oauth, expected.oauth);
}

#[test]
fn accepts_known_non_auth_runner_fields() {
    let expected = fixture_credentials();
    let source = copy_fixture();
    mutate_json(source.path(), ".runner", |runner| {
        let object = runner.as_object_mut().unwrap();
        object.insert("skipSessionRecover".to_owned(), json!(true));
        object.insert("monitorSocketAddress".to_owned(), json!("/tmp/runner.sock"));
        object.insert("IsHostedServer".to_owned(), json!(true));
        object.insert("useRunnerAdminFlow".to_owned(), json!(true));
    });

    let registration = read_official_registration(source.path()).unwrap();

    assert_eq!(registration.credentials, expected);
}

#[test]
fn allows_same_numeric_agent_id_to_be_scoped_by_repo() {
    let first_source = copy_fixture();
    set_runner_value(
        first_source.path(),
        "gitHubUrl",
        json!("https://github.com/example/one"),
    );
    let first = read_official_registration(first_source.path()).unwrap();

    let second_source = copy_fixture();
    set_runner_value(
        second_source.path(),
        "gitHubUrl",
        json!("https://github.com/example/two"),
    );
    let second = read_official_registration(second_source.path()).unwrap();

    assert_eq!(first.identity.pool_id, second.identity.pool_id);
    assert_eq!(first.identity.agent_id, second.identity.agent_id);
    assert_ne!(first.identity.scope, second.identity.scope);
    assert_eq!(first.identity.scope, "github.com/example/one");
    assert_eq!(second.identity.scope, "github.com/example/two");
}

#[test]
fn preserves_leading_zero_bytes_for_every_rsa_component() {
    let original_key = rsa_params_to_private_key(&fixture_credentials().rsa_params).unwrap();

    for field in ["d", "dp", "dq", "exponent", "inverseQ", "modulus", "p", "q"] {
        let source = copy_fixture();
        let path = source.path().join(".credentials_rsaparams");
        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let encoded = document[field].as_str().unwrap();
        let mut expected_bytes = BASE64.decode(encoded).unwrap();
        expected_bytes.insert(0, 0);
        document[field] = json!(BASE64.encode(&expected_bytes));
        std::fs::write(&path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();

        let registration = read_official_registration(source.path()).unwrap();
        let imported = match field {
            "d" => &registration.credentials.rsa_params.d,
            "dp" => &registration.credentials.rsa_params.dp,
            "dq" => &registration.credentials.rsa_params.dq,
            "exponent" => &registration.credentials.rsa_params.exponent,
            "inverseQ" => &registration.credentials.rsa_params.inverse_q,
            "modulus" => &registration.credentials.rsa_params.modulus,
            "p" => &registration.credentials.rsa_params.p,
            "q" => &registration.credentials.rsa_params.q,
            _ => unreachable!("table contains only the eight RSA fields"),
        };
        let imported_bytes = BASE64.decode(imported).unwrap();
        assert!(
            imported_bytes == expected_bytes,
            "RSA component width changed for {field}"
        );

        let imported_key = rsa_params_to_private_key(&registration.credentials.rsa_params).unwrap();
        assert!(
            imported_key.n() == original_key.n() && imported_key.e() == original_key.e(),
            "RSA public key changed for {field}"
        );
    }
}

#[test]
fn rejects_duplicate_oauth_metadata_keys_from_raw_json() {
    for duplicate_entries in [
        concat!(
            "\"clientId\":\"00000000-0000-4000-8000-000000000042\",",
            "\"clientId\":\"00000000-0000-4000-8000-000000000043\","
        ),
        concat!(
            "\"authorizationUrl\":\"https://vstoken.actions.githubusercontent.com/tenant-id\",",
            "\"authorizationUrl\":\"https://vstoken.actions.githubusercontent.com/other\","
        ),
        concat!(
            "\"requireFipsCryptography\":\"False\",",
            "\"requireFipsCryptography\":\"True\","
        ),
        concat!(
            "\"enableAuthMigrationByDefault\":\"false\",",
            "\"enableAuthMigrationByDefault\":\"true\","
        ),
    ] {
        let source = copy_fixture();
        let raw = format!(
            concat!(
                "{{\"scheme\":\"OAuth\",\"data\":{{{}",
                "\"clientId\":\"00000000-0000-4000-8000-000000000042\",",
                "\"authorizationUrl\":\"https://vstoken.actions.githubusercontent.com/tenant-id\"}}}}"
            ),
            duplicate_entries
        );
        std::fs::write(source.path().join(".credentials"), raw).unwrap();

        let diagnostic = assert_category(source.path(), "invalid-source");

        assert!(!diagnostic.contains("00000000-0000-4000-8000-000000000043"));
        assert!(!diagnostic.contains("/other"));
    }
}

#[test]
fn rejects_percent_encoded_repository_scope_aliases() {
    for repository_url in [
        "https://github.com/%65xample/repository",
        "https://github.com/example/repo%73itory",
        "https://github.com/example%2Frepository/alias",
        "https://github.com/example/%2e%2e",
        "https://github.com/example/%2e/repository",
        "https://github.com/other/%2e%2e/example/repository",
    ] {
        let source = copy_fixture();
        set_runner_value(source.path(), "gitHubUrl", json!(repository_url));

        assert_category(source.path(), "unsupported-registration");
    }
}

#[test]
fn migration_marker_metadata_classification_fails_closed() {
    let marker = Path::new("marker-name");

    assert!(migration_marker_exists_with(marker, |_| Ok(())).unwrap());
    assert!(
        !migration_marker_exists_with(marker, |_| Err(io::Error::from(io::ErrorKind::NotFound)))
            .unwrap()
    );
    let error = migration_marker_exists_with(marker, |_| {
        Err(io::Error::other("SECRET_MARKER_METADATA_FAILURE"))
    })
    .unwrap_err();
    let diagnostic = error.to_string();

    assert_eq!(error.category(), "invalid-source");
    assert!(!diagnostic.contains("SECRET_MARKER_METADATA_FAILURE"));
}
