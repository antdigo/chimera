#[path = "qualification/mod.rs"]
mod qualification;

#[cfg(feature = "acceptance-tests")]
#[tokio::test]
#[ignore = "native Debian exclusive qualification; E0 always reports blocked"]
async fn native_sandboxed_release_qualification() {
    use qualification::catalog::Reason;
    let outcome = async {
        let path = std::env::var_os("CHIMERA_QUALIFICATION_CONFIG").ok_or(Reason::InvalidConfig)?;
        let config = qualification::read_native_config(std::path::Path::new(&path))?;
        qualification::run_native(config).await
    }
    .await;
    match outcome {
        Ok(report) => {
            assert!(!report.activation_available);
            assert!(
                qualification::report::qualifies(&report),
                "BackendUnavailable"
            );
        }
        Err(reason) => panic!("{reason:?}"),
    }
}
