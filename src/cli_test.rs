use std::path::Path;

use clap::Parser;

use super::{Cli, Command};

#[test]
fn parses_import_official_arguments() {
    let cli = Cli::try_parse_from([
        "chimera",
        "import-official",
        "--source",
        "/official",
        "--name",
        "local.runner-1",
        "--root",
        "/chimera",
        "--dry-run",
    ])
    .unwrap();

    assert!(matches!(
        cli.command,
        Command::ImportOfficial {
            source,
            name,
            root,
            dry_run
        } if source == Path::new("/official")
            && name == "local.runner-1"
            && root == Path::new("/chimera")
            && dry_run
    ));
}

#[test]
fn parses_doctor_json_root() {
    let cli = Cli::try_parse_from(["chimera", "doctor", "--root", "/chimera", "--json"]).unwrap();
    assert!(
        matches!(cli.command, Command::Doctor { root, json: true } if root == Path::new("/chimera"))
    );
}

#[test]
fn install_policy_requires_render_and_rejects_apply() {
    assert!(Cli::try_parse_from(["chimera", "install-policy", "--root", "/chimera"]).is_err());
    assert!(
        Cli::try_parse_from([
            "chimera",
            "install-policy",
            "--render",
            "--apply",
            "--root",
            "/chimera"
        ])
        .is_err()
    );
    let cli = Cli::try_parse_from([
        "chimera",
        "install-policy",
        "--render",
        "--root",
        "/chimera",
    ])
    .unwrap();
    assert!(
        matches!(cli.command, Command::InstallPolicy { root, render: true } if root == Path::new("/chimera"))
    );
}
