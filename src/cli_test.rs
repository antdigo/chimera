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
