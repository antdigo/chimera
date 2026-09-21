use super::StorageBytes;

#[test]
fn storage_limit_has_exact_units_and_checked_arithmetic() {
    assert_eq!(
        "64GiB".parse::<StorageBytes>().unwrap().get(),
        68_719_476_736
    );
    assert_eq!("1B".parse::<StorageBytes>().unwrap().get(), 1);
    for bad in [
        "0",
        "0B",
        "1GB",
        "1.5GiB",
        "max",
        "-1B",
        "18446744073709551615TiB",
    ] {
        assert!(bad.parse::<StorageBytes>().is_err(), "accepted {bad:?}");
    }
}
