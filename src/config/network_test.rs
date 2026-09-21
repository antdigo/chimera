use super::IpCidr;

#[test]
fn cidr_is_strict_and_family_aware() {
    let cidr: IpCidr = "10.2.0.0/16".parse().unwrap();
    assert!(cidr.contains("10.2.9.3".parse().unwrap()));
    assert!(!cidr.contains("10.3.9.3".parse().unwrap()));
    assert!(!cidr.contains("::ffff:10.2.9.3".parse().unwrap()));
    assert_eq!(cidr.to_string(), "10.2.0.0/16");
    for bad in [
        "10.2.1.1/16",
        "::ffff:127.0.0.1/128",
        "0.0.0.0/33",
        "::/129",
        "10.0.0.0/8\nIPAddressAllow=any",
        " 10.0.0.0/8",
    ] {
        assert!(bad.parse::<IpCidr>().is_err(), "accepted {bad:?}");
    }
}
