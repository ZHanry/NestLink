use nestlink_protocol::api::NativeDiscoveryConfig;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn deployment_stun_rejects_local_special_scoped_duplicate_and_unbounded_addresses() -> Result {
    let mut config = NativeDiscoveryConfig {
        deployment_id: "1813a7c3-13d0-4a86-9b9e-6ad2b7c92f0b".into(),
        stun_servers: vec![
            "11.0.0.1:3478".parse()?,
            "[2606:4700:4700::1111]:3478".parse()?,
        ],
    };
    config.validate()?;
    assert_eq!(
        config.webrtc_stun_urls()?,
        vec!["stun:11.0.0.1:3478", "stun:[2606:4700:4700::1111]:3478"]
    );
    for invalid in [
        "0.0.0.0:3478",
        "127.0.0.1:3478",
        "10.1.2.3:3478",
        "169.254.169.254:3478",
        "192.0.2.1:3478",
        "224.0.0.1:3478",
        "11.0.0.1:0",
        "[::1]:3478",
        "[fd01::1]:3478",
        "[fe80::1]:3478",
        "[::ffff:11.0.0.1]:3478",
        "[2001:db8::1]:3478",
        "[2606:4700::1%2]:3478",
    ] {
        config.stun_servers = vec![invalid.parse()?];
        assert!(config.validate().is_err(), "accepted {invalid}");
        assert!(
            config.webrtc_stun_urls().is_err(),
            "WebRTC accepted {invalid}"
        );
    }
    let mut flowing = std::net::SocketAddrV6::new("2606:4700::1".parse()?, 3478, 7, 0);
    config.stun_servers = vec![flowing.into()];
    assert!(config.validate().is_err());
    flowing.set_flowinfo(0);
    config.stun_servers = vec![flowing.into(); 2];
    assert!(config.validate().is_err());
    config.stun_servers = (1..=5)
        .map(|port| std::net::SocketAddr::new(flowing.ip().to_owned().into(), port))
        .collect();
    assert!(config.validate().is_err());
    config.stun_servers.clear();
    config.validate()?;
    config.deployment_id = "untrusted-deployment".into();
    assert!(config.validate().is_err());
    Ok(())
}
