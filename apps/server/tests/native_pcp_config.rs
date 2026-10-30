//! Exercise the actual private configuration loader used by `server serve`.
use nestlink_platform_security::create_private;
use nestlink_server::config::ServerConfig;

#[test]
fn legacy_configuration_denies_pcp_and_explicit_deployment_consent_survives_reload()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let legacy = r#"
deployment_id = "ea96f315-6471-4859-a1dc-cb06acb3a021"
listen = "127.0.0.1:8080"
database = "control.sqlite3"
vault_key_file = "vault.key"
permit_key_file = "permit.key"
management_origin = "https://control.example.test"
"#;
    let legacy_path = directory.path().join("legacy.toml");
    create_private(&legacy_path, legacy.as_bytes())?;
    let mut config = ServerConfig::load(&legacy_path)?;
    assert!(!config.allow_pcp_mapping);
    assert_eq!(config.database, directory.path().join("control.sqlite3"));
    config.allow_pcp_mapping = true;
    let enabled_path = directory.path().join("enabled.toml");
    create_private(&enabled_path, toml::to_string(&config)?.as_bytes())?;
    assert!(ServerConfig::load(&enabled_path)?.allow_pcp_mapping);
    config.allow_pcp_mapping = false;
    let disabled_path = directory.path().join("disabled.toml");
    create_private(&disabled_path, toml::to_string(&config)?.as_bytes())?;
    assert!(!ServerConfig::load(&disabled_path)?.allow_pcp_mapping);
    Ok(())
}
