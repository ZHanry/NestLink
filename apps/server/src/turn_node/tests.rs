use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use nestlink_platform_security::create_private;
use rustls::{ClientConfig, ClientConnection, Connection, RootCertStore, ServerConnection};
use std::io::{Cursor, Read, Write};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct TlsFiles {
    directory: tempfile::TempDir,
    certificate: PathBuf,
    private_key: PathBuf,
    certificate_pem: String,
    certificate_der: CertificateDer<'static>,
}

fn pem(label: &str, der: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        STANDARD.encode(der)
    )
}

fn tls_files() -> TestResult<TlsFiles> {
    let directory = tempfile::tempdir()?;
    let certificate = directory.path().join("certificate.pem");
    let private_key = directory.path().join("private-key.pem");
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
    let certificate_der = certified.cert.der().clone();
    let certificate_pem = pem("CERTIFICATE", certificate_der.as_ref());
    fs::write(&certificate, &certificate_pem)?;
    create_private(
        &private_key,
        pem("PRIVATE KEY", &certified.signing_key.serialize_der()).as_bytes(),
    )?;
    Ok(TlsFiles {
        directory,
        certificate,
        private_key,
        certificate_pem,
        certificate_der,
    })
}

fn transfer(sender: &mut Connection, receiver: &mut Connection) -> TestResult {
    let mut bytes = Vec::new();
    while sender.wants_write() {
        sender.write_tls(&mut bytes)?;
    }
    let mut input = Cursor::new(bytes);
    while input.position() < input.get_ref().len() as u64 {
        receiver.read_tls(&mut input)?;
        receiver.process_new_packets()?;
    }
    Ok(())
}

#[test]
fn loaded_pem_pair_completes_authenticated_tls_and_transfers_data() -> TestResult {
    let files = tls_files()?;
    let config = load_tls_server_config(&files.certificate, &files.private_key)?;
    let mut roots = RootCertStore::empty();
    roots.add(files.certificate_der.clone())?;
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut client: Connection =
        ClientConnection::new(Arc::new(client_config), "localhost".try_into()?)?.into();
    let mut server: Connection = ServerConnection::new(Arc::new(config))?.into();
    for _ in 0..16 {
        transfer(&mut client, &mut server)?;
        transfer(&mut server, &mut client)?;
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
    }
    assert!(!client.is_handshaking() && !server.is_handshaking());
    client.writer().write_all(b"NestLink TURN TLS")?;
    transfer(&mut client, &mut server)?;
    let mut received = [0; 17];
    server.reader().read_exact(&mut received)?;
    assert_eq!(&received, b"NestLink TURN TLS");
    Ok(())
}

#[test]
fn missing_and_malformed_certificates_are_rejected() -> TestResult {
    let files = tls_files()?;
    for contents in [
        "",
        "no PEM objects",
        "-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nAA==\n",
    ] {
        fs::write(&files.certificate, contents)?;
        assert!(load_tls_server_config(&files.certificate, &files.private_key).is_err());
    }
    Ok(())
}

#[test]
fn excessive_certificate_chain_and_file_size_are_rejected() -> TestResult {
    let files = tls_files()?;
    fs::write(
        &files.certificate,
        files.certificate_pem.repeat(MAX_CERTIFICATES + 1),
    )?;
    assert!(load_tls_server_config(&files.certificate, &files.private_key).is_err());
    fs::write(
        &files.certificate,
        vec![b' '; MAX_CERTIFICATE_CHAIN_BYTES + 1],
    )?;
    assert!(load_tls_server_config(&files.certificate, &files.private_key).is_err());
    Ok(())
}

#[test]
fn missing_malformed_and_mismatched_private_keys_are_rejected() -> TestResult {
    let files = tls_files()?;
    let another = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
    for (index, contents) in [
        String::new(),
        files.certificate_pem.clone(),
        "-----BEGIN PRIVATE KEY-----\n%%%\n-----END PRIVATE KEY-----\n".to_owned(),
        pem("PRIVATE KEY", &another.signing_key.serialize_der()),
    ]
    .into_iter()
    .enumerate()
    {
        let key = files
            .directory
            .path()
            .join(format!("invalid-key-{index}.pem"));
        create_private(&key, contents.as_bytes())?;
        assert!(load_tls_server_config(&files.certificate, &key).is_err());
    }
    Ok(())
}
