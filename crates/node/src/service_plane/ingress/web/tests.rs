use super::*;
use tokio::io::AsyncWriteExt;
type Result = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;
fn auth() -> WebAuth {
    WebAuth {
        hostname: "app.svc.example.test".into(),
        scheme: "https",
        token: "local-only-token".into(),
    }
}
fn head(extra: &str, body: &str) -> Vec<u8> {
    format!("POST /upload?keep=1 HTTP/1.1\r\nHost: app.svc.example.test\r\nX-NestLink-Token: local-only-token\r\nX-NestLink-Peer: 198.51.100.7:40123\r\nX-NestLink-Scheme: https\r\nX-NestLink-SNI: app.svc.example.test\r\n{extra}\r\n{body}").into_bytes()
}
#[test]
fn authenticated_proxy_hop_strips_credentials_and_replaces_forged_forwarding_headers() -> Result {
    let input = head(
        "Content-Length: 4\r\nX-Forwarded-For: 10.0.0.1\r\nForwarded: for=10.0.0.1\r\nX-NestLink-Arbitrary: hidden\r\n",
        "body",
    );
    let (peer, forwarded) = authenticate_head(&input, &auth())?;
    assert_eq!(peer, "198.51.100.7:40123".parse()?);
    let text = String::from_utf8(forwarded)?;
    assert!(text.ends_with("\r\n\r\nbody"));
    assert!(text.contains("X-Forwarded-For: 198.51.100.7\r\n"));
    assert!(text.contains("X-Forwarded-Proto: https\r\n"));
    assert!(text.contains("Connection: close\r\n"));
    assert!(!text.to_ascii_lowercase().contains("x-nestlink-"));
    assert!(!text.contains("local-only-token") && !text.contains("10.0.0.1"));
    Ok(())
}
#[test]
fn private_hop_rejects_host_sni_peer_credential_and_http_framing_ambiguity() -> Result {
    let valid = String::from_utf8(head("Content-Length: 0\r\n", ""))?;
    let changes = [
        valid.replace("Host: app.svc.example.test", "Host: wrong.svc.example.test"),
        valid.replace(
            "X-NestLink-SNI: app.svc.example.test",
            "X-NestLink-SNI: wrong.svc.example.test",
        ),
        valid.replace(
            "X-NestLink-Token: local-only-token",
            "X-NestLink-Token: attacker",
        ),
        valid.replace(
            "X-NestLink-Peer: 198.51.100.7:40123",
            "X-NestLink-Peer: 198.51.100.7:0",
        ),
        valid.replace("X-NestLink-Scheme: https", "X-NestLink-Scheme: http"),
        valid.replace(
            "Content-Length: 0",
            "Content-Length: 0\r\nContent-Length: 0",
        ),
        valid.replace(
            "Content-Length: 0",
            "Content-Length: 0\r\nTransfer-Encoding: chunked",
        ),
        valid.replace("Content-Length: 0", "Content-Length: 18446744073709551616"),
        valid.replace("Content-Length: 0", "Transfer-Encoding: gzip, chunked"),
        valid.replace(
            "Host: app.svc.example.test",
            "Host: app.svc.example.test\r\nHost: app.svc.example.test",
        ),
        valid.replace(
            "X-NestLink-Token: local-only-token",
            "X-NestLink-Token: local-only-token\r\nX-NestLink-Token: local-only-token",
        ),
        valid.replace("POST /upload?keep=1", "POST http://attacker.test/upload"),
        valid.replace("POST /upload?keep=1", "CONNECT attacker.test:443"),
    ];
    for changed in changes {
        assert!(authenticate_head(changed.as_bytes(), &auth()).is_err());
    }
    Ok(())
}
#[test]
fn websocket_upgrade_is_preserved_but_private_proxy_auth_is_not_forwarded() -> Result {
    let bytes = head(
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: local-test\r\n",
        "",
    );
    let (_, forwarded) = authenticate_head(&bytes, &auth())?;
    let text = String::from_utf8(forwarded)?;
    assert!(text.contains("Upgrade: websocket\r\n"));
    assert!(text.contains("Connection: upgrade\r\n"));
    assert!(text.contains("Sec-WebSocket-Key: local-test\r\n"));
    assert!(!text.contains("local-only-token"));
    Ok(())
}
#[tokio::test]
async fn real_private_tcp_parser_preserves_streaming_body_bytes_after_the_head() -> Result {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let input = head("Content-Length: 8\r\n", "body");
    let send = input.clone();
    let sender = tokio::spawn(async move {
        let mut socket = TcpStream::connect(address).await?;
        socket.write_all(&send).await?;
        tokio::time::sleep(Duration::from_millis(10)).await;
        socket.write_all(b"tail").await?;
        socket.shutdown().await
    });
    let (mut socket, _) = listener.accept().await?;
    let received = tokio::time::timeout(HEADER_TIME, read_head(&mut socket)).await??;
    let (_, prefix) = authenticate_head(&received, &auth())?;
    let mut stream = PrefixedVisitor {
        socket,
        prefix,
        offset: 0,
    };
    let mut all = Vec::new();
    stream.read_to_end(&mut all).await?;
    assert!(all.ends_with(b"\r\n\r\nbodytail"));
    sender.await??;
    Ok(())
}
