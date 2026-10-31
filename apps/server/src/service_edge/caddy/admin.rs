use super::*;
use reqwest::{Client, Method, StatusCode};

#[derive(Clone)]
pub(super) struct Admin {
    client: Client,
    origin: String,
    // One retained worker owns each route; this also serializes Caddy config
    // mutations across all workers and startup reconciliation.
    serial: Arc<tokio::sync::Mutex<()>>,
    pub(super) lifecycle: Arc<tokio::sync::Mutex<()>>,
    provisioned_certificates: Option<Value>,
}
impl Admin {
    pub(super) fn new(config: &CaddyServiceConfig) -> io::Result<Self> {
        let builder = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(2));
        let builder = if let config::CaddyAdmin::Unix { path } = &config.admin {
            #[cfg(unix)]
            {
                builder.unix_socket(path.as_path())
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                return Err(denied());
            }
        } else {
            builder
        };
        Ok(Self {
            client: builder.build().map_err(fault)?,
            origin: config.origin(),
            serial: Arc::new(tokio::sync::Mutex::new(())),
            lifecycle: Arc::new(tokio::sync::Mutex::new(())),
            provisioned_certificates: config.edge_group.as_ref().map(|group|serde_json::json!([{"certificate":group.certificate,"key":group.private_key}])),
        })
    }
    pub(super) async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> io::Result<Option<Value>> {
        let _owner = self.serial.lock().await;
        self.request_owned(method, path, body).await
    }
    async fn request_owned(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> io::Result<Option<Value>> {
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.origin))
            .header("Origin", &self.origin);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(fault)?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(denied());
        }
        let bytes = bounded(response, 256 * 1024).await?;
        if bytes.is_empty() {
            return Ok(Some(Value::Null));
        }
        Ok(Some(serde_json::from_slice(&bytes).map_err(fault)?))
    }
    pub(super) async fn install(&self, node: &str, scheme: &str, route: &Value) -> io::Result<()> {
        self.request(
            Method::POST,
            &format!("/id/{}/handle/0/routes", config::root_id(node, scheme)),
            Some(route),
        )
        .await?
        .ok_or_else(denied)?;
        Ok(())
    }
    pub(super) async fn replace(&self, id: &str, route: &Value) -> io::Result<()> {
        self.request(Method::PATCH, &format!("/id/{id}"), Some(route))
            .await?
            .ok_or_else(denied)?;
        Ok(())
    }
    /// DELETE may have succeeded even if its response timed out. Only a
    /// successful subsequent 404 releases ownership of this exact route ID.
    pub(super) async fn remove(&self, id: &str) -> io::Result<()> {
        let _ = self
            .request(Method::DELETE, &format!("/id/{id}"), None)
            .await?;
        if self
            .request(Method::GET, &format!("/id/{id}"), None)
            .await?
            .is_some()
        {
            return Err(denied());
        }
        Ok(())
    }
    pub(super) async fn reconcile(&self, node: &str, suffix: &str) -> io::Result<()> {
        for scheme in ["http", "https"] {
            let root = self
                .request(
                    Method::GET,
                    &format!("/id/{}", config::root_id(node, scheme)),
                    None,
                )
                .await?
                .ok_or_else(denied)?;
            for id in owned_routes(&root, node, scheme)? {
                self.remove(&id).await?;
            }
        }
        // Nested routes are not included in Caddy's automatic Host discovery.
        // This dedicated loader is the only explicit service certificate owner.
        let hosts = self.certificate_hosts(node, suffix).await?;
        for host in hosts {
            self.certificate_host(node, suffix, &host, false).await?;
        }
        Ok(())
    }
    async fn certificate_hosts(&self, node: &str, suffix: &str) -> io::Result<Vec<String>> {
        let body = self
            .request_owned(
                Method::GET,
                &format!("/id/{}", config::certificate_id(node)),
                None,
            )
            .await?
            .ok_or_else(denied)?;
        let object = body.as_object().ok_or_else(denied)?;
        if object.len() != if self.provisioned_certificates.is_some(){3}else{2}
            || object.get("@id").and_then(Value::as_str)
                != Some(config::certificate_id(node).as_str())
            || object.get("load_files") != self.provisioned_certificates.as_ref()
        {
            return Err(denied());
        }
        let hosts: Vec<String> =
            serde_json::from_value(object.get("automate").ok_or_else(denied)?.clone())
                .map_err(fault)?;
        if hosts.len() > SERVICE_PUBLICATIONS_PER_NODE
            || hosts
                .iter()
                .any(|host| !service_dns(host) || !host.ends_with(&format!(".{suffix}")))
            || hosts
                .iter()
                .enumerate()
                .any(|(i, host)| hosts[..i].contains(host))
        {
            return Err(denied());
        }
        Ok(hosts)
    }
    pub(super) async fn certificate_host(
        &self,
        node: &str,
        suffix: &str,
        host: &str,
        add: bool,
    ) -> io::Result<()> {
        let _owner = self.serial.lock().await;
        let mut hosts = self.certificate_hosts(node, suffix).await?;
        if add {
            if !service_dns(host) || !host.ends_with(&format!(".{suffix}")) {
                return Err(denied());
            }
            if hosts.iter().any(|current| current == host) {
                return Ok(());
            }
            if hosts.len() >= SERVICE_PUBLICATIONS_PER_NODE {
                return Err(denied());
            }
            hosts.push(host.to_owned());
        } else {
            if !hosts.iter().any(|current| current == host) {
                return Ok(());
            }
            hosts.retain(|current| current != host);
        }
        self.request_owned(
            Method::PATCH,
            &format!("/id/{}/automate", config::certificate_id(node)),
            Some(&json!(hosts)),
        )
        .await?
        .ok_or_else(denied)?;
        let actual = self.certificate_hosts(node, suffix).await?;
        if actual.iter().any(|current| current == host) != add {
            return Err(denied());
        }
        Ok(())
    }
}
fn owned_routes(root: &Value, node: &str, scheme: &str) -> io::Result<Vec<String>> {
    let object = root.as_object().ok_or_else(denied)?;
    let handles = object
        .get("handle")
        .and_then(Value::as_array)
        .ok_or_else(denied)?;
    if object.len() != 2
        || object.get("@id").and_then(Value::as_str) != Some(config::root_id(node, scheme).as_str())
        || handles.len() != 1
    {
        return Err(denied());
    }
    let subroute = handles[0].as_object().ok_or_else(denied)?;
    if subroute.len() != 2 || subroute.get("handler").and_then(Value::as_str) != Some("subroute") {
        return Err(denied());
    }
    let routes = subroute
        .get("routes")
        .and_then(Value::as_array)
        .ok_or_else(denied)?;
    if routes.len() > SERVICE_PUBLICATIONS_PER_NODE {
        return Err(denied());
    }
    let prefix = format!("nestlink-pub-{node}-");
    let mut ids = Vec::new();
    for route in routes {
        let id = route
            .get("@id")
            .and_then(Value::as_str)
            .ok_or_else(denied)?;
        if !id.strip_prefix(&prefix).is_some_and(valid_id)
            || ids.iter().any(|current| current == id)
        {
            return Err(denied());
        }
        ids.push(id.to_owned());
    }
    Ok(ids)
}
pub(super) async fn bounded(response: reqwest::Response, limit: usize) -> io::Result<Vec<u8>> {
    use futures_util::StreamExt;
    if response.content_length().is_some_and(|n| n > limit as u64) {
        return Err(denied());
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(bytes) = stream.next().await {
        let bytes = bytes.map_err(fault)?;
        if body
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > limit)
        {
            return Err(denied());
        }
        body.extend_from_slice(&bytes);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reconciliation_refuses_unowned_or_ambiguous_subtrees() -> io::Result<()> {
        let node = uuid::Uuid::new_v4().to_string();
        let id = format!("nestlink-pub-{node}-{}", uuid::Uuid::new_v4());
        let owned = json!({"@id":config::root_id(&node,"http"),"handle":[{"handler":"subroute","routes":[{"@id":id}]}]});
        assert_eq!(owned_routes(&owned, &node, "http")?, vec![id]);
        let mut extra = owned.clone();
        extra["match"] = json!([{"host":["other.example.test"]}]);
        assert!(owned_routes(&extra, &node, "http").is_err());
        let mut unknown = owned.clone();
        unknown["handle"][0]["routes"][0]["@id"] = json!("another-app-route");
        assert!(owned_routes(&unknown, &node, "http").is_err());
        let mut duplicate = owned.clone();
        duplicate["handle"][0]["routes"] = json!([
            owned["handle"][0]["routes"][0],
            owned["handle"][0]["routes"][0]
        ]);
        assert!(owned_routes(&duplicate, &node, "http").is_err());
        assert!(owned_routes(&owned, &node, "https").is_err());
        Ok(())
    }

    struct OwnedCaddy(std::process::Child);
    impl Drop for OwnedCaddy {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }

    #[tokio::test]
    #[ignore = "requires explicit NESTLINK_CADDY_BINARY; exercises the production Rust private loopback Admin client against an actual owned Caddy process"]
    async fn actual_caddy_loopback_admin_route_round_trip()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let directory = tempfile::tempdir()?;
        let reserve = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = reserve.local_addr()?;
        drop(reserve);
        actual_admin_route_round_trip(
            config::CaddyAdmin::LoopbackHttp { address },
            directory.path(),
        )
        .await
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires explicit NESTLINK_CADDY_BINARY; exercises the production Rust Unix Admin client against an actual owned Caddy process"]
    async fn actual_caddy_unix_admin_route_round_trip()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let directory = tempfile::tempdir()?;
        actual_admin_route_round_trip(
            config::CaddyAdmin::Unix {
                path: directory.path().join("admin.sock"),
            },
            directory.path(),
        )
        .await
    }

    async fn actual_admin_route_round_trip(
        transport: config::CaddyAdmin,
        directory: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = CaddyServiceConfig {
            deployment_id: uuid::Uuid::new_v4().to_string(),
            admin: transport,
            public_ips: vec!["1.1.1.1".parse()?],
            dns_json_endpoint: "https://dns.google/resolve".into(),
            edge_group:None,
        };
        config.validate()?;
        let node = uuid::Uuid::new_v4().to_string();
        let root_id = config::root_id(&node, "http");
        let listen = match &config.admin {
            config::CaddyAdmin::LoopbackHttp { address } => address.to_string(),
            config::CaddyAdmin::Unix { path } => {
                format!("unix/{}", path.to_str().ok_or_else(denied)?)
            }
        };
        // This fixture binds only private ephemeral ports and starts no TLS/ACME.
        // Production bootstrap serialization has its own real-binary test.
        let value = json!({
            "admin": {"listen":listen,"enforce_origin":true,"origins":[config.origin()],"config":{"persist":false}},
            "apps":{"http":{"servers":{"fixture":{
                "listen":["127.0.0.1:0"],"automatic_https":{"disable":true},
                "routes":[{"@id":root_id,"handle":[{"handler":"subroute","routes":[]}]}]
            }}}}
        });
        let config_path = directory.join("Caddy.json");
        std::fs::write(&config_path, serde_json::to_vec(&value)?)?;
        let log = std::fs::File::options()
            .create_new(true)
            .write(true)
            .open(directory.join("Caddy.log"))?;
        let mut command = std::process::Command::new(std::env::var("NESTLINK_CADDY_BINARY")?);
        command
            .args(["run", "--config"])
            .arg(&config_path)
            .env("XDG_DATA_HOME", directory.join("data"))
            .env("XDG_CONFIG_HOME", directory.join("config"))
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = OwnedCaddy(command.spawn()?);
        let admin = Admin::new(&config)?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if child.0.try_wait()?.is_some() {
                    return Err(io::Error::other(
                        "owned Caddy exited before Admin readiness",
                    ));
                }
                if admin
                    .request(Method::GET, &format!("/id/{root_id}"), None)
                    .await
                    .is_ok_and(|body| body.is_some())
                {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await??;
        let id = format!("nestlink-pub-{node}-{}", uuid::Uuid::new_v4());
        let route = json!({"@id":id,"handle":[{"handler":"static_response","status_code":200,"body":"before"}]});
        admin.install(&node, "http", &route).await?;
        let replacement = json!({"@id":id,"handle":[{"handler":"static_response","status_code":200,"body":"after"}]});
        admin.replace(&id, &replacement).await?;
        let root = admin
            .request(Method::GET, &format!("/id/{root_id}"), None)
            .await?
            .ok_or_else(denied)?;
        assert_eq!(owned_routes(&root, &node, "http")?, vec![id.clone()]);
        let current = admin
            .request(Method::GET, &format!("/id/{id}"), None)
            .await?
            .ok_or_else(denied)?;
        assert_eq!(current.pointer("/handle/0/body"), Some(&json!("after")));
        admin.remove(&id).await?;
        assert!(
            admin
                .request(Method::GET, &format!("/id/{id}"), None)
                .await?
                .is_none()
        );
        let root = admin
            .request(Method::GET, &format!("/id/{root_id}"), None)
            .await?
            .ok_or_else(denied)?;
        assert!(owned_routes(&root, &node, "http")?.is_empty());
        admin.request(Method::POST, "/stop", None).await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(status) = child.0.try_wait()? {
                    return if status.success() {
                        Ok(())
                    } else {
                        Err(io::Error::other("owned Caddy stop failed"))
                    };
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await??;
        Ok(())
    }
}
