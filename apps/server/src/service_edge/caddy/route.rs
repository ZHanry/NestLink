use super::*;

fn route(entry: &Entry, enabled: bool) -> Value {
    // Caddy reloads when any route changes. Existing upgraded streams may live
    // through that reload for the maximum consent lifetime; Node authority
    // checks still close revoked or expired flows independently and promptly.
    let proxy = if enabled {
        json!({"handler":"reverse_proxy","upstreams":[{"dial":entry.private_address.to_string()}],
            "transport":{"protocol":"http","versions":["1.1"],"keep_alive":{"enabled":false}},
            "headers":{"request":{"set":{
                "X-NestLink-Token":[entry.private_token],"X-NestLink-Peer":["{http.request.remote}"],
                "X-NestLink-Scheme":["{http.request.scheme}"],"X-NestLink-SNI":["{http.request.tls.server_name}"]
            }}},"flush_interval":-1,"stream_close_delay":"1h"})
    } else {
        json!({"handler":"static_response","status_code":503})
    };
    json!({"@id":entry.id,"match":[{"host":[entry.hostname]}],"terminal":true,
    "handle":[{"handler":"subroute","routes":[
        {"match":[{"path":[entry.probe_path]}],"handle":[{"handler":"static_response","status_code":200,"body":entry.probe_response,"headers":{"Cache-Control":["no-store"]}}],"terminal":true},
        {"handle":[proxy],"terminal":true}
    ]}]})
}
pub(super) async fn run(config: &CaddyServiceConfig, admin: &admin::Admin, entry: &Entry) {
    let ready = activate(config, admin, entry).await;
    if ready.is_ok() && !entry.stopped() {
        entry.state.send_replace(State::Ready);
        let mut stop = entry.stop.subscribe();
        let mut tick = tokio::time::interval(Duration::from_millis(25));
        let mut next_check = Instant::now() + Duration::from_secs(5);
        loop {
            if entry.stopped() {
                break;
            }
            tokio::select! {biased;
                _=stop.changed()=>{},
                _=entry.connection.closed()=>break,
                _=tick.tick()=>{
                    if Instant::now()>=next_check {
                        if dns::ownership(config,entry).await.is_err() || dns::probe(config,entry).await.is_err(){break;}
                        next_check=Instant::now()+Duration::from_secs(5);
                    }
                },
            }
        }
    }
    // The listener observes Removing and closes immediately. Its random private
    // token cannot authorize a future endpoint even while Admin is unavailable.
    entry.state.send_replace(State::Removing);
    cleanup(admin, entry).await;
}
pub(super) async fn cleanup(admin: &admin::Admin, entry: &Entry) {
    let _lifecycle = admin.lifecycle.clone().lock_owned().await;
    loop {
        if admin.remove(&entry.id).await.is_ok()
            && (entry.scheme != "https"
                || admin
                    .certificate_host(
                        &entry.node_id,
                        &entry.service_suffix,
                        &entry.hostname,
                        false,
                    )
                    .await
                    .is_ok())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    entry.state.send_replace(State::Removed);
}
async fn activate(
    config: &CaddyServiceConfig,
    admin: &admin::Admin,
    entry: &Entry,
) -> io::Result<()> {
    // Caddy reload cancels certificate jobs from the previous configuration.
    // Serialize whole provision/remove lifecycles through actual readiness.
    let lock = admin.lifecycle.clone().lock_owned();
    tokio::pin!(lock);
    let mut tick = tokio::time::interval(Duration::from_millis(25));
    let _lifecycle = loop {
        if entry.stopped() {
            return Err(denied());
        }
        tokio::select! {biased;guard=&mut lock=>break guard,_=tick.tick()=>{}}
    };
    if entry.stopped() {
        return Err(denied());
    }
    dns::ownership(config, entry).await?;
    if entry.stopped() {
        return Err(denied());
    }
    // Public backend forwarding stays unavailable while ACME obtains a normal
    // certificate. Only the unpredictable readiness path is served locally.
    admin
        .install(&entry.node_id, entry.scheme, &route(entry, false))
        .await?;
    if entry.scheme == "https" {
        admin
            .certificate_host(&entry.node_id, &entry.service_suffix, &entry.hostname, true)
            .await?;
    }
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if entry.stopped() || Instant::now() >= deadline {
            return Err(denied());
        }
        if dns::probe(config, entry).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    dns::ownership(config, entry).await?;
    if entry.stopped() {
        return Err(denied());
    }
    admin.replace(&entry.id, &route(entry, true)).await?;
    if entry.stopped() {
        return Err(denied());
    }
    Ok(())
}
