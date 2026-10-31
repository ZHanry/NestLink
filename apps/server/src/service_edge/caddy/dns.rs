use super::*;
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Deserialize)]
struct Answer {
    name: String,
    #[serde(rename = "type")]
    kind: u16,
    data: String,
    #[serde(rename = "TTL")]
    ttl: u32,
}
#[derive(Deserialize)]
struct Response {
    #[serde(rename = "Status")]
    status: u16,
    #[serde(rename = "TC", default)]
    truncated: bool,
    #[serde(rename = "Question")]
    question: Vec<Question>,
    #[serde(rename = "Answer", default)]
    answers: Vec<Answer>,
}
#[derive(Deserialize)]
struct Question {
    name: String,
    #[serde(rename = "type")]
    kind: u16,
}
fn same_name(answer: &str, expected: &str) -> bool {
    answer
        .strip_suffix('.')
        .unwrap_or(answer)
        .eq_ignore_ascii_case(expected)
}
fn parse(bytes: &[u8], name: &str, kind: u16) -> io::Result<Vec<Answer>> {
    let response: Response = serde_json::from_slice(bytes).map_err(fault)?;
    if response.status != 0
        || response.truncated
        || response.question.len() != 1
        || !same_name(&response.question[0].name, name)
        || response.question[0].kind != kind
        || response.answers.len() > 16
        || response
            .answers
            .iter()
            .any(|a| a.kind != kind || !same_name(&a.name, name) || a.ttl == 0)
    {
        return Err(denied());
    }
    Ok(response.answers)
}
async fn query(config: &CaddyServiceConfig, name: &str, kind: u16) -> io::Result<Vec<Answer>> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(fault)?;
    let response = client
        .get(&config.dns_json_endpoint)
        .header("Accept", "application/dns-json")
        .query(&[("name", name), ("type", &kind.to_string())])
        .send()
        .await
        .map_err(fault)?;
    if !response.status().is_success() {
        return Err(denied());
    }
    parse(&admin::bounded(response, 16 * 1024).await?, name, kind)
}
pub(super) async fn ownership(config: &CaddyServiceConfig, entry: &Entry) -> io::Result<()> {
    let txt_name = format!("_nestlink-service.{}", entry.hostname);
    let (a, aaaa, txt) = tokio::try_join!(
        query(config, &entry.hostname, 1),
        query(config, &entry.hostname, 28),
        query(config, &txt_name, 16)
    )?;
    let mut addresses = BTreeSet::new();
    for record in a {
        let ip: std::net::Ipv4Addr = record.data.parse().map_err(fault)?;
        if !addresses.insert(IpAddr::V4(ip)) {
            return Err(denied());
        }
    }
    for record in aaaa {
        let ip: std::net::Ipv6Addr = record.data.parse().map_err(fault)?;
        if !addresses.insert(IpAddr::V6(ip)) {
            return Err(denied());
        }
    }
    let expected: BTreeSet<_> = config.public_ips.iter().copied().collect();
    let proof = if let Some(binding)=&entry.edge_group {
        use base64::{Engine,engine::general_purpose::URL_SAFE_NO_PAD};
        format!("\"nestlink-group-v1:{}:{}:{}:{}:{}\"",config.deployment_id,binding.group.group_id,binding.group.revision,entry.service_id,URL_SAFE_NO_PAD.encode(binding.aggregate_sha256))
    } else { format!(
        "\"nestlink-v1:{}:{}:{}\"",
        config.deployment_id, entry.node_id, entry.service_id
    ) };
    if addresses != expected || txt.len() != 1 || txt[0].data != proof {
        return Err(denied());
    }
    Ok(())
}
/// Every advertised address must serve this exact route. A fresh client uses
/// normal root/SAN/validity verification with the exact host as SNI and never
/// trusts resolver changes, redirects, proxy environment or a cached TLS pool.
pub(super) async fn probe(config: &CaddyServiceConfig, entry: &Entry) -> io::Result<()> {
    // The group frontdoor must be qualified separately. Per-edge readiness
    // reaches this member directly with the same original hostname and normal
    // TLS verification, rather than accepting another edge's probe token.
    let addresses=if let Some(binding)=&entry.edge_group {vec![binding.group.member(&entry.node_id).map_err(fault)?.ingress_ip]}else{config.public_ips.clone()};
    let probes = addresses.iter().map(|ip| async move {
        let port = if entry.scheme == "https" { 443 } else { 80 };
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(3))
            .pool_max_idle_per_host(0)
            .resolve(&entry.hostname, (*ip, port).into())
            .build()
            .map_err(fault)?;
        let response = client
            .get(format!(
                "{}://{}{}",
                entry.scheme, entry.hostname, entry.probe_path
            ))
            .send()
            .await
            .map_err(fault)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(denied());
        }
        if admin::bounded(response, 128).await? != entry.probe_response.as_bytes() {
            return Err(denied());
        }
        Ok(())
    });
    for result in futures_util::future::join_all(probes).await {
        result?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_response_must_have_exact_question_and_no_aliases() -> io::Result<()> {
        let good=br#"{"Status":0,"TC":false,"Question":[{"name":"app.svc.example.test.","type":1}],"Answer":[{"name":"app.svc.example.test.","type":1,"TTL":60,"data":"1.1.1.1"}]}"#;
        assert_eq!(parse(good, "app.svc.example.test", 1)?.len(), 1);
        for bad in [br#"{"Status":0,"Question":[{"name":"attacker.test.","type":1}]}"#.as_slice(),br#"{"Status":0,"Question":[{"name":"app.svc.example.test.","type":1}],"Answer":[{"name":"app.svc.example.test.","type":5,"TTL":60,"data":"attacker.test."}]}"#.as_slice(),br#"{"Status":3,"Question":[{"name":"app.svc.example.test.","type":1}]}"#.as_slice()] {
            assert!(parse(bad,"app.svc.example.test",1).is_err());
        }
        Ok(())
    }
}
