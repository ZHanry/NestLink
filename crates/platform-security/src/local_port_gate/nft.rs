use super::*;
use serde_json::json;

fn address(plan: &GatePlan) -> Value {
    json!({"match":{"op":"==","left":{"payload":{"protocol":if plan.endpoint.is_ipv4(){"ip"}else{"ip6"},"field":"daddr"}},"right":plan.endpoint.ip().to_string()}})
}
fn selected(plan: &GatePlan) -> Vec<Value> {
    vec![
        address(plan),
        json!({"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":plan.transport.number()}}),
        json!({"match":{"op":"==","left":{"payload":{"protocol":plan.transport.name(),"field":"dport"}},"right":plan.endpoint.port()}}),
    ]
}
fn rule(plan: &GatePlan, chain: &str, kind: &str) -> Value {
    let mut expr = selected(plan);
    match kind {
        "allow" => {
            expr.push(json!({"match":{"op":"==","left":{"meta":{"key":"skuid"}},"right":plan.process.uid}}));
            expr.push(json!({"return":null}));
        }
        "outside" => {
            expr.push(json!({"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":"lo"}}));
            expr.push(json!({"drop":null}));
        }
        _ => expr.push(json!({"drop":null})),
    }
    json!({"family":"inet","table":plan.table(),"chain":chain,"expr":expr,"comment":format!("{}:{kind}",plan.marker())})
}
fn chain(plan: &GatePlan, name: &str) -> Value {
    json!({"family":"inet","table":plan.table(),"name":name,"type":"filter","hook":name,"prio":0,"policy":"accept"})
}
async fn mutate(store: &Store, operations: Vec<Value>) -> io::Result<()> {
    let path = store.directory.join("local-port-transaction.json");
    if replace_private_metadata(&path, &serde_json::to_vec(&json!({"nftables":operations}))?)?
        != MetadataCommit::Durable
    {
        return Err(invalid("gate transaction intent persistence unconfirmed"));
    }
    command::run(
        store,
        &[
            "--json".into(),
            "--file".into(),
            path.to_string_lossy().into_owned(),
        ],
    )
    .await?;
    Ok(())
}
pub(super) async fn install(store: &Store, plan: &GatePlan) -> io::Result<()> {
    mutate(
        store,
        vec![
            json!({"add":{"table":{"family":"inet","name":plan.table(),"comment":plan.marker()}}}),
            json!({"add":{"chain":chain(plan,"output")}}),
            json!({"add":{"chain":chain(plan,"input")}}),
            json!({"add":{"rule":rule(plan,"output","allow")}}),
            json!({"add":{"rule":rule(plan,"output","drop")}}),
            json!({"add":{"rule":rule(plan,"input","outside")}}),
        ],
    )
    .await
}
pub(super) async fn deny(store: &Store, plan: &GatePlan) -> io::Result<()> {
    // One kernel transaction. There is no interval with an empty live chain.
    mutate(
        store,
        vec![
            json!({"flush":{"chain":{"family":"inet","table":plan.table(),"name":"output"}}}),
            json!({"add":{"rule":rule(plan,"output","drop")}}),
        ],
    )
    .await
}
pub(super) async fn remove(store: &Store, plan: &GatePlan) -> io::Result<()> {
    mutate(
        store,
        vec![json!({"delete":{"table":{"family":"inet","name":plan.table()}}})],
    )
    .await
}
fn normalize(mut item: Value) -> Value {
    if let Some(object) = item.as_object_mut() {
        object.remove("handle");
    }
    if let Some(expressions) = item.get_mut("expr").and_then(Value::as_array_mut) {
        for expression in expressions.iter_mut() {
            if expression["match"]["left"] == json!({"meta":{"key":"l4proto"}}) {
                match expression["match"]["right"].as_str() {
                    Some("tcp") => expression["match"]["right"] = json!(6),
                    Some("udp") => expression["match"]["right"] = json!(17),
                    _ => {}
                }
            }
        }
        // nft 1.0.9 omits an explicit l4proto selector when the matching
        // transport payload already carries that dependency. Normalize only
        // this precise redundant equality, once; the exact tcp/udp dport
        // expression, address, UID/interface, order and verdict remain checked.
        // A different protocol, duplicate selector or opaque expression is
        // retained and therefore fails the complete expected-rule comparison.
        for (protocol, number) in [("tcp", 6), ("udp", 17)] {
            let selector =
                json!({"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":number}});
            let payloads = expressions.iter().filter(|expression| {
                let right = &expression["match"]["right"];
                right.as_u64().is_some()
                    && **expression == json!({"match":{"op":"==","left":{"payload":{"protocol":protocol,"field":"dport"}},"right":right}})
            }).count();
            if payloads == 1
                && expressions
                    .iter()
                    .filter(|expression| **expression == selector)
                    .count()
                    == 1
            {
                expressions.retain(|expression| *expression != selector);
            }
        }
    }
    item
}
pub(super) fn verify(plan: &GatePlan, snapshot: &Value, denying: bool) -> io::Result<()> {
    if snapshot.as_object().is_none_or(|object| {
        object.len() != 3
            || !["table", "chains", "rules"]
                .iter()
                .all(|name| object.contains_key(*name))
    }) {
        return Err(invalid(
            "gate receipt must contain the complete table, chains and rules snapshot",
        ));
    }
    let table = &snapshot["table"];
    let chains = snapshot["chains"]
        .as_array()
        .ok_or_else(|| invalid("missing gate chains"))?;
    let rules = snapshot["rules"]
        .as_array()
        .ok_or_else(|| invalid("missing gate rules"))?;
    if normalize(table.clone())
        != json!({"family":"inet","name":plan.table(),"comment":plan.marker()})
        || chains.len() != 2
        || rules.len() != if denying { 2 } else { 3 }
        || chains
            .iter()
            .filter(|observed| normalize((*observed).clone()) == chain(plan, "input"))
            .count()
            != 1
        || chains
            .iter()
            .filter(|observed| normalize((*observed).clone()) == chain(plan, "output"))
            .count()
            != 1
        || std::iter::once(table)
            .chain(chains)
            .chain(rules)
            .any(|object| object["handle"].as_u64().is_none_or(|handle| handle == 0))
    {
        return Err(invalid(
            "gate table/chain ownership or configuration does not match the complete plan",
        ));
    }
    let mut handles = std::collections::BTreeSet::new();
    if rules
        .iter()
        .any(|rule| !handles.insert(rule["handle"].as_u64()))
    {
        return Err(invalid("duplicate gate rule handles"));
    }
    let expected_output = if denying {
        vec![normalize(rule(plan, "output", "drop"))]
    } else {
        vec![
            normalize(rule(plan, "output", "allow")),
            normalize(rule(plan, "output", "drop")),
        ]
    };
    let actual_output: Vec<Value> = rules
        .iter()
        .filter(|rule| rule["chain"] == "output")
        .cloned()
        .map(normalize)
        .collect();
    let actual_input: Vec<Value> = rules
        .iter()
        .filter(|rule| rule["chain"] == "input")
        .cloned()
        .map(normalize)
        .collect();
    if actual_output != expected_output
        || actual_input != vec![normalize(rule(plan, "input", "outside"))]
    {
        return Err(invalid(
            "gate rules differ from the exact UID/endpoint/protocol deny policy",
        ));
    }
    Ok(())
}
/// A deny transaction deliberately replaces output-rule handles. Its crash
/// window cannot authorize adoption of a new table, either chain, or the
/// unaffected input rule, and a fully saved deny snapshot cannot be replaced.
pub(super) fn verify_deny_transition(
    plan: &GatePlan,
    installed: &Value,
    current: &Value,
) -> io::Result<()> {
    verify(plan, installed, false)?;
    verify(plan, current, true)?;
    let input = |snapshot: &Value| {
        snapshot["rules"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|rule| rule["chain"] == "input")
            .cloned()
            .collect::<Vec<_>>()
    };
    if current["table"] != installed["table"]
        || current["chains"] != installed["chains"]
        || input(current) != input(installed)
    {
        return Err(invalid(
            "deny recovery observed changed original table/chain/input handles; preserve the policy",
        ));
    }
    Ok(())
}
pub(super) async fn inspect(store: &Store, plan: &GatePlan) -> io::Result<Option<Value>> {
    let tables: Value = serde_json::from_slice(
        &command::run(
            store,
            &[
                "--json".into(),
                "--handle".into(),
                "--numeric".into(),
                "list".into(),
                "tables".into(),
            ],
        )
        .await?,
    )?;
    let entries = tables["nftables"]
        .as_array()
        .ok_or_else(|| invalid("invalid nft table inventory"))?;
    if entries.len() > 257 {
        return Err(invalid("nft table inventory exceeds bounded observation"));
    }
    if !entries
        .iter()
        .any(|entry| entry["table"]["family"] == "inet" && entry["table"]["name"] == plan.table())
    {
        return Ok(None);
    }
    let observation: Value = serde_json::from_slice(
        &command::run(
            store,
            &[
                "--json".into(),
                "--handle".into(),
                "--numeric".into(),
                "list".into(),
                "table".into(),
                "inet".into(),
                plan.table(),
            ],
        )
        .await?,
    )?;
    let mut table = None;
    let mut chains = Vec::new();
    let mut rules = Vec::new();
    for entry in observation["nftables"]
        .as_array()
        .ok_or_else(|| invalid("invalid nft table readback"))?
    {
        let object = entry
            .as_object()
            .ok_or_else(|| invalid("invalid nft object"))?;
        if object.len() != 1 {
            return Err(invalid("ambiguous nft readback object"));
        }
        if object.contains_key("metainfo") {
            continue;
        }
        if let Some(value) = object.get("table") {
            if table.replace(value.clone()).is_some() {
                return Err(invalid("duplicate gate table readback"));
            }
        } else if let Some(value) = object.get("chain") {
            chains.push(value.clone());
        } else if let Some(value) = object.get("rule") {
            rules.push(value.clone());
        } else {
            return Err(invalid("unknown object in gate table; preserve it"));
        }
    }
    let table = table.ok_or_else(|| invalid("gate table readback missing"))?;
    if table["family"] != "inet"
        || table["name"] != plan.table()
        || table["comment"] != plan.marker()
    {
        return Err(invalid("gate table marker belongs to another owner"));
    }
    chains.sort_by_key(|chain| chain["name"].as_str().unwrap_or("").to_owned());
    Ok(Some(json!({"table":table,"chains":chains,"rules":rules})))
}
