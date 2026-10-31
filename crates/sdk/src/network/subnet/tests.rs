use super::*;
use nestlink_identity::{
    network::{NetworkAuthoritySigner, verify_network_grant},
    subnet::verify_subnet_mapping,
};
use nestlink_protocol::{
    network::{
        Direction, GrantScope, IpProtocol, NetworkAccessClaims, NetworkRule, PeerId,
        RouteExportClaims,
    },
    network_topology::BootIncarnation,
    subnet::{SUBNET_MAPPING_VERSION, SubnetMappingClaims},
};
use std::collections::BTreeSet;

const DEPLOYMENT: &str = "00000000-0000-4000-8000-000000000001";
const SPACE: &str = "00000000-0000-4000-8000-000000000002";
struct Fixture {
    signer: NetworkAuthoritySigner,
    authority: [u8; 32],
    revoked: BTreeSet<String>,
    now: u64,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let signer = NetworkAuthoritySigner::from_master_seed(&[29; 32])?;
        let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
        Ok(Self {
            authority: signer.public_key(),
            signer,
            revoked: BTreeSet::new(),
            now,
        })
    }
    fn context(&self) -> NetworkVerification<'_> {
        NetworkVerification {
            authority_key: &self.authority,
            deployment_id: DEPLOYMENT,
            space_id: SPACE,
            policy_epoch: 3,
            now_ms: self.now,
            revoked_grant_ids: &self.revoked,
        }
    }
    fn scope(&self, suffix: u16) -> GrantScope {
        GrantScope {
            schema_version: 1,
            deployment_id: DEPLOYMENT.into(),
            space_id: SPACE.into(),
            grant_id: format!("00000000-0000-4000-8000-{suffix:012x}"),
            policy_epoch: 3,
            not_before_ms: self.now - 1000,
            expires_at_ms: self.now + 60_000,
        }
    }
    fn mapping(
        &self,
        suffix: u16,
        alias: &str,
    ) -> Result<VerifiedSubnetMapping, Box<dyn std::error::Error>> {
        let key = [u8::try_from(suffix)?; 32];
        let original = IpPrefix {
            network: "192.168.1.0".parse()?,
            prefix_len: 24,
        };
        let alias = IpPrefix {
            network: alias.parse()?,
            prefix_len: 24,
        };
        let export = self
            .signer
            .sign(&GrantClaims::RouteExport(RouteExportClaims {
                scope: self.scope(suffix * 3),
                gateway: PeerId::from_public_key(&key),
                prefixes: vec![alias, original],
            }))?;
        let export = verify_network_grant(&export, &self.context())?;
        let claims = SubnetMappingClaims {
            mapping_version: SUBNET_MAPPING_VERSION,
            scope: self.scope(suffix * 3 + 1),
            gateway_node_id: format!("00000000-0000-4000-8000-{:012x}", suffix + 100),
            gateway_public_key: key,
            gateway: PeerId::from_public_key(&key),
            gateway_incarnation: BootIncarnation {
                runtime_generation: 1,
                runtime_id: format!("00000000-0000-4000-8000-{:012x}", suffix + 200),
            },
            original,
            alias,
            route_export_digest: export.digest(),
            mapping_revision: 1,
        };
        Ok(verify_subnet_mapping(
            &self.signer.sign_subnet_mapping(&claims)?,
            &self.context(),
            export,
            &gateway(&claims),
        )?)
    }
    fn access(
        &self,
        mapping: &VerifiedSubnetMapping,
    ) -> Result<VerifiedNetworkGrant, Box<dyn std::error::Error>> {
        let claims = GrantClaims::NetworkAccess(NetworkAccessClaims {
            scope: self.scope(999),
            source: PeerId::from_public_key(&[101; 32]),
            destination: mapping.claims().gateway,
            source_prefixes: vec![IpPrefix {
                network: "10.80.0.2".parse()?,
                prefix_len: 32,
            }],
            destination_prefixes: vec![mapping.claims().alias],
            rules: vec![NetworkRule {
                protocol: IpProtocol::Tcp,
                direction: Direction::Inbound,
                ports: Some([443, 443]),
            }],
            byte_limit: 100_000,
        });
        Ok(verify_network_grant(
            &self.signer.sign(&claims)?,
            &self.context(),
        )?)
    }
}
fn gateway(claims: &SubnetMappingClaims) -> SubnetGatewayState<'_> {
    SubnetGatewayState {
        node_id: &claims.gateway_node_id,
        public_key: &claims.gateway_public_key,
        incarnation: &claims.gateway_incarnation,
        mapping_revision: claims.mapping_revision,
        lease_expires_at_ms: claims.scope.expires_at_ms,
    }
}
fn interfaces() -> SubnetInterfaces {
    SubnetInterfaces {
        tun: SubnetInterface {
            index: 71,
            name: "nltfixture".into(),
        },
        lan: SubnetInterface {
            index: 2,
            name: "eth0".into(),
        },
    }
}
fn consent(
    mapping: &VerifiedSubnetMapping,
    access: &VerifiedNetworkGrant,
) -> io::Result<SubnetLocalConsent> {
    SubnetLocalConsent::approve(
        "00000000-0000-4000-8000-000000000099".into(),
        mapping.digest(),
        access.digest(),
    )
}
#[test]
fn two_overlapping_sites_have_distinct_aliases_and_exact_local_intent()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let first = fixture.mapping(11, "10.210.1.0")?;
    let second = fixture.mapping(12, "10.210.2.0")?;
    let local = IpPrefix {
        network: "192.168.1.0".parse()?,
        prefix_len: 24,
    };
    check_mapping_conflicts(&[first.clone(), second], &[local])?;
    let access = fixture.access(&first)?;
    let GrantClaims::NetworkAccess(mut reflected_claims) = access.claims().clone() else {return Err("expected raw-IP access".into());};
    reflected_claims.source_prefixes = vec![IpPrefix {network:"192.168.1.42".parse()?,prefix_len:32}];
    let reflected = verify_network_grant(&fixture.signer.sign(&GrantClaims::NetworkAccess(reflected_claims))?,&fixture.context())?;
    assert!(VerifiedSubnetPlan::new(&fixture.context(),&gateway(first.claims()),first.clone(),reflected.clone(),consent(&first,&reflected)?,interfaces(),&["203.0.113.8".parse()?]).is_err(),"a remote wire route must not be delivered back into this gateway's original LAN");
    let approved = consent(&first, &access)?;
    let plan = VerifiedSubnetPlan::new(
        &fixture.context(),
        &gateway(first.claims()),
        first.clone(),
        access,
        approved,
        interfaces(),
        &["203.0.113.8".parse()?],
    )?;
    plan.check_current(&fixture.context(), &gateway(first.claims()))?;
    assert_eq!(plan.view().translation, SubnetTranslation::Ipv4PrefixNat);
    assert_eq!(plan.view().original, local);
    assert_eq!(plan.view().alias.network, "10.210.1.0".parse::<IpAddr>()?);
    let rules = plan
        .nft_ipv4_translation()
        .ok_or("IPv4 prefix NAT intent missing")?;
    assert!(rules[0].contains("dnat ip prefix to ip daddr map { 10.210.1.0/24 : 192.168.1.0/24 }"));
    assert!(rules[1].contains("snat ip prefix to ip saddr map { 192.168.1.0/24 : 10.210.1.0/24 }"));
    assert!(
        rules
            .iter()
            .all(|rule| rule.contains("71 meta") && rule.contains("\"nltfixture\""))
    );
    Ok(())
}
#[test]
fn ambiguity_local_conflicts_and_forged_interface_names_are_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let first = fixture.mapping(11, "10.210.1.0")?;
    let duplicate = fixture.mapping(12, "10.210.1.0")?;
    assert!(check_mapping_conflicts(&[first.clone(), duplicate], &[]).is_err());
    assert!(
        check_mapping_conflicts(
            std::slice::from_ref(&first),
            &[IpPrefix {
                network: "10.210.0.0".parse()?,
                prefix_len: 16
            }]
        )
        .is_err()
    );
    for name in ["lo", "eth0\";flush ruleset", "*", "../eth0", "eth0\n"] {
        let mut selected = interfaces();
        selected.lan.name = name.into();
        let access = fixture.access(&first)?;
        let choice = consent(&first, &access)?;
        assert!(
            VerifiedSubnetPlan::new(
                &fixture.context(),
                &gateway(first.claims()),
                first.clone(),
                access,
                choice,
                selected,
                &["203.0.113.8".parse()?]
            )
            .is_err()
        );
    }
    Ok(())
}
#[test]
fn exact_approval_gateway_prefix_and_physical_endpoint_cannot_be_replaced()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let first = fixture.mapping(11, "10.210.1.0")?;
    let access = fixture.access(&first)?;
    let wrong_choice = SubnetLocalConsent::approve(
        "00000000-0000-4000-8000-000000000099".into(),
        [91; 32],
        access.digest(),
    )?;
    assert!(
        VerifiedSubnetPlan::new(
            &fixture.context(),
            &gateway(first.claims()),
            first.clone(),
            access.clone(),
            wrong_choice,
            interfaces(),
            &["203.0.113.8".parse()?]
        )
        .is_err()
    );
    assert!(
        VerifiedSubnetPlan::new(
            &fixture.context(),
            &gateway(first.claims()),
            first.clone(),
            access.clone(),
            consent(&first, &access)?,
            interfaces(),
            &["10.210.1.20".parse()?]
        )
        .is_err()
    );
    assert!(
        VerifiedSubnetPlan::new(
            &fixture.context(),
            &gateway(first.claims()),
            first.clone(),
            access.clone(),
            consent(&first, &access)?,
            interfaces(),
            &["10.80.0.2".parse()?]
        )
        .is_err(),
        "a remote wire route must not capture the original physical endpoint either"
    );
    let other = fixture.mapping(12, "10.210.2.0")?;
    assert!(
        VerifiedSubnetPlan::new(
            &fixture.context(),
            &gateway(other.claims()),
            other.clone(),
            access.clone(),
            consent(&other, &access)?,
            interfaces(),
            &["203.0.113.8".parse()?]
        )
        .is_err()
    );
    let plan = VerifiedSubnetPlan::new(
        &fixture.context(),
        &gateway(first.claims()),
        first.clone(),
        access.clone(),
        consent(&first, &access)?,
        interfaces(),
        &["203.0.113.8".parse()?],
    )?;
    fixture
        .revoked
        .insert(first.claims().scope.grant_id.clone());
    assert!(
        plan.check_current(&fixture.context(), &gateway(first.claims()))
            .is_err()
    );
    fixture.revoked.clear();
    fixture.now = fixture.now.saturating_sub(5000);
    assert!(
        plan.check_current(&fixture.context(), &gateway(first.claims()))
            .is_err()
    );
    Ok(())
}
