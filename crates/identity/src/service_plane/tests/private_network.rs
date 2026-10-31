//! Independently signed business and network graphs must agree before the
//! private carrier can select a route. No remote-control permit is constructed.
use super::*;
use crate::network::{NetworkAuthoritySigner, NetworkVerification, SignedNetworkGrant,
    VerifiedMembership, VerifiedNetworkGrant, VerifiedNetworkPath, private_service_path_peers,
    private_service_route_binding, verify_network_grant};
use crate::services::private::{VerifiedPrivateServiceLease, verify_private_service_lease};
use nestlink_protocol::{network::{ConnectivityClaims, GrantClaims, GrantScope, MembershipClaims,
    PathClaims, PathPolicy, PeerId, PeerPair, Purpose, SpaceRole, TransitClaims},
    services::private::PrivateServiceClaims};
use std::collections::BTreeSet;

struct PrivateFixture { base: Fixture, network: NetworkAuthoritySigner,
    consumer: InstallationIdentity, lease: VerifiedPrivateServiceLease }
impl PrivateFixture {
    fn new() -> Result<Self,ContractError> {
        let mut base=Fixture::new()?;
        base.claims.edge_key_sha256=base.claims.host_key_sha256;
        let network=NetworkAuthoritySigner::from_master_seed(&[161;32])?;
        let consumer=InstallationIdentity::generate();
        let signed=base.service.sign(&base.claims)?;
        let claims=PrivateServiceClaims { schema_version:SCHEMA_VERSION,
            service_lease_sha256:digest(&signed.claims),usage_grant_sha256:digest(&base.claims.usage_grant.claims),
            space_id:id(30),space_policy_epoch:1,network_authority_key:network.public_key(),
            exposure_revision:1,acl_rule_id:id(31),subject_epoch:3,host_membership_epoch:5,
            consumer_membership_epoch:3,consumer_account_id:id(32),consumer_login_id:id(33),
            consumer_device_id:id(34),consumer_public_key:consumer.public_key(),host_public_key:base.host.public_key() };
        let lease=verify_private_service_lease(&base.service.sign_private_service(signed,&claims)?,&base.service.public_key())?;
        Ok(Self{base,network,consumer,lease})
    }
    fn scope(&self,n:u8,epoch:u64)->GrantScope {
        GrantScope{schema_version:nestlink_protocol::network::SCHEMA_VERSION,deployment_id:id(1),
            space_id:id(30),grant_id:id(n),policy_epoch:epoch,not_before_ms:10_000,expires_at_ms:20_000}
    }
    fn path(&self,signer:&NetworkAuthoritySigner,context:&NetworkVerification<'_>,purpose:Purpose,
        consumer_epoch:u64,policy:PathPolicy)->Result<(VerifiedNetworkPath,VerifiedNetworkGrant),ContractError> {
        let member=|host:bool|->Result<VerifiedMembership,ContractError> {
            let (installation,key,epoch,n)=if host {(id(7),self.base.host.public_key(),5,41)}
                else {(id(34),self.consumer.public_key(),consumer_epoch,40)};
            let signed=signer.sign(&GrantClaims::Membership(MembershipClaims{
                scope:self.scope(n,context.policy_epoch),installation_id:installation.clone(),
                peer:PeerId::from_public_key(&key),public_key:key,membership_epoch:epoch,role:SpaceRole::Member}))?;
            VerifiedMembership::from_grant(verify_network_grant(&signed,context)?,context,&installation,&key,epoch)
        };
        let first=member(false)?;let second=member(true)?;
        let peers=PeerPair::new(first.peer(),second.peer())?;
        let membership_digests=if first.peer()==peers.first {[first.digest(),second.digest()]}
            else {[second.digest(),first.digest()]};
        let connectivity=verify_network_grant(&signer.sign(&GrantClaims::Connectivity(ConnectivityClaims{
            scope:self.scope(42,context.policy_epoch),peers,purpose,membership_digests,
            business_grant_digest:self.lease.digest()}))?,context)?;
        let signed=signer.sign(&GrantClaims::Path(PathClaims{scope:self.scope(43,context.policy_epoch),
            peers,purpose,connectivity_grant_digest:connectivity.digest(),policy}))?;
        let path=VerifiedNetworkPath::from_grants(context,[first,second],connectivity.clone(),
            verify_network_grant(&signed,context)?,self.lease.digest())?;
        Ok((path,connectivity))
    }
}
fn direct()->PathPolicy { PathPolicy{allow_direct:true,relays:vec![],max_hops:0} }

#[test]
fn private_chain_requires_service_purpose_epoch_membership_and_independent_signer()->Result<(),ContractError> {
    let f=PrivateFixture::new()?;let key=f.network.public_key();let revoked=BTreeSet::new();
    let deployment=id(1);let space=id(30);
    let context=NetworkVerification{authority_key:&key,deployment_id:&deployment,space_id:&space,
        policy_epoch:1,now_ms:11_000,revoked_grant_ids:&revoked};
    let (path,connection)=f.path(&f.network,&context,Purpose::PrivateService,3,direct())?;
    private_service_path_peers(&context,&path,&connection,&f.lease)?;path.check_route(&context,&[])?;
    let (wrong,connection)=f.path(&f.network,&context,Purpose::RemoteControl,3,direct())?;
    assert!(private_service_path_peers(&context,&wrong,&connection,&f.lease).is_err());
    let (wrong,connection)=f.path(&f.network,&context,Purpose::PrivateService,4,direct())?;
    assert!(private_service_path_peers(&context,&wrong,&connection,&f.lease).is_err());
    let newer=NetworkVerification{policy_epoch:2,..context};
    let (wrong,connection)=f.path(&f.network,&newer,Purpose::PrivateService,3,direct())?;
    assert!(private_service_path_peers(&newer,&wrong,&connection,&f.lease).is_err());
    let other=NetworkAuthoritySigner::from_master_seed(&[162;32])?;let other_key=other.public_key();
    let substituted=NetworkVerification{authority_key:&other_key,..context};
    let (wrong,connection)=f.path(&other,&substituted,Purpose::PrivateService,3,direct())?;
    assert!(private_service_path_peers(&substituted,&wrong,&connection,&f.lease).is_err());
    Ok(())
}

#[test]
fn private_relay_policy_cannot_be_dialled_direct_and_transit_never_expands_shared_budget()->Result<(),ContractError> {
    let f=PrivateFixture::new()?;let key=f.network.public_key();let revoked=BTreeSet::new();
    let deployment=id(1);let space=id(30);let relay=PeerId::from_public_key(&[173;32]);
    let context=NetworkVerification{authority_key:&key,deployment_id:&deployment,space_id:&space,
        policy_epoch:1,now_ms:11_000,revoked_grant_ids:&revoked};
    let (path,connection)=f.path(&f.network,&context,Purpose::PrivateService,3,
        PathPolicy{allow_direct:false,relays:vec![relay],max_hops:1})?;
    private_service_path_peers(&context,&path,&connection,&f.lease)?;
    assert!(path.check_route(&context,&[]).is_err());
    let peers=path.peers();
    let transit=TransitClaims{scope:f.scope(44,1),relay,peers,transport_group:path.transport_group_id(),route_id:id(45),
        previous:peers.first,next:peers.second,remaining_hops:1,byte_limit:65536};
    let verify=|claims:TransitClaims|->Result<VerifiedNetworkGrant,ContractError>{
        let signed:SignedNetworkGrant=f.network.sign(&GrantClaims::Transit(claims))?;
        verify_network_grant(&signed,&context)
    };
    private_service_route_binding(&context,&path,&connection,&verify(transit.clone())?,&f.lease)?;
    let mut exceeded=transit.clone();exceeded.byte_limit+=1;
    assert!(private_service_route_binding(&context,&path,&connection,&verify(exceeded)?,&f.lease).is_err());
    let mut wrong=transit;wrong.transport_group=[191;32];
    assert!(private_service_route_binding(&context,&path,&connection,&verify(wrong)?,&f.lease).is_err());
    Ok(())
}
