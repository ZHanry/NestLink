//! A single explicit local selection starts independent original edge owners.
//! Losing one edge does not revoke a healthy sibling's target or budget owner.
use super::*;
use futures_util::{StreamExt,stream::FuturesUnordered};
use nestlink_identity::service_plane::group::service_edge_group_digest;
use nestlink_protocol::service_plane::group::*;

pub struct LocalServiceGroupChoice { group:ServiceEdgeGroupView, digest:[u8;32] }
impl LocalServiceGroupChoice {
    /// Display and select every recipient, namespace revision and allocation
    /// locally. This owner cannot be deserialized from management/IPC JSON.
    pub fn from_local_choice(group:&ServiceEdgeGroupView,consent:&LocalServiceTargetConsent)->Result<Self,SdkError> {
        group.validate(&consent.original_view.definition)?;
        if group.service_id!=consent.service_id || consent.revision.checked_add(1)!=Some(group.service_revision)
            || group.definition_sha256!=nestlink_identity::services::decode_digest(&consent.definition_sha256)?
            || group.target_sha256!=nestlink_identity::services::decode_digest(&consent.target_sha256)? {return Err(SdkError::Trust);}
        Ok(Self{group:group.clone(),digest:service_edge_group_digest(group)?})
    }
    pub fn group(&self)->&ServiceEdgeGroupView {&self.group}
    fn request(&self)->ServiceGroupPublicationRequest {
        ServiceGroupPublicationRequest{group_version:SERVICE_EDGE_GROUP_VERSION,group_id:self.group.group_id.clone(),expected_group_revision:self.group.revision,expected_service_revision:self.group.service_revision,aggregate_sha256:self.digest}
    }
}
pub struct LocalServiceGroupRuntime {members:Vec<(String,LocalServiceRuntime)>}
#[derive(Debug,Clone,PartialEq,Eq)]
pub enum ServiceGroupHostWait {
    CleanupPending,
    Stopped{members:Vec<(String,ServiceHostStopReport)>},
}
impl LocalServiceGroupRuntime {
    pub fn stop(&self){for (_,runtime) in &self.members{runtime.stop();}}
    /// These are live original lease/connection observations, not a claim that
    /// an external load balancer has sent traffic to every member.
    pub fn ready_members(&self)->Vec<String> {
        self.members.iter().filter(|(_,runtime)|runtime.publication.handle().lease().is_ok()
            && runtime.connection.as_ref().is_some_and(|connection|connection.close_reason().is_none())
            && !*runtime.stop.borrow()).map(|(node,_)|node.clone()).collect()
    }
    pub async fn wait_stopped(&mut self,budget:Duration)->ServiceGroupHostWait {
        self.stop();
        let reports=futures_util::future::join_all(self.members.iter_mut().map(|(node,runtime)|async move {(node.clone(),runtime.wait_stopped(budget).await)})).await;
        let mut members=Vec::new();
        for (node,report) in reports {
            match report{ServiceHostWait::Stopped(report)=>members.push((node,report)),ServiceHostWait::CleanupPending{..}=>return ServiceGroupHostWait::CleanupPending}
        }
        ServiceGroupHostWait::Stopped{members}
    }
}
impl Drop for LocalServiceGroupRuntime {fn drop(&mut self){self.stop();}}

fn copy_selected_consent(consent:&LocalServiceTargetConsent)->LocalServiceTargetConsent {
    // Private to the consumed group-start operation. There is deliberately no
    // public Clone for a local target consent or a group chooser owner.
    LocalServiceTargetConsent{original_view:consent.original_view.clone(),service_id:consent.service_id.clone(),revision:consent.revision,definition_sha256:consent.definition_sha256.clone(),host_device_id:consent.host_device_id.clone(),account_id:consent.account_id.clone(),target_id:consent.target_id.clone(),target_sha256:consent.target_sha256.clone(),protocol:consent.protocol.clone(),address:consent.address,backend_tls:consent.backend_tls.clone()}
}
impl Sdk {
    pub async fn start_service_group_host(&self,host:Arc<DeviceIdentity>,consent:LocalServiceTargetConsent,choice:LocalServiceGroupChoice)->Result<LocalServiceGroupRuntime,SdkError> {
        let (_sender,cancelled)=watch::channel(false);
        self.start_service_group_host_cancellable(host,consent,choice,cancelled).await
    }
    pub async fn start_service_group_host_cancellable(&self,host:Arc<DeviceIdentity>,consent:LocalServiceTargetConsent,choice:LocalServiceGroupChoice,mut cancelled:watch::Receiver<bool>)->Result<LocalServiceGroupRuntime,SdkError> {
        if *cancelled.borrow(){return Err(interrupted());}
        let selected=LocalServiceGroupChoice::from_local_choice(&choice.group,&consent)?;
        if selected.digest!=choice.digest || host.device_id!=consent.host_device_id
            || self.principal().ok_or(SdkError::SignIn)?.account_id!=consent.account_id {return Err(SdkError::Trust);}
        let request=choice.request();let requested=Instant::now();
        let publishing=self.publish_service_group(&consent.service_id,&request);tokio::pin!(publishing);
        let grant=tokio::select!{biased;
            _=start_cancelled(&mut cancelled)=>{
                // Keep the original HTTP issuance future through completion,
                // then revoke the selected group. Dropping it could race a
                // late committed publication against an earlier stop request.
                let _=publishing.await;let _=self.stop_service_group_publication(&consent.service_id,&request).await;return Err(interrupted());
            },
            grant=&mut publishing=>match grant{Ok(grant)=>grant,Err(error)=>{let _=self.stop_service_group_publication(&consent.service_id,&request).await;return Err(error);}},
        };
        let validation=(||->Result<(),SdkError>{
        if grant.group!=choice.group || grant.members.len()!=choice.group.members.len(){return Err(SdkError::Trust);}
        let policy:[u8;32]=URL_SAFE_NO_PAD.decode(&self.health.node_policy_issuer).map_err(|_|SdkError::Trust)?.try_into().map_err(|_|SdkError::Trust)?;
        // Verify every signed recipient and allocation before connecting to any
        // edge. Ordering, duplicates, changed digests and stale revisions fail.
        for (member,grant) in choice.group.members.iter().zip(&grant.members) {
            let issuer=verify_service_issuer_delegation(&grant.issuer,&policy,&self.trust.deployment_id,wall()?)?;
            let lease=issuer.verify_lease(&grant.lease,wall()?)?;
            let binding=lease.claims().edge_group.as_ref().ok_or(SdkError::Trust)?;
            if binding.group!=choice.group || binding.member_node_id!=member.node_id || binding.aggregate_sha256!=choice.digest
                || lease.claims().edge_key_sha256!=digest(&grant.edge_public_key) {return Err(SdkError::Trust);}
        }
        Ok(())})();
        if let Err(error)=validation{let _=self.stop_service_group_publication(&consent.service_id,&request).await;return Err(error);}
        let (stop,children_cancelled)=watch::channel(false);
        let mut pending=FuturesUnordered::new();
        for (member,grant) in choice.group.members.iter().zip(grant.members) {
            let node=member.node_id.clone();let consent=copy_selected_consent(&consent);let host=host.clone();let cancelled=children_cancelled.clone();let group=&choice.group;
            pending.push(async move {(node,self.attach_service_publication(host,consent,grant,requested,cancelled,Some(group)).await)});
        }
        let mut members=Vec::new();let mut failure=None;let mut externally_cancelled=false;
        while !pending.is_empty(){
            tokio::select!{biased;
                _=start_cancelled(&mut cancelled),if !externally_cancelled=>{externally_cancelled=true;stop.send_replace(true);if failure.is_none(){failure=Some(interrupted());}},
                Some((node,result))=pending.next()=>match result{Ok(runtime)=>members.push((node,runtime)),Err(error)=>{stop.send_replace(true);if failure.is_none(){failure=Some(error);}}},
            }
        }
        members.sort_by(|a,b|a.0.cmp(&b.0));
        let mut runtime=LocalServiceGroupRuntime{members};
        if let Some(error)=failure {
            // Management failure cannot extend any old edge lease; still join
            // every original local owner before returning the startup error.
            let _=self.stop_service_group_publication(&consent.service_id,&request).await;
            while matches!(runtime.wait_stopped(Duration::from_secs(5)).await,ServiceGroupHostWait::CleanupPending){}
            return Err(error);
        }
        Ok(runtime)
    }
}
