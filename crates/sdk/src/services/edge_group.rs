//! Management metadata creates no native group or target owner. Native startup
//! additionally consumes the explicit local group choice and target consent.
use super::*;
use nestlink_protocol::service_plane::{group::*,publication::ServicePublicationRequest};

impl Sdk {
    pub async fn service_edge_group(&self,id:&str)->Result<ServiceEdgeGroupView,SdkError> {
        let service=self.service(id).await?;
        let view:ServiceEdgeGroupView=self.required(Method::GET,&format!("{}/edge-group",resource("services",id)?),None::<&()>).await?;
        self.validate_edge_group(id,&service,&view)?;Ok(view)
    }
    pub async fn set_service_edge_group(&self,id:&str,body:&ServiceEdgeGroupUpdate)->Result<ServiceEdgeGroupView,SdkError> {
        let service=self.service(id).await?;body.validate(&service.definition)?;
        let view:ServiceEdgeGroupView=self.required(Method::PUT,&format!("{}/edge-group",resource("services",id)?),Some(body)).await?;
        self.validate_edge_group(id,&service,&view)?;
        if view.revision!=body.expected_revision.checked_add(1).ok_or(SdkError::Invalid)?
            || view.service_revision!=body.expected_service_revision || view.members!=body.members || view.public_ips!=body.public_ips {return Err(SdkError::Trust);}
        Ok(view)
    }
    fn validate_edge_group(&self,id:&str,service:&ServiceView,view:&ServiceEdgeGroupView)->Result<(),SdkError> {
        view.validate(&service.definition)?;
        if view.service_id!=id || view.service_revision!=service.revision
            || view.definition_sha256!=nestlink_identity::services::decode_digest(&service.definition_sha256)? {return Err(SdkError::Trust);}
        Ok(())
    }
    pub async fn revoke_service_edge_group(&self,id:&str,revision:u64)->Result<(),SdkError> {
        if !nestlink_protocol::services::revision_valid(revision){return Err(SdkError::Invalid);}
        self.call::<_,serde_json::Value>(Method::DELETE,&format!("{}/edge-group",resource("services",id)?),Some(&ServicePublicationRequest{expected_revision:revision}),true).await?;Ok(())
    }
    pub async fn publish_service_group(&self,id:&str,body:&ServiceGroupPublicationRequest)->Result<ServiceGroupPublicationGrant,SdkError> {
        body.validate()?;
        let result:ServiceGroupPublicationGrant=self.required(Method::POST,&format!("{}/publication-group",resource("services",id)?),Some(body)).await?;
        if result.group.service_id!=id || result.group.group_id!=body.group_id || result.group.revision!=body.expected_group_revision
            || result.group.service_revision!=body.expected_service_revision {return Err(SdkError::Trust);}
        // Full cryptographic member verification belongs to native startup;
        // the management method itself grants no target or socket authority.
        if result.members.len()!=result.group.members.len(){return Err(SdkError::Trust);}
        Ok(result)
    }
    pub async fn service_group_publication(&self,id:&str)->Result<ServiceGroupPublicationGrant,SdkError> {
        let result:ServiceGroupPublicationGrant=self.required(Method::GET,&format!("{}/publication-group",resource("services",id)?),None::<&()>).await?;
        if result.group.service_id!=id || result.members.len()!=result.group.members.len(){return Err(SdkError::Trust);}
        Ok(result)
    }
    pub async fn stop_service_group_publication(&self,id:&str,body:&ServiceGroupPublicationRequest)->Result<(),SdkError> {
        body.validate()?;
        self.call::<_,serde_json::Value>(Method::DELETE,&format!("{}/publication-group",resource("services",id)?),Some(body),true).await?;Ok(())
    }
}
