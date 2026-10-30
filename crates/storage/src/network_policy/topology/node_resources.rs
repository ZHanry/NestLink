//! Bootstrap observations only from current, explicitly delegated publishers.
use super::*;
use nestlink_protocol::{NodeResourceQueryClaims, api::{NetworkNodeTopologyAuthority, NetworkNodeTopologyNeighbor, NetworkTopologyEnvelope, NodeEndpointsView}, network_topology::MAX_NODE_PUBLICATIONS};

impl Store {
    /// Caller has authenticated this exact query and owns the resource snapshot
    /// transaction. A global node role alone never produces a space entry.
    pub(crate) fn node_topology_publications(&self,query:&NodeResourceQueryClaims,now:u64)
        ->Result<Vec<NetworkNodeTopologyAuthority>,StorageError>
    {
        let mut statement=self.connection.prepare("SELECT p.space_id,p.publisher_id FROM network_topology_publishers p JOIN network_authorities a ON a.space_id=p.space_id JOIN deployment d ON d.singleton=1 WHERE p.node_id=?1 AND p.revoked=0 AND p.expires_at_ms>?2 AND p.policy_epoch=a.policy_epoch AND a.authority_revoked=0 AND a.restore_fenced=0 AND a.security_epoch=d.security_epoch AND NOT EXISTS(SELECT 1 FROM network_spaces s WHERE s.space_id=p.space_id AND s.archived=1) ORDER BY p.space_id LIMIT ?3")?;
        let rows=statement.query_map(params![query.node_id,now,MAX_NODE_PUBLICATIONS+1],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?)))?
            .collect::<Result<Vec<_>,_>>()?;
        if rows.len()>MAX_NODE_PUBLICATIONS {return Err(StorageError::RateLimited);}
        drop(statement);
        let mut publications=Vec::new();
        for (space,id) in rows {
            let publication=(|| {
                let snapshot=read_snapshot(&self.connection,&space,now)?;
                let local=node(self,&query.node_id,now)?;
                if local.incarnation.runtime_id!=query.runtime_id || local.incarnation.runtime_generation!=query.runtime_generation {
                    return Err(StorageError::Forbidden);
                }
                let endpoints=super::super::remote_relays::relay_node(self,&query.node_id,now)?;
                let signed=publisher(&self.connection,&space,&id)?;
                let verified=verified_publisher(self,&snapshot,&signed,&query.node_id,&local)?;
                let claims=verified.claims();
                let exports=super::super::route_exports::for_publisher(self,&snapshot,claims)?;
                // Preserve exact original export envelopes for independent node
                // verification, rather than replacing them with parsed claims.
                let mut export_statement=self.connection.prepare("SELECT e.claims,e.signature FROM network_topology_publisher_exports p JOIN network_route_exports e ON e.space_id=p.space_id AND e.grant_id=p.grant_id WHERE p.space_id=?1 AND p.publisher_id=?2 ORDER BY e.digest")?;
                let route_exports=export_statement.query_map(params![space,id],|row|Ok(NetworkTopologyEnvelope {claims:row.get(0)?,signature:row.get(1)?}))?
                    .collect::<Result<Vec<_>,_>>()?;
                if route_exports.len()!=exports.len() {return Err(StorageError::Conflict);}
                // Read only identity columns for non-neighbors. Their full
                // signed envelopes are irrelevant to this node's delegation.
                let mut remote_statement=self.connection.prepare("SELECT p.node_id,p.publisher_id,n.public_key FROM network_topology_publishers p JOIN data_nodes n ON n.id=p.node_id WHERE p.space_id=?1 AND p.node_id<>?2 AND p.revoked=0 AND p.policy_epoch=?3 AND p.expires_at_ms>?4 ORDER BY p.node_id LIMIT ?5")?;
                let candidates=remote_statement.query_map(params![space,query.node_id,snapshot.policy_epoch,now,MAX_ADVERTISEMENTS+1],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,Vec<u8>>(2)?)))?
                    .collect::<Result<Vec<_>,_>>()?;
                // Each space has its own bounded publication graph. Summing
                // unrelated spaces would reject valid bootstrap metadata once
                // their combined graph sizes crossed one space's limit.
                if candidates.len()>MAX_ADVERTISEMENTS {return Err(StorageError::RateLimited);}
                let mut neighbors=Vec::new();
                for (remote_id,remote_publisher_id,key) in candidates {
                    let key:[u8;32]=key.try_into().map_err(|_|StorageError::Conflict)?;
                    let peer=PeerId::from_public_key(&key);
                    if claims.allowed_neighbors.binary_search(&peer).is_err() {continue;}
                    let neighbor=(|| {
                        let remote=node(self,&remote_id,now)?;
                        let remote_signed=publisher(&self.connection,&space,&remote_publisher_id)?;
                        let remote_publisher=verified_publisher(self,&snapshot,&remote_signed,&remote_id,&remote)?;
                        if remote_publisher.claims().allowed_neighbors.binary_search(&claims.peer).is_err() {
                            return Err(StorageError::Forbidden);
                        }
                        let endpoints=super::super::remote_relays::relay_node(self,&remote_id,now)?;
                        Ok(NetworkNodeTopologyNeighbor {
                            public_key:key,publisher_digest:remote_publisher.digest(),incarnation:remote.incarnation,
                            expires_at_ms:remote.lease_end.min(remote_publisher.claims().scope.expires_at_ms),
                            node:NodeEndpointsView {node_id:remote_id,revision:endpoints.endpoint_revision,endpoints:endpoints.endpoints},
                        })
                    })();
                    match neighbor {
                        Ok(neighbor)=>neighbors.push(neighbor),
                        Err(StorageError::Forbidden|StorageError::Unauthorized)=>{},
                        Err(StorageError::Proof(_))=>{},
                        Err(error)=>return Err(error),
                    }
                }
                neighbors.sort_by_key(|neighbor|PeerId::from_public_key(&neighbor.public_key));
                Ok(NetworkNodeTopologyAuthority {
                    authority_key:snapshot.authority_key,publisher:signed,publisher_digest:verified.digest(),route_exports,
                    local:NodeEndpointsView {node_id:query.node_id.clone(),revision:endpoints.endpoint_revision,endpoints:endpoints.endpoints},neighbors,
                })
            })();
            match publication {
                Ok(publication)=>publications.push(publication),
                Err(StorageError::Forbidden|StorageError::Unauthorized)=>{},
                Err(StorageError::Proof(_))=>{},
                Err(error)=>return Err(error),
            }
        }
        Ok(publications)
    }
}
