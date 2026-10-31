//! Private installation reports use the original admitted-byte/flow ledger and
//! its immutable pending-report queue. No private allowance is created here.
use super::*;
use nestlink_identity::{InstallationIdentity, services::private::{VerifiedPrivateServiceLease, verify_private_service_lease}};
use nestlink_protocol::services::private::*;

impl ServiceUsageStore {
    pub fn activate_private(&self, lease: &VerifiedPrivateServiceLease) -> Result<(), Error> {
        let json = serde_json::to_string(lease.signed()).map_err(|_| fenced())?;
        self.activate_inner(lease.lease(),Some((json,lease.lease().issuer())))?;
        Ok(())
    }

    /// Retries retain exact signed bytes even when current counters advance.
    /// A final report requires the original gate's real drain receipt.
    pub fn private_report(&self, grant_id: &str, host: &InstallationIdentity,
        terminal: bool, sampled_at_unix_ms: u64) -> Result<Option<SignedPrivateServiceUsage>, Error> {
        let mut connection = self.connection.lock().map_err(|_| fenced())?;
        let tx = connection.transaction()?;
        type Facts = (String,Vec<u8>,Vec<u8>,u64,u64,u64,u64,bool,bool,bool);
        let (json,issuer,hash,admitted,opened,closed,sequence,stopped,drained,ended): Facts = tx.query_row(
            "SELECT p.lease_json,p.issuer,g.grant_sha256,g.admitted_bytes,g.opened_connections,g.closed_connections,g.report_sequence,g.stop_requested,g.drain_confirmed,g.terminal FROM service_usage_local_private p JOIN service_usage_local_grants g ON g.grant_id=p.grant_id WHERE p.grant_id=?1",
            [grant_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?)))?;
        if ended { return Ok(None); }
        let signed: SignedPrivateServiceLease = serde_json::from_str(&json).map_err(|_|fenced())?;
        let issuer: [u8;32] = issuer.try_into().map_err(|_|fenced())?;
        let lease = verify_private_service_lease(&signed,&issuer).map_err(|_|fenced())?;
        if host.public_key() != lease.claims().host_public_key { return Err(fenced()); }
        let pending: Option<String> = tx.query_row(
            "SELECT report_json FROM service_usage_local_reports WHERE grant_id=?1 AND ack_json IS NULL ORDER BY report_sequence LIMIT 1",
            [grant_id],|r|r.get(0)).optional()?;
        if let Some(pending) = pending {
            return Ok(Some(serde_json::from_str(&pending).map_err(|_|fenced())?));
        }
        if terminal && (!stopped || !drained || opened != closed) { return Err(fenced()); }
        let base = lease.lease().claims();
        let claims = PrivateServiceUsageClaims { schema_version: nestlink_protocol::SCHEMA_VERSION,
            deployment_id: base.deployment_id.clone(), security_epoch: base.security_epoch,
            grant_id: grant_id.into(), grant_sha256: hash.try_into().map_err(|_|fenced())?,
            host_device_id: base.definition.host_device_id.clone(), runtime_id: base.edge_runtime_id.clone(),
            report_sequence: sequence.checked_add(1).ok_or_else(fenced)?, admitted_bytes: admitted,
            opened_connections: opened, closed_connections: closed, terminal, sampled_at_unix_ms };
        let report = host.sign_private_service_usage(&claims).map_err(|_|fenced())?;
        tx.execute("INSERT INTO service_usage_local_reports(grant_id,report_sequence,report_sha256,report_json) VALUES(?1,?2,?3,?4)",
            params![grant_id,claims.report_sequence,digest(&report.claims),serde_json::to_string(&report).map_err(|_|fenced())?])?;
        tx.commit()?;
        Ok(Some(report))
    }
    pub fn acknowledge_private_report(&self, ack: &PrivateServiceUsageAck) -> Result<(), Error> {
        let mut connection = self.connection.lock().map_err(|_|fenced())?;
        let tx = connection.transaction()?;
        let json: String = tx.query_row("SELECT report_json FROM service_usage_local_reports WHERE grant_id=?1 AND report_sequence=?2 AND ack_json IS NULL",
            params![ack.grant_id,ack.report_sequence],|r|r.get(0))?;
        let signed: SignedPrivateServiceUsage = serde_json::from_str(&json).map_err(|_|fenced())?;
        let claims: PrivateServiceUsageClaims = decode_service_message(&signed.claims,PRIVATE_SERVICE_MESSAGE_BYTES).map_err(|_|fenced())?;
        if digest(&signed.claims) != ack.report_sha256 || claims.terminal != ack.terminal
            || claims.grant_id != ack.grant_id || claims.report_sequence != ack.report_sequence { return Err(fenced()); }
        tx.execute("UPDATE service_usage_local_reports SET ack_json=?1 WHERE grant_id=?2 AND report_sequence=?3 AND ack_json IS NULL",
            params![serde_json::to_string(ack).map_err(|_|fenced())?,ack.grant_id,ack.report_sequence])?;
        if tx.execute("UPDATE service_usage_local_grants SET report_sequence=?1,report_sha256=?2,terminal=?3 WHERE grant_id=?4 AND report_sequence=?5 AND terminal=0",
            params![ack.report_sequence,ack.report_sha256,ack.terminal,ack.grant_id,ack.report_sequence.checked_sub(1).ok_or_else(fenced)?])? != 1 { return Err(fenced()); }
        tx.commit()?;
        Ok(())
    }
}
