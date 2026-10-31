//! Durable IPAM/name directory. No resolver, OS route or traffic authorization.
use super::*;
use ipnet::{Ipv4Net, Ipv6Net};
use nestlink_protocol::spaces::addressing::*;
use std::net::{Ipv4Addr, Ipv6Addr};

const IPV4_POOL: &str = "100.64.0.0/10";
const IPV6_POOL: &str = "fd4e:6573:744c::/48";
const MAX_SLOT: u64 = (1 << 22) - 1;
const MAX_ALLOCATION_PROBES: u64 = 128;

struct Identity {
    account: String,
    public_key: [u8; 32],
    account_epoch: u64,
    membership_epoch: u64,
}

struct Address {
    installation: String,
    account: String,
    public_key: Vec<u8>,
    account_epoch: u64,
    membership_epoch: u64,
    epoch: u64,
    name: String,
    ipv4: String,
    ipv6: String,
    reserved: bool,
    revoked: bool,
}

fn label(value: &str) -> Result<String, StorageError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 63
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
        || !bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
    {
        return Err(StorageError::Invalid("invalid space DNS label"));
    }
    Ok(value.to_ascii_lowercase())
}

fn suffix(space: &str) -> String {
    format!("s-{space}.nestlink.internal")
}

fn pools() -> Result<(Ipv4Net, Ipv6Net), StorageError> {
    Ok((
        IPV4_POOL.parse().map_err(|_| StorageError::Conflict)?,
        IPV6_POOL.parse().map_err(|_| StorageError::Conflict)?,
    ))
}

fn addresses(ipv4: &str, ipv6: &str) -> Result<(String, String), StorageError> {
    let v4: Ipv4Addr = ipv4.parse().map_err(|_| StorageError::Invalid("invalid IPv4 address"))?;
    let v6: Ipv6Addr = ipv6.parse().map_err(|_| StorageError::Invalid("invalid IPv6 address"))?;
    let (pool4, pool6) = pools()?;
    // Reserve every /24 network, gateway and broadcast position, plus the
    // IPv6 pool's zero/gateway addresses. This is a directory allocation rule.
    if !pool4.contains(&v4)
        || !(2..=254).contains(&v4.octets()[3])
        || !pool6.contains(&v6)
        || u128::from(v6) - u128::from(pool6.network()) <= 1
    {
        return Err(StorageError::Invalid("address outside usable virtual pools"));
    }
    Ok((v4.to_string(), v6.to_string()))
}

fn stored(connection: &Connection, space: &str, installation: &str) -> Result<Option<Address>, StorageError> {
    Ok(connection.query_row(
        "SELECT installation_id,account_id,public_key,account_member_epoch,membership_epoch,address_epoch,name,ipv4,ipv6,reserved,revoked FROM network_space_addresses WHERE space_id=?1 AND installation_id=?2",
        params![space,installation],
        |r| Ok(Address {
            installation:r.get(0)?, account:r.get(1)?, public_key:r.get(2)?,
            account_epoch:r.get(3)?, membership_epoch:r.get(4)?, epoch:r.get(5)?,
            name:r.get(6)?, ipv4:r.get(7)?, ipv6:r.get(8)?,
            reserved:r.get(9)?, revoked:r.get(10)?,
        }),
    ).optional()?)
}

fn directory_revision(connection: &Connection, space: &str, now: u64) -> Result<u64, StorageError> {
    let row: Option<(u64, u64)> = connection.query_row(
        "SELECT revision,last_observed_ms FROM network_space_address_directories WHERE space_id=?1",
        [space], |r| Ok((r.get(0)?,r.get(1)?)),
    ).optional()?;
    if let Some((revision, observed)) = row {
        if now < observed { return Err(StorageError::Conflict); }
        Ok(revision)
    } else {
        Ok(0)
    }
}

fn write_authority(connection: &Connection, actor: &Principal, id: &str, expected: u64, now: u64) -> Result<SpaceView, StorageError> {
    let space = read_space(connection, actor, id, now)?;
    if space.archived || !management(space.role) { return Err(StorageError::Forbidden); }
    if directory_revision(connection,id,now)? != expected || expected >= i64::MAX as u64 {
        return Err(StorageError::Conflict);
    }
    Ok(space)
}

fn advance_directory(tx: &Transaction<'_>, id: &str, expected: u64, now: u64) -> Result<(), StorageError> {
    let changed = if expected == 0 {
        tx.execute("INSERT INTO network_space_address_directories(space_id,revision,last_observed_ms) VALUES(?1,1,?2) ON CONFLICT DO NOTHING", params![id,now])?
    } else {
        tx.execute("UPDATE network_space_address_directories SET revision=revision+1,last_observed_ms=?1 WHERE space_id=?2 AND revision=?3", params![now,id,expected])?
    };
    if changed != 1 { return Err(StorageError::Conflict); }
    Ok(())
}

fn next_epoch(epoch: u64) -> Result<u64, StorageError> {
    epoch.checked_add(1).filter(|v| *v <= i64::MAX as u64).ok_or(StorageError::Conflict)
}

fn free(connection: &Connection, space: &str, installation: &str, name: &str, ipv4: &str, ipv6: &str) -> Result<(), StorageError> {
    let occupied: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM network_space_addresses WHERE revoked=0 AND NOT(space_id=?1 AND installation_id=?2) AND ((space_id=?1 AND name=?3) OR ipv4=?4 OR ipv6=?5))",
        params![space,installation,name,ipv4,ipv6], |r|r.get(0),
    )?;
    if occupied { return Err(StorageError::Conflict); }
    Ok(())
}

fn automatic(connection: &Connection) -> Result<(u64, String, String), StorageError> {
    let maximum: u64 = connection.query_row("SELECT coalesce(max(allocation_slot),0) FROM network_space_addresses", [], |r|r.get(0))?;
    let (v4, v6) = pools()?;
    let end = maximum.saturating_add(MAX_ALLOCATION_PROBES).min(MAX_SLOT);
    for slot in maximum.saturating_add(1)..=end {
        let candidate4 = Ipv4Addr::from(u32::from(v4.network()) + slot as u32);
        if !(2..=254).contains(&candidate4.octets()[3]) { continue; }
        let candidate6 = Ipv6Addr::from(u128::from(v6.network()) + u128::from(slot));
        let a4 = candidate4.to_string();
        let a6 = candidate6.to_string();
        let occupied: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM network_space_addresses WHERE revoked=0 AND (ipv4=?1 OR ipv6=?2))", params![a4,a6], |r|r.get(0))?;
        if !occupied { return Ok((slot,a4,a6)); }
    }
    Err(StorageError::RateLimited)
}

impl Store {
    fn address_identity(&self, connection: &Connection, space: &str, installation: &str, now: u64) -> Result<Identity, StorageError> {
        require_id(installation)?;
        let device = self.device_record_at(installation,now / 1000)?;
        let (role, account_epoch, active) = member(connection,space,&device.account)?;
        if !active { return Err(StorageError::Forbidden); }
        type Row = (Vec<u8>,u64,String,bool,Vec<u8>);
        let row: Option<Row> = connection.query_row("SELECT m.public_key,m.membership_epoch,m.role,m.revoked,d.key_sha256 FROM network_memberships m JOIN devices d ON d.id=m.installation_id WHERE m.space_id=?1 AND m.installation_id=?2", params![space,installation], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
        let (key,membership_epoch,device_role,revoked,key_hash) = row.ok_or(StorageError::Forbidden)?;
        if revoked || key != device.public_key || device_role != role_name(role) || key_hash != nestlink_identity::digest(&device.public_key) { return Err(StorageError::Forbidden); }
        Ok(Identity { account:device.account, public_key:device.public_key, account_epoch, membership_epoch })
    }

    fn address_current(&self, connection: &Connection, space: &SpaceView, row: &Address, now: u64) -> Result<bool, StorageError> {
        if space.archived || row.revoked { return Ok(false); }
        match self.address_identity(connection,&space.space_id,&row.installation,now) {
            Ok(identity) => Ok(identity.account == row.account && identity.public_key.as_slice() == row.public_key.as_slice() && identity.account_epoch == row.account_epoch && identity.membership_epoch == row.membership_epoch),
            Err(StorageError::Forbidden | StorageError::Unauthorized | StorageError::Conflict) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn address_directory_view(&self, connection: &Connection, actor: &Principal, space: SpaceView, now: u64) -> Result<SpaceAddressDirectory, StorageError> {
        let revision = directory_revision(connection,&space.space_id,now)?;
        let suffix = suffix(&space.space_id);
        let mut statement = connection.prepare("SELECT installation_id FROM network_space_addresses WHERE space_id=?1 AND (?2 OR account_id=?3) ORDER BY installation_id LIMIT ?4")?;
        let ids = statement.query_map(params![space.space_id,management(space.role),actor.account_id,MAX_MEMBERS+1], |r|r.get::<_,String>(0))?.collect::<Result<Vec<_>,_>>()?;
        if ids.len() as u64 > MAX_MEMBERS { return Err(StorageError::RateLimited); }
        let mut views = Vec::new();
        for id in ids {
            let row = stored(connection,&space.space_id,&id)?.ok_or(StorageError::Conflict)?;
            let active = self.address_current(connection,&space,&row,now)?;
            if !management(space.role) && !active { continue; }
            views.push(SpaceAddressView {
                installation_id:row.installation, account_id:row.account,
                public_key:URL_SAFE_NO_PAD.encode(row.public_key), account_member_epoch:row.account_epoch,
                membership_epoch:row.membership_epoch, address_epoch:row.epoch,
                fqdn:format!("{}.{}",row.name,suffix), name:row.name,
                ipv4:row.ipv4, ipv6:row.ipv6, reserved:row.reserved, revoked:row.revoked, active,
            });
        }
        Ok(SpaceAddressDirectory { space, revision, suffix, ipv4_pool:IPV4_POOL.into(), ipv6_pool:IPV6_POOL.into(), cache_max_age_seconds:0, addresses:views })
    }

    pub fn space_address_directory(&self, actor: &Principal, id: &str, now: u64) -> Result<SpaceAddressDirectory, StorageError> {
        let tx = self.connection.unchecked_transaction()?;
        self.validate_access(actor,now / 1000)?;
        let space = read_space(&tx,actor,id,now)?;
        self.address_directory_view(&tx,actor,space,now)
    }

    pub fn issue_space_address(&mut self, actor: &Principal, id: &str, request: SpaceAddressIssue, now: u64) -> Result<SpaceAddressDirectory, StorageError> {
        require_id(&request.installation_id)?;
        let name = label(&request.name)?;
        let tx = Transaction::new_unchecked(&self.connection,TransactionBehavior::Immediate)?;
        self.validate_access(actor,now / 1000)?;
        let space = write_authority(&tx,actor,id,request.expected_revision,now)?;
        let identity = self.address_identity(&tx,id,&request.installation_id,now)?;
        if identity.membership_epoch != request.expected_membership_epoch { return Err(StorageError::Conflict); }
        let old = stored(&tx,id,&request.installation_id)?;
        if old.as_ref().map_or(0,|r|r.epoch) != request.expected_address_epoch { return Err(StorageError::Conflict); }
        if let Some(row) = &old {
            if !row.revoked {
                if !self.address_current(&tx,&space,row,now)? || row.name != name { return Err(StorageError::Conflict); }
                return self.address_directory_view(&tx,actor,space,now);
            }
        } else {
            let count: u64 = tx.query_row("SELECT count(*) FROM network_space_addresses WHERE space_id=?1", [id], |r|r.get(0))?;
            if count >= MAX_MEMBERS { return Err(StorageError::RateLimited); }
        }
        let (slot,ipv4,ipv6) = automatic(&tx)?;
        free(&tx,id,&request.installation_id,&name,&ipv4,&ipv6)?;
        let epoch = next_epoch(request.expected_address_epoch)?;
        tx.execute("INSERT INTO network_space_addresses(space_id,installation_id,account_id,public_key,account_member_epoch,membership_epoch,address_epoch,name,ipv4,ipv6,allocation_slot,reserved,revoked) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,0,0) ON CONFLICT(space_id,installation_id) DO UPDATE SET account_id=excluded.account_id,public_key=excluded.public_key,account_member_epoch=excluded.account_member_epoch,membership_epoch=excluded.membership_epoch,address_epoch=excluded.address_epoch,name=excluded.name,ipv4=excluded.ipv4,ipv6=excluded.ipv6,allocation_slot=excluded.allocation_slot,reserved=0,revoked=0",
            params![id,request.installation_id,identity.account,identity.public_key.as_slice(),identity.account_epoch,identity.membership_epoch,epoch,name,ipv4,ipv6,slot])?;
        advance_directory(&tx,id,request.expected_revision,now)?;
        event(&tx,actor,id,"space_address_issued",&request.installation_id,now)?;
        let view = self.address_directory_view(&tx,actor,space,now)?;
        tx.commit()?;
        Ok(view)
    }

    pub fn reserve_space_address(&mut self, actor: &Principal, id: &str, installation: &str, request: SpaceAddressReservation, now: u64) -> Result<SpaceAddressDirectory, StorageError> {
        require_id(installation)?;
        let (ipv4,ipv6) = addresses(&request.ipv4,&request.ipv6)?;
        let tx = Transaction::new_unchecked(&self.connection,TransactionBehavior::Immediate)?;
        self.validate_access(actor,now / 1000)?;
        let space = write_authority(&tx,actor,id,request.expected_revision,now)?;
        let row = stored(&tx,id,installation)?.ok_or(StorageError::Forbidden)?;
        if row.epoch != request.expected_address_epoch { return Err(StorageError::Conflict); }
        if !self.address_current(&tx,&space,&row,now)? { return Err(StorageError::Forbidden); }
        free(&tx,id,installation,&row.name,&ipv4,&ipv6)?;
        tx.execute("UPDATE network_space_addresses SET ipv4=?1,ipv6=?2,reserved=1,address_epoch=?3 WHERE space_id=?4 AND installation_id=?5", params![ipv4,ipv6,next_epoch(row.epoch)?,id,installation])?;
        advance_directory(&tx,id,request.expected_revision,now)?;
        event(&tx,actor,id,"space_address_reserved",installation,now)?;
        let view = self.address_directory_view(&tx,actor,space,now)?;
        tx.commit()?;
        Ok(view)
    }

    pub fn rename_space_address(&mut self, actor: &Principal, id: &str, installation: &str, request: SpaceAddressRename, now: u64) -> Result<SpaceAddressDirectory, StorageError> {
        require_id(installation)?;
        let name = label(&request.name)?;
        let tx = Transaction::new_unchecked(&self.connection,TransactionBehavior::Immediate)?;
        self.validate_access(actor,now / 1000)?;
        let space = write_authority(&tx,actor,id,request.expected_revision,now)?;
        let row = stored(&tx,id,installation)?.ok_or(StorageError::Forbidden)?;
        if row.epoch != request.expected_address_epoch { return Err(StorageError::Conflict); }
        if !self.address_current(&tx,&space,&row,now)? { return Err(StorageError::Forbidden); }
        free(&tx,id,installation,&name,&row.ipv4,&row.ipv6)?;
        tx.execute("UPDATE network_space_addresses SET name=?1,address_epoch=?2 WHERE space_id=?3 AND installation_id=?4", params![name,next_epoch(row.epoch)?,id,installation])?;
        advance_directory(&tx,id,request.expected_revision,now)?;
        event(&tx,actor,id,"space_address_renamed",installation,now)?;
        let view = self.address_directory_view(&tx,actor,space,now)?;
        tx.commit()?;
        Ok(view)
    }

    pub fn revoke_space_address(&mut self, actor: &Principal, id: &str, installation: &str, request: SpaceAddressRevocation, now: u64) -> Result<SpaceAddressDirectory, StorageError> {
        require_id(installation)?;
        let tx = Transaction::new_unchecked(&self.connection,TransactionBehavior::Immediate)?;
        self.validate_access(actor,now / 1000)?;
        let space = write_authority(&tx,actor,id,request.expected_revision,now)?;
        let row = stored(&tx,id,installation)?.ok_or(StorageError::Forbidden)?;
        if row.epoch != request.expected_address_epoch || row.revoked { return Err(StorageError::Conflict); }
        tx.execute("UPDATE network_space_addresses SET revoked=1,address_epoch=?1 WHERE space_id=?2 AND installation_id=?3", params![next_epoch(row.epoch)?,id,installation])?;
        advance_directory(&tx,id,request.expected_revision,now)?;
        event(&tx,actor,id,"space_address_revoked",installation,now)?;
        let view = self.address_directory_view(&tx,actor,space,now)?;
        tx.commit()?;
        Ok(view)
    }
}
