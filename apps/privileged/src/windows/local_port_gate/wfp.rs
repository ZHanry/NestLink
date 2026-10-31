//! Native WFP management adapter. WFP owns matching, arbitration and atomic
//! kernel transactions; no callout driver or custom packet parser is added.
#![allow(unsafe_code)]
use super::*;
use serde_json::json;
use std::{
    ffi::c_void,
    ptr::{null, null_mut},
};
use windows_sys::{
    Win32::{
        Foundation::{FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE},
        NetworkManagement::WindowsFilteringPlatform::*,
        Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW,
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetSecurityDescriptorControl,
            GetSecurityDescriptorLength, IsValidSecurityDescriptor, OWNER_SECURITY_INFORMATION,
            SE_SELF_RELATIVE,
        },
    },
    core::GUID,
};

fn result(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "WFP operation failed ({code:#x}); original gate/journal retained"
        )))
    }
}
struct Memory(*mut c_void);
impl Drop for Memory {
    fn drop(&mut self) {
        unsafe {
            FwpmFreeMemory0(&mut self.0);
        }
    }
}
#[derive(Clone, Copy)]
enum Object {
    Provider,
    Sublayer,
    Filter,
}
const AUTHORIZATION_SECURITY: u32 =
    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
pub(super) struct Engine(HANDLE);
impl Drop for Engine {
    fn drop(&mut self) {
        // This is deliberately a non-dynamic session. Closing the RPC handle
        // never removes the persistent gate protecting a still-live socket.
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}
impl Engine {
    pub fn open() -> io::Result<Self> {
        require_admin()?;
        let session = FWPM_SESSION0 {
            txnWaitTimeoutInMSec: 3000,
            ..FWPM_SESSION0::default()
        };
        let mut handle = null_mut();
        // SAFETY: local authenticated RPC, non-dynamic session and writable
        // handle. No remote host or delegated credentials are accepted.
        result(unsafe { FwpmEngineOpen0(null(), 10, null(), &session, &mut handle) })?;
        if handle.is_null() {
            return Err(invalid("WFP returned an empty engine handle"));
        }
        Ok(Self(handle))
    }
    fn transaction<T>(&self, operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        result(unsafe { FwpmTransactionBegin0(self.0, 0) })?;
        let outcome = operation();
        match outcome {
            Ok(value) => match result(unsafe { FwpmTransactionCommit0(self.0) }) {
                Ok(()) => Ok(value),
                Err(error) => {
                    unsafe {
                        FwpmTransactionAbort0(self.0);
                    }
                    Err(error)
                }
            },
            Err(error) => {
                unsafe {
                    FwpmTransactionAbort0(self.0);
                }
                Err(error)
            }
        }
    }
    pub fn install(&self, plan: &GatePlan) -> io::Result<Value> {
        self.transaction(|| {
            if self.inspect(plan)?.is_some() {
                return Err(invalid(
                    "WFP gate identity is occupied; existing policy is never adopted",
                ));
            }
            let mut objects = Objects::new(plan)?;
            let descriptor = store::descriptor(None, false)?;
            result(unsafe { FwpmProviderAdd0(self.0, &objects.provider(), descriptor.0) })?;
            result(unsafe { FwpmSubLayerAdd0(self.0, &objects.sublayer(), descriptor.0) })?;
            for kind in [Kind::Allow, Kind::Drop, Kind::Outside] {
                let filter = objects.filter(kind)?;
                let mut id = 0;
                result(unsafe { FwpmFilterAdd0(self.0, &filter, descriptor.0, &mut id) })?;
                if id == 0 {
                    return Err(invalid("WFP did not assign a filter identity"));
                }
            }
            let observed = self
                .inspect(plan)?
                .ok_or_else(|| invalid("WFP transaction readback missing"))?;
            verify(plan, &observed, false)?;
            Ok(())
        })?;
        self.inspect(plan)?
            .ok_or_else(|| invalid("committed WFP gate disappeared"))
    }
    pub fn deny(&self, plan: &GatePlan, installed: &Value) -> io::Result<Value> {
        self.transaction(|| {
            if self.inspect(plan)?.as_ref() != Some(installed) {
                return Err(invalid(
                    "WFP gate changed before deny; foreign policy preserved",
                ));
            }
            result(unsafe { FwpmFilterDeleteByKey0(self.0, &key(plan, 2)?) })
        })?;
        let observed = self
            .inspect(plan)?
            .ok_or_else(|| invalid("WFP deny gate disappeared"))?;
        verify_deny_transition(plan, installed, &observed)?;
        Ok(observed)
    }
    pub fn remove(&self, plan: &GatePlan, installed: &Value) -> io::Result<()> {
        self.transaction(|| {
            if self.inspect(plan)?.as_ref() != Some(installed) {
                return Err(invalid(
                    "WFP gate changed before cleanup; foreign policy preserved",
                ));
            }
            for filter in installed["filters"]
                .as_array()
                .ok_or_else(|| invalid("missing installed WFP filters"))?
            {
                let id = filter["filter_id"]
                    .as_u64()
                    .filter(|id| *id != 0)
                    .ok_or_else(|| invalid("missing original WFP filter ID"))?;
                result(unsafe { FwpmFilterDeleteById0(self.0, id) })?;
            }
            result(unsafe { FwpmSubLayerDeleteByKey0(self.0, &key(plan, 1)?) })?;
            result(unsafe { FwpmProviderDeleteByKey0(self.0, &key(plan, 0)?) })
        })
    }
    pub fn inspect(&self, plan: &GatePlan) -> io::Result<Option<Value>> {
        let mut provider = null_mut();
        let mut sublayer = null_mut();
        let provider_status =
            unsafe { FwpmProviderGetByKey0(self.0, &key(plan, 0)?, &mut provider) };
        let provider_memory = Memory(provider.cast());
        let layer_status = unsafe { FwpmSubLayerGetByKey0(self.0, &key(plan, 1)?, &mut sublayer) };
        let layer_memory = Memory(sublayer.cast());
        let mut filters = self.filters(plan)?;
        if provider_status == FWP_E_PROVIDER_NOT_FOUND as u32
            && layer_status == FWP_E_SUBLAYER_NOT_FOUND as u32
            && filters.is_empty()
        {
            return Ok(None);
        }
        result(provider_status)?;
        result(layer_status)?;
        if provider.is_null() || sublayer.is_null() {
            return Err(invalid("WFP readback missing owned objects"));
        }
        filters.sort_by_key(|filter| filter["key"].as_str().unwrap_or("").to_owned());
        // SAFETY: successful WFP queries return complete structures whose
        // allocations remain owned until these copied observations are built.
        let mut provider_snapshot = unsafe { read_provider(&*provider)? };
        provider_snapshot["security"] = self.security(Object::Provider, &key(plan, 0)?)?;
        let mut sublayer_snapshot = unsafe { read_sublayer(&*sublayer)? };
        sublayer_snapshot["security"] = self.security(Object::Sublayer, &key(plan, 1)?)?;
        let observed =
            json!({"provider":provider_snapshot,"sublayer":sublayer_snapshot,"filters":filters});
        drop(provider_memory);
        drop(layer_memory);
        Ok(Some(observed))
    }
    fn security(&self, kind: Object, key: &GUID) -> io::Result<Value> {
        let mut descriptor = null_mut();
        // SAFETY: a fixed key in this engine, read-only OWNER/GROUP/DACL
        // request, and one writable allocation output. No audit privilege or
        // impersonation is added. Every pointer stays within this call frame.
        let status = unsafe {
            match kind {
                Object::Provider => FwpmProviderGetSecurityInfoByKey0(
                    self.0,
                    key,
                    AUTHORIZATION_SECURITY,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    &mut descriptor,
                ),
                Object::Sublayer => FwpmSubLayerGetSecurityInfoByKey0(
                    self.0,
                    key,
                    AUTHORIZATION_SECURITY,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    &mut descriptor,
                ),
                Object::Filter => FwpmFilterGetSecurityInfoByKey0(
                    self.0,
                    key,
                    AUTHORIZATION_SECURITY,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    &mut descriptor,
                ),
            }
        };
        let _allocation = Memory(descriptor);
        result(status)?;
        read_security(descriptor)
    }
    fn filters(&self, plan: &GatePlan) -> io::Result<Vec<Value>> {
        let mut cursor = null_mut();
        result(unsafe { FwpmFilterCreateEnumHandle0(self.0, null(), &mut cursor) })?;
        struct Cursor(HANDLE, HANDLE);
        impl Drop for Cursor {
            fn drop(&mut self) {
                unsafe {
                    FwpmFilterDestroyEnumHandle0(self.0, self.1);
                }
            }
        }
        let _cursor = Cursor(self.0, cursor);
        let mut filters = Vec::new();
        let mut total = 0usize;
        loop {
            let mut entries = null_mut();
            let mut count = 0;
            result(unsafe { FwpmFilterEnum0(self.0, cursor, 256, &mut entries, &mut count) })?;
            let _memory = Memory(entries.cast());
            total = total.saturating_add(count as usize);
            if count > 256 || total > 65_536 || count != 0 && entries.is_null() {
                return Err(invalid("WFP inventory exceeds bounded observation"));
            }
            if count == 0 {
                break;
            }
            // Enumerating the complete engine also sees foreign-provider
            // filters inserted in our sublayer. They are never ignored/adopted.
            for entry in unsafe { std::slice::from_raw_parts(entries, count as usize) } {
                if entry.is_null() {
                    return Err(invalid("empty WFP filter entry"));
                }
                let filter = unsafe { &**entry };
                let owned_provider = !filter.providerKey.is_null()
                    && same_guid(unsafe { &*filter.providerKey }, &key(plan, 0)?);
                if owned_provider || same_guid(&filter.subLayerKey, &key(plan, 1)?) {
                    let mut snapshot = read_filter(filter)?;
                    snapshot["security"] = self.security(Object::Filter, &filter.filterKey)?;
                    filters.push(snapshot);
                    if filters.len() > 8 {
                        return Err(invalid("unexpected objects in the owned WFP gate"));
                    }
                }
            }
        }
        Ok(filters)
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Allow,
    Drop,
    Outside,
}
impl Kind {
    fn id(self) -> u128 {
        match self {
            Self::Allow => 2,
            Self::Drop => 3,
            Self::Outside => 4,
        }
    }
    fn weight(self) -> u64 {
        match self {
            Self::Allow => 200,
            _ => 100,
        }
    }
}
struct Objects<'a> {
    plan: &'a GatePlan,
    provider_key: GUID,
    layer_key: GUID,
    marker: Vec<u16>,
    names: [Vec<u16>; 3],
    data: Vec<u8>,
    sid: security::Local,
    sid_blob: FWP_BYTE_BLOB,
    ip6: FWP_BYTE_ARRAY16,
    weight: u64,
    conditions: Vec<FWPM_FILTER_CONDITION0>,
}
impl<'a> Objects<'a> {
    fn new(plan: &'a GatePlan) -> io::Result<Self> {
        let sddl = security::text(&format!("D:P(A;;0x1;;;{})", plan.process.sid))?;
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
            || descriptor.is_null()
        {
            return Err(io::Error::last_os_error());
        }
        let sid = security::Local(descriptor);
        let size = unsafe { GetSecurityDescriptorLength(sid.0) };
        Ok(Self {
            plan,
            provider_key: key(plan, 0)?,
            layer_key: key(plan, 1)?,
            marker: security::text(&plan.marker())?,
            names: [
                security::text(&format!("{}:allow", plan.marker()))?,
                security::text(&format!("{}:drop", plan.marker()))?,
                security::text(&format!("{}:outside", plan.marker()))?,
            ],
            data: serde_json::to_vec(plan)?,
            sid_blob: FWP_BYTE_BLOB {
                size,
                data: sid.0.cast(),
            },
            sid,
            ip6: FWP_BYTE_ARRAY16 {
                byteArray16: match plan.endpoint.ip() {
                    std::net::IpAddr::V6(ip) => ip.octets(),
                    _ => [0; 16],
                },
            },
            weight: 0,
            conditions: Vec::new(),
        })
    }
    fn data(&mut self) -> FWP_BYTE_BLOB {
        FWP_BYTE_BLOB {
            size: self.data.len() as u32,
            data: self.data.as_mut_ptr(),
        }
    }
    fn provider(&mut self) -> FWPM_PROVIDER0 {
        FWPM_PROVIDER0 {
            providerKey: self.provider_key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: self.marker.as_mut_ptr(),
                description: null_mut(),
            },
            flags: FWPM_PROVIDER_FLAG_PERSISTENT,
            providerData: self.data(),
            serviceName: null_mut(),
        }
    }
    fn sublayer(&mut self) -> FWPM_SUBLAYER0 {
        FWPM_SUBLAYER0 {
            subLayerKey: self.layer_key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: self.marker.as_mut_ptr(),
                description: null_mut(),
            },
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: &mut self.provider_key,
            providerData: self.data(),
            weight: u16::MAX,
        }
    }
    fn filter(&mut self, kind: Kind) -> io::Result<FWPM_FILTER0> {
        self.conditions.clear();
        self.weight = kind.weight();
        let outside = matches!(kind, Kind::Outside);
        let address = match self.plan.endpoint.ip() {
            std::net::IpAddr::V4(ip) => FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint32: u32::from_be_bytes(ip.octets()),
                },
            },
            std::net::IpAddr::V6(_) => FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_ARRAY16_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteArray16: &mut self.ip6,
                },
            },
        };
        self.conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: if outside {
                FWPM_CONDITION_IP_LOCAL_ADDRESS
            } else {
                FWPM_CONDITION_IP_REMOTE_ADDRESS
            },
            matchType: FWP_MATCH_EQUAL,
            conditionValue: address,
        });
        self.conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: if outside {
                FWPM_CONDITION_IP_LOCAL_PORT
            } else {
                FWPM_CONDITION_IP_REMOTE_PORT
            },
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint16: self.plan.endpoint.port(),
                },
            },
        });
        self.conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_PROTOCOL,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint8: self.plan.transport.number(),
                },
            },
        });
        if matches!(kind, Kind::Allow) {
            self.conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_USER_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        sd: &mut self.sid_blob,
                    },
                },
            });
        } else if outside {
            self.conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_FLAGS,
                matchType: FWP_MATCH_FLAGS_NONE_SET,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT32,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                    },
                },
            });
        }
        let index = kind.id() as usize - 2;
        let weight = FWP_VALUE0 {
            r#type: FWP_UINT64,
            Anonymous: FWP_VALUE0_0 {
                uint64: &mut self.weight,
            },
        };
        let filter = FWPM_FILTER0 {
            filterKey: key(self.plan, kind.id())?,
            displayData: FWPM_DISPLAY_DATA0 {
                name: self.names[index].as_mut_ptr(),
                description: null_mut(),
            },
            flags: FWPM_FILTER_FLAG_PERSISTENT,
            providerKey: &mut self.provider_key,
            providerData: self.data(),
            layerKey: match (outside, self.plan.endpoint.is_ipv4()) {
                (false, true) => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                (false, false) => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                (true, true) => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                (true, false) => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            },
            subLayerKey: self.layer_key,
            weight,
            numFilterConditions: self.conditions.len() as u32,
            filterCondition: self.conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: if matches!(kind, Kind::Allow) {
                    FWP_ACTION_PERMIT
                } else {
                    FWP_ACTION_BLOCK
                },
                ..FWPM_ACTION0::default()
            },
            effectiveWeight: weight,
            ..FWPM_FILTER0::default()
        };
        let _keep_descriptor = &self.sid;
        Ok(filter)
    }
}
fn key(plan: &GatePlan, part: u128) -> io::Result<GUID> {
    let value =
        u128::from_str_radix(&plan.owner_id.replace('-', ""), 16).map_err(io::Error::other)?;
    Ok(GUID::from_u128(value ^ part))
}
fn same_guid(a: &GUID, b: &GUID) -> bool {
    guid(a) == guid(b)
}
fn guid(value: &GUID) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        value.data1,
        value.data2,
        value.data3,
        value.data4[0],
        value.data4[1],
        installation::hex(&value.data4[2..])
    )
}
fn text(pointer: *const u16) -> io::Result<String> {
    if pointer.is_null() {
        return Ok(String::new());
    }
    let mut length = 0;
    // SAFETY: strings originate in complete WFP RPC allocations or the live
    // bounded Objects buffers, and remain alive through this conversion.
    while length < 32768 && unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    if length == 32768 {
        return Err(invalid("WFP display name exceeds bound"));
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(pointer, length) })
        .map_err(io::Error::other)
}
fn blob(value: &FWP_BYTE_BLOB) -> io::Result<String> {
    if value.size > MAXIMUM_JSON as u32 || value.size != 0 && value.data.is_null() {
        return Err(invalid("invalid WFP blob"));
    }
    if value.size == 0 {
        return Ok(String::new());
    }
    Ok(installation::hex(unsafe {
        std::slice::from_raw_parts(value.data, value.size as usize)
    }))
}
fn optional_guid(pointer: *const GUID) -> Option<String> {
    if pointer.is_null() {
        None
    } else {
        Some(guid(unsafe { &*pointer }))
    }
}
fn read_provider(value: &FWPM_PROVIDER0) -> io::Result<Value> {
    Ok(
        json!({"key":guid(&value.providerKey),"name":text(value.displayData.name)?,"description":text(value.displayData.description)?,"flags":value.flags,"data":blob(&value.providerData)?,"service":text(value.serviceName)?}),
    )
}
fn read_sublayer(value: &FWPM_SUBLAYER0) -> io::Result<Value> {
    Ok(
        json!({"key":guid(&value.subLayerKey),"name":text(value.displayData.name)?,"description":text(value.displayData.description)?,"flags":value.flags,"provider":optional_guid(value.providerKey),"data":blob(&value.providerData)?,"weight":value.weight}),
    )
}
fn read_security(descriptor: *mut c_void) -> io::Result<Value> {
    if descriptor.is_null() || unsafe { IsValidSecurityDescriptor(descriptor) } == 0 {
        return Err(invalid("invalid owned WFP security descriptor"));
    }
    let length = unsafe { GetSecurityDescriptorLength(descriptor) };
    if length < 20 || length > MAXIMUM_JSON as u32 {
        return Err(invalid("owned WFP security descriptor exceeds its bound"));
    }
    let mut control = 0u16;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sddl = null_mut();
    // Windows performs canonical semantic serialization, preserving owner,
    // group, DACL protection and every ACE's type/flags/mask/SID/order. This
    // avoids treating RPC-relative pointer offsets as security policy. Audit
    // SACLs do not grant admission and require a separate auditing privilege.
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            AUTHORIZATION_SECURITY,
            &mut sddl,
            null_mut(),
        )
    } == 0
        || sddl.is_null()
    {
        return Err(io::Error::last_os_error());
    }
    let _allocation = security::Local(sddl.cast());
    Ok(json!({"revision":revision,"control":control & !SE_SELF_RELATIVE,"sddl":text(sddl)?}))
}
fn weight(value: &FWP_VALUE0) -> io::Result<u64> {
    if value.r#type != FWP_UINT64 || unsafe { value.Anonymous.uint64 }.is_null() {
        return Err(invalid("WFP weight differs from exact gate"));
    }
    Ok(unsafe { *value.Anonymous.uint64 })
}
fn read_condition(value: &FWPM_FILTER_CONDITION0) -> io::Result<Value> {
    let data = &value.conditionValue;
    let observed = unsafe {
        match data.r#type {
            FWP_UINT8 => json!(data.Anonymous.uint8),
            FWP_UINT16 => json!(data.Anonymous.uint16),
            FWP_UINT32 => json!(data.Anonymous.uint32),
            FWP_BYTE_ARRAY16_TYPE if !data.Anonymous.byteArray16.is_null() => {
                json!((*data.Anonymous.byteArray16).byteArray16)
            }
            FWP_SECURITY_DESCRIPTOR_TYPE if !data.Anonymous.sd.is_null() => {
                json!(blob(&*data.Anonymous.sd)?)
            }
            _ => return Err(invalid("unknown condition type in owned WFP gate")),
        }
    };
    Ok(
        json!({"field":guid(&value.fieldKey),"match":value.matchType,"type":data.r#type,"value":observed}),
    )
}
fn read_filter(value: &FWPM_FILTER0) -> io::Result<Value> {
    if value.numFilterConditions > 8
        || value.numFilterConditions != 0 && value.filterCondition.is_null()
    {
        return Err(invalid("invalid WFP conditions"));
    }
    let mut conditions = Vec::new();
    if value.numFilterConditions != 0 {
        for condition in unsafe {
            std::slice::from_raw_parts(value.filterCondition, value.numFilterConditions as usize)
        } {
            conditions.push(read_condition(condition)?);
        }
    }
    conditions.sort_by_key(|condition| condition["field"].as_str().unwrap_or("").to_owned());
    Ok(
        json!({"key":guid(&value.filterKey),"name":text(value.displayData.name)?,"description":text(value.displayData.description)?,"flags":value.flags,"provider":optional_guid(value.providerKey),"data":blob(&value.providerData)?,
        "layer":guid(&value.layerKey),"sublayer":guid(&value.subLayerKey),"weight":weight(&value.weight)?,"conditions":conditions,
        "action":value.action.r#type,"action_key":guid(unsafe {&value.action.Anonymous.filterType}),"context":unsafe {value.Anonymous.rawContext},"reserved":optional_guid(value.reserved),"filter_id":value.filterId,"effective_weight":weight(&value.effectiveWeight)?}),
    )
}
fn expected(plan: &GatePlan, denying: bool) -> io::Result<Value> {
    let mut objects = Objects::new(plan)?;
    let descriptor = store::descriptor(None, false)?;
    let security = read_security(descriptor.0)?;
    let mut provider = read_provider(&objects.provider())?;
    provider["security"] = security.clone();
    let mut sublayer = read_sublayer(&objects.sublayer())?;
    sublayer["security"] = security.clone();
    let mut filters = Vec::new();
    for kind in [Kind::Allow, Kind::Drop, Kind::Outside] {
        if denying && matches!(kind, Kind::Allow) {
            continue;
        }
        let mut snapshot = read_filter(&objects.filter(kind)?)?;
        snapshot["security"] = security.clone();
        filters.push(snapshot);
    }
    filters.sort_by_key(|filter| filter["key"].as_str().unwrap_or("").to_owned());
    Ok(json!({"provider":provider,"sublayer":sublayer,"filters":filters}))
}
pub(super) fn verify(plan: &GatePlan, observed: &Value, denying: bool) -> io::Result<()> {
    let mut normalized = observed.clone();
    let filters = normalized["filters"]
        .as_array_mut()
        .ok_or_else(|| invalid("WFP snapshot missing filters"))?;
    let mut ids = std::collections::BTreeSet::new();
    for filter in filters {
        let id = filter["filter_id"]
            .as_u64()
            .filter(|id| *id != 0)
            .ok_or_else(|| invalid("WFP snapshot missing positive filter ID"))?;
        if !ids.insert(id) {
            return Err(invalid("duplicate WFP filter IDs"));
        }
        filter["filter_id"] = json!(0);
    }
    if normalized != expected(plan, denying)? {
        return Err(invalid(
            "WFP gate does not match the complete planned SID/endpoint/protocol policy",
        ));
    }
    Ok(())
}
pub(super) fn verify_deny_transition(
    plan: &GatePlan,
    before: &Value,
    current: &Value,
) -> io::Result<()> {
    verify(plan, before, false)?;
    verify(plan, current, true)?;
    let mut expected = before.clone();
    let allow = guid(&key(plan, 2)?);
    expected["filters"]
        .as_array_mut()
        .ok_or_else(|| invalid("missing original WFP filters"))?
        .retain(|filter| filter["key"] != allow);
    if expected != *current {
        return Err(invalid(
            "WFP deny recovery changed original object identities; preserve it",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn installed(plan: &GatePlan, denied: bool) -> io::Result<Value> {
        let mut value = expected(plan, denied)?;
        for (index, filter) in value["filters"]
            .as_array_mut()
            .ok_or_else(|| invalid("missing test filters"))?
            .iter_mut()
            .enumerate()
        {
            filter["filter_id"] = json!(100 + index as u64);
        }
        Ok(value)
    }
    #[test]
    fn complete_native_policy_binds_sid_endpoint_transport_and_admin_objects() -> io::Result<()> {
        let plan = super::super::tests::plan()?;
        let value = installed(&plan, false)?;
        verify(&plan, &value, false)?;
        assert_eq!(value["filters"].as_array().map(Vec::len), Some(3));
        assert_eq!(value["provider"]["flags"], FWPM_PROVIDER_FLAG_PERSISTENT);
        assert_eq!(value["sublayer"]["weight"], u16::MAX);
        let mut changed = plan.clone();
        changed.process.sid = "S-1-5-21-1-2-3-1002".into();
        assert!(verify(&changed, &value, false).is_err());
        changed = plan.clone();
        changed.endpoint.set_port(34568);
        assert!(verify(&changed, &value, false).is_err());
        changed = plan.clone();
        changed.transport = Transport::Udp;
        assert!(verify(&changed, &value, false).is_err());
        changed = plan;
        changed.endpoint = SocketAddr::from((Ipv6Addr::LOCALHOST, 34567));
        changed.transport = Transport::Udp;
        verify(&changed, &installed(&changed, false)?, false)?;
        Ok(())
    }
    #[test]
    fn sid_permit_and_hard_blocks_use_native_ale_conditions() -> io::Result<()> {
        let plan = super::super::tests::plan()?;
        let value = installed(&plan, false)?;
        let filters = value["filters"]
            .as_array()
            .ok_or_else(|| invalid("test filters missing"))?;
        let allow_key = guid(&key(&plan, 2)?);
        let allow = filters
            .iter()
            .find(|filter| filter["key"] == allow_key)
            .ok_or_else(|| invalid("test permit missing"))?;
        assert_eq!(allow["action"], FWP_ACTION_PERMIT);
        assert_eq!(allow["layer"], guid(&FWPM_LAYER_ALE_AUTH_CONNECT_V4));
        assert_eq!(allow["weight"], 200);
        let conditions = allow["conditions"]
            .as_array()
            .ok_or_else(|| invalid("test conditions missing"))?;
        let sid = conditions
            .iter()
            .find(|condition| condition["field"] == guid(&FWPM_CONDITION_ALE_USER_ID))
            .ok_or_else(|| invalid("test SID missing"))?;
        assert_eq!(sid["match"], FWP_MATCH_EQUAL);
        assert_eq!(sid["type"], FWP_SECURITY_DESCRIPTOR_TYPE);
        let outside_key = guid(&key(&plan, 4)?);
        let outside = filters
            .iter()
            .find(|filter| filter["key"] == outside_key)
            .ok_or_else(|| invalid("test outside fence missing"))?;
        assert_eq!(outside["action"], FWP_ACTION_BLOCK);
        assert_eq!(outside["layer"], guid(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4));
        let flags = outside["conditions"]
            .as_array()
            .ok_or_else(|| invalid("test flags missing"))?
            .iter()
            .find(|condition| condition["field"] == guid(&FWPM_CONDITION_FLAGS))
            .ok_or_else(|| invalid("test flags missing"))?;
        assert_eq!(flags["match"], FWP_MATCH_FLAGS_NONE_SET);
        assert_eq!(flags["value"], FWP_CONDITION_FLAG_IS_LOOPBACK);
        Ok(())
    }
    #[test]
    fn changed_or_foreign_objects_and_duplicate_filter_ids_are_rejected() -> io::Result<()> {
        let plan = super::super::tests::plan()?;
        let value = installed(&plan, false)?;
        for field in [
            "layer",
            "sublayer",
            "provider",
            "name",
            "data",
            "action",
            "weight",
            "effective_weight",
            "context",
            "flags",
            "reserved",
        ] {
            let mut changed = value.clone();
            changed["filters"][0][field] = json!("foreign");
            assert!(
                verify(&plan, &changed, false).is_err(),
                "changed filter field {field}"
            );
        }
        let mut changed = value.clone();
        changed["provider"]["service"] = json!("foreign-service");
        assert!(verify(&plan, &changed, false).is_err());
        changed = value.clone();
        changed["filters"][1]["filter_id"] = changed["filters"][0]["filter_id"].clone();
        assert!(verify(&plan, &changed, false).is_err());
        changed = value;
        changed["filters"]
            .as_array_mut()
            .ok_or_else(|| invalid("test filters missing"))?
            .push(json!({"filter_id":999}));
        assert!(verify(&plan, &changed, false).is_err());
        Ok(())
    }
    #[test]
    fn native_object_acl_owner_group_and_protection_changes_are_foreign() -> io::Result<()> {
        let plan = super::super::tests::plan()?;
        let value = installed(&plan, false)?;
        let original = value["provider"]["security"].clone();
        let descriptor = store::descriptor(None, false)?;
        assert_eq!(read_security(descriptor.0)?, original);
        for sddl in [
            "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;AU)",
            "O:SYG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
            "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)",
            "O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)",
            "O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)",
        ] {
            let text = security::text(sddl)?;
            let mut raw = null_mut();
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    SDDL_REVISION_1,
                    &mut raw,
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let descriptor = security::Local(raw);
            let changed = read_security(descriptor.0)?;
            assert_ne!(
                changed, original,
                "changed native authorization descriptor {sddl}"
            );
            for object in ["provider", "sublayer"] {
                let mut snapshot = value.clone();
                snapshot[object]["security"] = changed.clone();
                assert!(
                    verify(&plan, &snapshot, false).is_err(),
                    "changed {object} authorization"
                );
            }
            let mut snapshot = value.clone();
            snapshot["filters"][0]["security"] = changed;
            assert!(
                verify(&plan, &snapshot, false).is_err(),
                "changed filter authorization"
            );
        }
        Ok(())
    }
    #[test]
    fn deny_crash_recovery_retains_original_block_filter_ids() -> io::Result<()> {
        let plan = super::super::tests::plan()?;
        let before = installed(&plan, false)?;
        let mut current = before.clone();
        let allow = guid(&key(&plan, 2)?);
        current["filters"]
            .as_array_mut()
            .ok_or_else(|| invalid("test filters missing"))?
            .retain(|filter| filter["key"] != allow);
        verify_deny_transition(&plan, &before, &current)?;
        let mut recreated = current.clone();
        recreated["filters"][0]["filter_id"] = json!(9000);
        // The same textual rule with a newly allocated kernel ID is foreign.
        verify(&plan, &recreated, true)?;
        assert!(verify_deny_transition(&plan, &before, &recreated).is_err());
        assert!(verify_deny_transition(&plan, &before, &before).is_err());
        let mut changed_acl = current.clone();
        changed_acl["filters"][0]["security"]["sddl"] = json!("foreign ACL");
        assert!(verify_deny_transition(&plan, &before, &changed_acl).is_err());
        current["sublayer"]["weight"] = json!(10);
        assert!(verify_deny_transition(&plan, &before, &current).is_err());
        Ok(())
    }
}
