//! Exact PnP resource recovery through Windows SetupAPI. This module never
//! opens a Wintun session, scans for orphan removal, or deletes a driver.
#![allow(unsafe_code)]
use super::{ProviderIdentity, resources, security};
use serde::{Deserialize, Serialize};
use std::{
    io,
    mem::size_of,
    ptr::{null, null_mut},
};
use windows_sys::{
    Win32::{
        Devices::DeviceAndDriverInstallation::*,
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS},
        System::Registry::*,
    },
    core::GUID,
};

const MAX_DEVICES: u32 = 4096;
const MAX_CHARS: usize = 512;
fn wide(value: &str) -> io::Result<Vec<u16>> {
    if value.is_empty() || value.len() >= MAX_CHARS || value.contains('\0') {
        return Err(security::denied());
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}
fn bool_result(value: i32) -> io::Result<()> {
    if value == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn text(value: &[u16]) -> io::Result<String> {
    let Some((&0, body)) = value.split_last() else {
        return Err(security::denied());
    };
    if body.contains(&0) {
        return Err(security::denied());
    }
    String::from_utf16(body).map_err(|_| security::denied())
}
struct DeviceSet(HDEVINFO);
impl Drop for DeviceSet {
    fn drop(&mut self) {
        unsafe {
            SetupDiDestroyDeviceInfoList(self.0);
        }
    }
}
impl DeviceSet {
    fn checked(raw: HDEVINFO) -> io::Result<Self> {
        if raw == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(raw))
        }
    }
}
struct RegistryKey(HKEY);
impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
fn row() -> SP_DEVINFO_DATA {
    SP_DEVINFO_DATA {
        cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
        ClassGuid: GUID::from_u128(0),
        DevInst: 0,
        Reserved: 0,
    }
}
fn netcfg_guid(set: &DeviceSet, row: &SP_DEVINFO_DATA) -> io::Result<Option<String>> {
    let key = unsafe {
        SetupDiOpenDevRegKey(set.0, row, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_QUERY_VALUE)
    };
    if key as isize == -1 || key.is_null() {
        return Err(io::Error::last_os_error());
    }
    let key = RegistryKey(key);
    let name = wide("NetCfgInstanceId")?;
    let mut buffer = [0_u16; MAX_CHARS];
    let mut bytes = size_of::<[u16; MAX_CHARS]>() as u32;
    let result = unsafe {
        RegGetValueW(
            key.0,
            null(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if result == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    if bytes < 2 || bytes as usize > size_of::<[u16; MAX_CHARS]>() || !bytes.is_multiple_of(2) {
        return Err(security::denied());
    }
    let value = text(&buffer[..bytes as usize / 2])?;
    let guid = value
        .strip_prefix('{')
        .and_then(|v| v.strip_suffix('}'))
        .unwrap_or(&value)
        .to_ascii_lowercase();
    resources::guid_value(&guid)?;
    Ok(Some(guid))
}
fn instance_id(set: &DeviceSet, row: &SP_DEVINFO_DATA) -> io::Result<String> {
    let mut buffer = [0_u16; MAX_CHARS];
    let mut required = 0;
    bool_result(unsafe {
        SetupDiGetDeviceInstanceIdW(
            set.0,
            row,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut required,
        )
    })?;
    if required < 2 || required as usize > buffer.len() {
        return Err(security::denied());
    }
    let value = text(&buffer[..required as usize])?;
    if !value.to_ascii_uppercase().starts_with("SWD\\WINTUN\\") {
        return Err(security::denied());
    }
    Ok(value)
}
fn require_wintun(set: &DeviceSet, row: &SP_DEVINFO_DATA) -> io::Result<()> {
    let mut buffer = [0_u16; MAX_CHARS];
    let (mut kind, mut required) = (0, 0);
    bool_result(unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            set.0,
            row,
            SPDRP_HARDWAREID,
            &mut kind,
            buffer.as_mut_ptr().cast(),
            size_of::<[u16; MAX_CHARS]>() as u32,
            &mut required,
        )
    })?;
    if kind != REG_MULTI_SZ
        || required < 4
        || required as usize > size_of::<[u16; MAX_CHARS]>()
        || !required.is_multiple_of(2)
    {
        return Err(security::denied());
    }
    let units = &buffer[..required as usize / 2];
    if units.last() != Some(&0) || !text(&units[..units.len() - 1])?.eq_ignore_ascii_case("Wintun")
    {
        return Err(security::denied());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceInstance {
    instance_id: String,
    adapter_guid: String,
}
impl DeviceInstance {
    pub fn validate(&self, guid: &str) -> io::Result<()> {
        resources::guid_value(guid)?;
        if self.adapter_guid != guid
            || !self
                .instance_id
                .to_ascii_uppercase()
                .starts_with("SWD\\WINTUN\\")
        {
            return Err(security::denied());
        }
        wide(&self.instance_id)?;
        Ok(())
    }
}
pub fn capture(identity: &ProviderIdentity) -> io::Result<DeviceInstance> {
    resources::original(identity)?.ok_or_else(security::denied)?;
    let enumerator = wide("SWD\\Wintun")?;
    let set = DeviceSet::checked(unsafe {
        SetupDiGetClassDevsW(
            &GUID_DEVCLASS_NET,
            enumerator.as_ptr(),
            null_mut(),
            DIGCF_PRESENT,
        )
    })?;
    let mut found = None;
    for index in 0..MAX_DEVICES {
        let mut row = row();
        if unsafe { SetupDiEnumDeviceInfo(set.0, index, &mut row) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                resources::original(identity)?.ok_or_else(security::denied)?;
                return found
                    .ok_or_else(|| io::Error::other("original Wintun PnP instance missing"));
            }
            return Err(error);
        }
        if netcfg_guid(&set, &row)?.as_deref() != Some(identity.adapter_guid.as_str()) {
            continue;
        }
        if found.is_some() {
            return Err(security::denied());
        }
        require_wintun(&set, &row)?;
        found = Some(DeviceInstance {
            instance_id: instance_id(&set, &row)?,
            adapter_guid: identity.adapter_guid.clone(),
        });
    }
    Err(io::Error::other("Wintun PnP inventory exceeded its bound"))
}
/// Caller must first prove both original process incarnations are dead and
/// compare the durable resource snapshot. The retained SetupAPI element binds
/// removal to one device instance; no current-name provider session is adopted.
pub fn remove_original(identity: &ProviderIdentity, expected: &DeviceInstance) -> io::Result<()> {
    super::super::require_administrator_process()?;
    expected.validate(&identity.adapter_guid)?;
    resources::original(identity)?.ok_or_else(security::denied)?;
    let set =
        DeviceSet::checked(unsafe { SetupDiCreateDeviceInfoList(&GUID_DEVCLASS_NET, null_mut()) })?;
    let name = wide(&expected.instance_id)?;
    let mut row = row();
    bool_result(unsafe { SetupDiOpenDeviceInfoW(set.0, name.as_ptr(), null_mut(), 0, &mut row) })?;
    require_wintun(&set, &row)?;
    if instance_id(&set, &row)? != expected.instance_id
        || netcfg_guid(&set, &row)?.as_deref() != Some(identity.adapter_guid.as_str())
    {
        return Err(security::denied());
    }
    let parameters = SP_REMOVEDEVICE_PARAMS {
        ClassInstallHeader: SP_CLASSINSTALL_HEADER {
            cbSize: size_of::<SP_CLASSINSTALL_HEADER>() as u32,
            InstallFunction: DIF_REMOVE,
        },
        Scope: DI_REMOVEDEVICE_GLOBAL,
        HwProfile: 0,
    };
    bool_result(unsafe {
        SetupDiSetClassInstallParamsW(
            set.0,
            &row,
            &parameters.ClassInstallHeader,
            size_of::<SP_REMOVEDEVICE_PARAMS>() as u32,
        )
    })?;
    resources::original(identity)?.ok_or_else(security::denied)?;
    bool_result(unsafe { SetupDiCallClassInstaller(DIF_REMOVE, set.0, &row) })
}
