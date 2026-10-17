use super::{AndroidManagementSession, lock};
use crate::{file_transfer::export_json, platform_clipboard::AndroidBrowserClipboardFactory};
use nestlink_app_core::{BrowserHostBinding, BrowserHostDataView};
use std::fs::File;

impl AndroidManagementSession {
    fn publish_browser_data(
        &self,
        binding: &BrowserHostBinding,
    ) -> Result<BrowserHostDataView, String> {
        let data = self.browser_data.view(&self.handle, binding)?;
        let snapshot = self.handle.snapshot();
        if snapshot
            .browser_host
            .data
            .as_ref()
            .is_none_or(|host| host.binding.as_ref() != Some(binding))
        {
            return Err("Android browser data proof was replaced".into());
        }
        if snapshot
            .browser_host
            .data
            .as_ref()
            .is_some_and(|host| host.data != data)
        {
            self.runtime
                .block_on(self.handle.update_browser_host_data(
                    binding.clone(),
                    snapshot.generation,
                    data.clone(),
                ))
                .map_err(|_| {
                    "Android browser data changed while publishing local approval".to_owned()
                })?;
        }
        Ok(data)
    }
    pub(crate) fn browser_data_json(&self, binding: &BrowserHostBinding) -> Result<String, String> {
        let data = self.publish_browser_data(binding)?;
        serde_json::to_string(&serde_json::json!({ "binding": binding, "data": data }))
            .map_err(|_| "Android browser data status is unavailable".to_owned())
    }
    pub(crate) fn browser_files_json(
        &self,
        binding: &BrowserHostBinding,
    ) -> Result<String, String> {
        let value = lock(&self.host_files, "Android host files are unavailable")?
            .browser_status(&self.handle, binding)?;
        self.publish_browser_data(binding)?;
        serde_json::to_string(&value)
            .map_err(|_| "Android browser file status is unavailable".to_owned())
    }
    pub(crate) fn browser_share_file(
        &self,
        binding: &BrowserHostBinding,
        grant: &str,
        name: String,
        source: File,
    ) -> Result<String, String> {
        lock(&self.host_files, "Android host files are unavailable")?.browser_share(
            &self.handle,
            binding,
            grant,
            name,
            source,
        )
    }
    pub(crate) fn browser_approve_receive(
        &self,
        binding: &BrowserHostBinding,
        approved: bool,
    ) -> Result<(), String> {
        lock(&self.host_files, "Android host files are unavailable")?.browser_approve_receive(
            &self.handle,
            binding,
            approved,
        )?;
        self.publish_browser_data(binding)?;
        Ok(())
    }
    pub(crate) fn browser_discard_file(
        &self,
        binding: &BrowserHostBinding,
        id: &str,
    ) -> Result<(), String> {
        lock(&self.host_files, "Android host files are unavailable")?.browser_discard(
            &self.handle,
            binding,
            id,
        )?;
        self.publish_browser_data(binding)?;
        Ok(())
    }
    pub(crate) fn browser_export_file(
        &self,
        binding: &BrowserHostBinding,
        grant: &str,
        id: &str,
        destination: File,
    ) -> Result<String, String> {
        let status = lock(&self.host_files, "Android host files are unavailable")?
            .browser_start_export(&self.handle, binding, grant, id, destination)?;
        serde_json::to_string(&export_json(&status))
            .map_err(|_| "Android browser export status is unavailable".to_owned())
    }
    pub(crate) fn browser_cancel_export(
        &self,
        binding: &BrowserHostBinding,
        id: &str,
    ) -> Result<(), String> {
        lock(&self.host_files, "Android host files are unavailable")?
            .browser_cancel_export(binding, id)
    }
    pub(crate) fn browser_export_status_json(
        &self,
        binding: &BrowserHostBinding,
        grant: &str,
    ) -> Result<String, String> {
        let status = lock(&self.host_files, "Android host files are unavailable")?
            .browser_export_status(&self.handle, binding, grant)?;
        serde_json::to_string(&status.as_ref().map(export_json))
            .map_err(|_| "Android browser export cleanup status is unavailable".to_owned())
    }
    pub(crate) fn browser_clipboard_set_directions(
        &self,
        binding: &BrowserHostBinding,
        read: bool,
        write: bool,
        factory: Option<AndroidBrowserClipboardFactory>,
    ) -> Result<String, String> {
        let _entered = self.runtime.enter();
        self.browser_data
            .set_directions(binding, read, write, factory)?;
        self.browser_data_json(binding)
    }
    pub(crate) fn browser_clipboard_platform_allowed(
        &self,
        binding: &BrowserHostBinding,
        read: bool,
    ) -> bool {
        self.browser_data.platform_allowed(binding, read)
    }
    pub(crate) fn browser_files_platform_allowed(
        &self,
        binding: &BrowserHostBinding,
        write: bool,
    ) -> bool {
        self.browser_data.files_platform_allowed(binding, write)
    }
}
