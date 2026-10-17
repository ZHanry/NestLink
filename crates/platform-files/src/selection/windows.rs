//! The only unsafe selector boundary: COM lifetime, modal dialog and OS string.
#![allow(unsafe_code)]
use super::SelectionKind;
use std::{io, path::PathBuf};
use windows::{
    Win32::{
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
            CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize,
        },
        UI::Shell::{
            FOS_DONTADDTORECENT, FOS_FILEMUSTEXIST, FOS_FORCEFILESYSTEM, FOS_NOCHANGEDIR,
            FOS_NODEREFERENCELINKS, FOS_PATHMUSTEXIST, FOS_PICKFOLDERS, FileOpenDialog,
            IFileOpenDialog, SIGDN_FILESYSPATH,
        },
    },
    core::{HRESULT, w},
};

struct Apartment;
impl Drop for Apartment {
    fn drop(&mut self) {
        // This guard never moves to another thread and outlives all interfaces.
        unsafe { CoUninitialize() };
    }
}
fn error<E>(_: E) -> io::Error {
    io::Error::other("the Windows file selector failed")
}

pub(super) fn choose(kind: SelectionKind) -> io::Result<Option<PathBuf>> {
    // The selector is entered before this helper process creates any GUI/COM
    // state. Every returned interface and string is released in this apartment.
    unsafe {
        CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)
            .ok()
            .map_err(error)?;
        let _apartment = Apartment;
        let dialog: IFileOpenDialog =
            CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER).map_err(error)?;
        let mut options = FOS_FORCEFILESYSTEM
            | FOS_PATHMUSTEXIST
            | FOS_FILEMUSTEXIST
            | FOS_NODEREFERENCELINKS
            | FOS_DONTADDTORECENT
            | FOS_NOCHANGEDIR;
        if kind == SelectionKind::Folder {
            options |= FOS_PICKFOLDERS;
        }
        dialog.SetOptions(options).map_err(error)?;
        dialog.SetTitle(w!("NestLink")).map_err(error)?;
        if let Err(failure) = dialog.Show(None) {
            // HRESULT_FROM_WIN32(ERROR_CANCELLED), not an OS/provider failure.
            if failure.code() == HRESULT(0x800704C7_u32 as i32) {
                return Ok(None);
            }
            return Err(error(failure));
        }
        let item = dialog.GetResult().map_err(error)?;
        let name = item.GetDisplayName(SIGDN_FILESYSPATH).map_err(error)?;
        let selected = name.to_string().map(PathBuf::from).map_err(error);
        CoTaskMemFree(Some(name.0.cast()));
        selected.map(Some)
    }
}
