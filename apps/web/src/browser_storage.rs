//! Origin-private storage has one browser-managed lock for its entire owner
//! lifetime. A later page can recover leftovers only after the old page's lock
//! is released, including when the browser destroys a crashed execution context.
use crate::browser_rpc::BrowserRpcError;
use futures_channel::oneshot;
use js_sys::{Array, Function, Object, Promise, Reflect};
use std::{cell::RefCell, rc::Rc};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::{JsFuture, future_to_promise, spawn_local};

const STORAGE_NAME: &str = "nestlink-private-v15";
const RECOVERY_ENTRIES: usize = 64;

pub(crate) struct PrivateStorage {
    pub parent: JsValue,
    recovered: bool,
    recovery_iterator: Option<JsValue>,
    recovery_pending: Option<String>,
    release: Option<oneshot::Sender<()>>,
    stopped: Option<oneshot::Receiver<Result<(), BrowserRpcError>>>,
}

impl PrivateStorage {
    pub async fn open() -> Result<Self, BrowserRpcError> {
        let window = web_sys::window().ok_or(BrowserRpcError::Storage)?;
        let navigator = window.navigator();
        let manager = Reflect::get(navigator.as_ref(), &"locks".into())
            .map_err(|_| BrowserRpcError::Storage)?;
        let (granted, waiting) = oneshot::channel();
        let grant = Rc::new(RefCell::new(Some(granted)));
        let callback_grant = grant.clone();
        let (release, released) = oneshot::channel::<()>();
        let released = Rc::new(RefCell::new(Some(released)));
        let callback = Closure::<dyn FnMut(JsValue) -> Promise>::new(move |lock: JsValue| {
            let Some(granted) = callback_grant.borrow_mut().take() else {
                return Promise::reject(&JsValue::UNDEFINED);
            };
            if lock.is_null() || lock.is_undefined() {
                let _ = granted.send(Err(BrowserRpcError::Busy));
                return Promise::resolve(&JsValue::UNDEFINED);
            }
            let Some(released) = released.borrow_mut().take() else {
                let _ = granted.send(Err(BrowserRpcError::Storage));
                return Promise::reject(&JsValue::UNDEFINED);
            };
            // The pending callback Promise, rather than a page timer or stale
            // localStorage timestamp, is the browser's actual lock owner.
            let _ = granted.send(Ok(()));
            future_to_promise(async move {
                let _ = released.await;
                Ok(JsValue::UNDEFINED)
            })
        });
        let options = Object::new();
        set(&options, "mode", &"exclusive".into())?;
        set(&options, "ifAvailable", &true.into())?;
        let request = invoke(
            &manager,
            "request",
            &[
                STORAGE_NAME.into(),
                options.into(),
                callback.as_ref().clone(),
            ],
        )?
        .dyn_into::<Promise>()
        .map_err(|_| BrowserRpcError::Storage)?;
        let (completed, stopped) = oneshot::channel();
        // Retain the exact Closure and Promise through the real release. A
        // dropped UI waiter cannot invalidate an invoked JavaScript callback.
        spawn_local(async move {
            let result = JsFuture::from(request)
                .await
                .map(|_| ())
                .map_err(|_| BrowserRpcError::Storage);
            if let Some(granted) = grant.borrow_mut().take() {
                let _ = granted.send(Err(BrowserRpcError::Storage));
            }
            drop(callback);
            let _ = completed.send(result);
        });
        waiting.await.map_err(|_| BrowserRpcError::Storage)??;
        let mut owner = Self {
            parent: JsValue::UNDEFINED,
            recovered: false,
            recovery_iterator: None,
            recovery_pending: None,
            release: Some(release),
            stopped: Some(stopped),
        };
        let storage = Reflect::get(navigator.as_ref(), &"storage".into())
            .map_err(|_| BrowserRpcError::Storage)?;
        let root = call(&storage, "getDirectory", &[]).await?;
        let create = Object::new();
        set(&create, "create", &true.into())?;
        owner.parent = call(
            &root,
            "getDirectoryHandle",
            &[STORAGE_NAME.into(), create.into()],
        )
        .await?;
        Ok(owner)
    }

    pub async fn recover(&mut self) -> Result<(), BrowserRpcError> {
        if self.recovered {
            return Ok(());
        }
        if let Some(name) = &self.recovery_pending {
            remove_directory(&self.parent, name).await?;
            self.recovery_pending = None;
        }
        let iterator = match &self.recovery_iterator {
            Some(iterator) => iterator.clone(),
            None => {
                let iterator = invoke(&self.parent, "values", &[])?;
                self.recovery_iterator = Some(iterator.clone());
                iterator
            }
        };
        for _ in 0..RECOVERY_ENTRIES {
            let next = call(&iterator, "next", &[]).await?;
            if Reflect::get(&next, &"done".into())
                .map_err(|_| BrowserRpcError::Storage)?
                .as_bool()
                == Some(true)
            {
                self.recovered = true;
                self.recovery_iterator = None;
                return Ok(());
            }
            let entry =
                Reflect::get(&next, &"value".into()).map_err(|_| BrowserRpcError::Storage)?;
            let name = Reflect::get(&entry, &"name".into())
                .map_err(|_| BrowserRpcError::Storage)?
                .as_string()
                .ok_or(BrowserRpcError::Storage)?;
            let kind =
                Reflect::get(&entry, &"kind".into()).map_err(|_| BrowserRpcError::Storage)?;
            if kind.as_string().as_deref() == Some("directory") && owned_directory(&name) {
                self.recovery_pending = Some(name.clone());
                remove_directory(&self.parent, &name).await?;
                self.recovery_pending = None;
            }
        }
        // Bound each recovery pass and retain the same lock for a later retry.
        // No download may bypass leftovers that have not actually been removed.
        Err(BrowserRpcError::Capacity)
    }

    pub async fn close(&mut self) -> Result<(), BrowserRpcError> {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(stopped) = self.stopped.take() {
            stopped.await.map_err(|_| BrowserRpcError::Storage)??;
        }
        Ok(())
    }
}

impl Drop for PrivateStorage {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

fn owned_directory(name: &str) -> bool {
    uuid::Uuid::parse_str(name)
        .is_ok_and(|id| id.get_version_num() == 4 && id.hyphenated().to_string() == name)
}
pub(crate) async fn remove_directory(parent: &JsValue, name: &str) -> Result<(), BrowserRpcError> {
    if !owned_directory(name) {
        return Err(BrowserRpcError::Protocol);
    }
    let recursive = Object::new();
    set(&recursive, "recursive", &true.into())?;
    let promise = invoke(parent, "removeEntry", &[name.into(), recursive.into()])?
        .dyn_into::<Promise>()
        .map_err(|_| BrowserRpcError::Storage)?;
    match JsFuture::from(promise).await {
        Ok(_) => Ok(()),
        Err(error)
            if Reflect::get(&error, &"name".into())
                .ok()
                .and_then(|name| name.as_string())
                .as_deref()
                == Some("NotFoundError") =>
        {
            Ok(())
        }
        Err(_) => Err(BrowserRpcError::Storage),
    }
}
fn set(object: &Object, key: &str, value: &JsValue) -> Result<(), BrowserRpcError> {
    Reflect::set(object, &key.into(), value)
        .map(|_| ())
        .map_err(|_| BrowserRpcError::Storage)
}
fn invoke(object: &JsValue, method: &str, args: &[JsValue]) -> Result<JsValue, BrowserRpcError> {
    let function = Reflect::get(object, &method.into())
        .map_err(|_| BrowserRpcError::Storage)?
        .dyn_into::<Function>()
        .map_err(|_| BrowserRpcError::Storage)?;
    let arguments = Array::new();
    for arg in args {
        arguments.push(arg);
    }
    function
        .apply(object, &arguments)
        .map_err(|_| BrowserRpcError::Storage)
}
async fn call(
    object: &JsValue,
    method: &str,
    args: &[JsValue],
) -> Result<JsValue, BrowserRpcError> {
    let promise = invoke(object, method, args)?
        .dyn_into::<Promise>()
        .map_err(|_| BrowserRpcError::Storage)?;
    JsFuture::from(promise)
        .await
        .map_err(|_| BrowserRpcError::Storage)
}
