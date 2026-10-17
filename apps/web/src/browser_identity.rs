//! A browser controller is one persistent installation per management account.
//! Its Ed25519 seed is encrypted by a non-extractable WebCrypto key kept in
//! IndexedDB; the seed itself is never written to browser storage.

use futures_channel::oneshot;
use js_sys::{Array, Function, Object, Promise, Reflect, Uint8Array};
use nestlink_auth::{random_bytes, random_id};
use nestlink_identity::InstallationIdentity;
use nestlink_sdk::{DeviceIdentity, Sdk, SdkError};
use std::{cell::RefCell, rc::Rc};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::{JsFuture, future_to_promise, spawn_local};
use web_sys::{CryptoKey, Event, IdbDatabase, IdbRequest, IdbTransaction, IdbTransactionMode};
use zeroize::Zeroizing;

const DATABASE: &str = "nestlink-control-identity-v1";
const STORE: &str = "identities";

#[derive(Debug, thiserror::Error)]
pub enum BrowserIdentityError {
    #[error("browser identity storage is unavailable")]
    Storage,
    #[error("the saved browser identity is invalid; its key was left untouched")]
    Corrupt,
    #[error("this browser identity was revoked; remove it only after reviewing the device list")]
    Revoked,
    #[error("the saved browser identity does not match the registered device")]
    Mismatch,
    #[error(transparent)]
    Management(#[from] SdkError),
}

/// Load the account-scoped identity, creating an encrypted one only when the
/// browser has no record. Device registration is permanent and can be revoked
/// from the normal device-management page.
pub async fn load_or_register(sdk: &mut Sdk) -> Result<DeviceIdentity, BrowserIdentityError> {
    let principal = sdk.principal().ok_or(SdkError::SignIn)?;
    let slot = format!("{}:{}", sdk.health().deployment_id, principal.account_id);
    let _lock = IdentityLock::acquire(&slot).await?;
    let identity = load_or_create_locked(&slot).await?;
    ensure_registered(sdk, &identity).await?;
    Ok(identity)
}

/// Storage-only entry used by the browser verification build. The production
/// caller additionally validates or enrolls the returned key with the server.
pub async fn load_or_create(scope: &str) -> Result<DeviceIdentity, BrowserIdentityError> {
    let _lock = IdentityLock::acquire(scope).await?;
    load_or_create_locked(scope).await
}

async fn load_or_create_locked(scope: &str) -> Result<DeviceIdentity, BrowserIdentityError> {
    if scope.is_empty() || scope.len() > 256 || scope.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(BrowserIdentityError::Corrupt);
    }
    let db = open_database().await?;
    let result = async {
        let saved = read_record(&db, scope).await?;
        match saved {
            Some(record) => decrypt_record(scope, record).await,
            None => {
                let mut seed = Zeroizing::new(random_bytes::<32>());
                let device_id = random_id();
                let db_record = encrypt_record(scope, &device_id, &seed).await?;
                write_record(&db, scope, &db_record).await?;
                Ok(DeviceIdentity {
                    device_id,
                    identity: InstallationIdentity::from_seed_zeroizing(&mut seed),
                })
            }
        }
    }
    .await;
    db.close();
    result
}

async fn ensure_registered(
    sdk: &mut Sdk,
    identity: &DeviceIdentity,
) -> Result<(), BrowserIdentityError> {
    let devices = sdk.devices().await?;
    let existing = devices
        .iter()
        .find(|entry| entry.device.id == identity.device_id);
    if let Some(entry) = existing {
        if entry.revoked {
            return Err(BrowserIdentityError::Revoked);
        }
        let expected = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            identity.identity.public_key(),
        );
        if entry.device.platform != "web"
            || entry.device.public_key != expected
            || !entry
                .device
                .capabilities
                .iter()
                .any(|value| value == "controller")
            || !entry.device.capabilities.iter().any(|value| value == "vp8")
            || entry
                .device
                .capabilities
                .iter()
                .any(|value| value == "host")
        {
            return Err(BrowserIdentityError::Mismatch);
        }
        return Ok(());
    }

    // A second tab can finish enrollment between the list call and POST. The
    // Web Lock serializes this origin's tabs, while this read-after-error also
    // keeps recovery safe if a browser loses its lock service mid-request.
    let enrolled = sdk
        .enroll(
            identity,
            "NestLink Web controller".into(),
            "web".into(),
            vec!["controller".into(), "vp8".into()],
            "direct_preferred".into(),
        )
        .await;
    if enrolled.is_ok() {
        return Ok(());
    }
    let devices = sdk.devices().await?;
    if devices.iter().any(|entry| {
        entry.device.id == identity.device_id
            && !entry.revoked
            && entry.device.platform == "web"
            && entry.device.public_key
                == base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    identity.identity.public_key(),
                )
            && entry
                .device
                .capabilities
                .iter()
                .any(|value| value == "controller")
            && entry.device.capabilities.iter().any(|value| value == "vp8")
            && entry
                .device
                .capabilities
                .iter()
                .all(|value| value != "host")
    }) {
        Ok(())
    } else {
        Err(BrowserIdentityError::Management(
            enrolled.err().ok_or(SdkError::Trust)?,
        ))
    }
}

struct StoredRecord {
    device_id: String,
    key: CryptoKey,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
}

async fn open_database() -> Result<IdbDatabase, BrowserIdentityError> {
    let window = web_sys::window().ok_or(BrowserIdentityError::Storage)?;
    let factory = window
        .indexed_db()
        .map_err(|_| BrowserIdentityError::Storage)?
        .ok_or(BrowserIdentityError::Storage)?;
    let request = factory
        .open_with_u32(DATABASE, 1)
        .map_err(|_| BrowserIdentityError::Storage)?;
    let upgrade_request = request.clone();
    let upgrade = Closure::<dyn FnMut(Event)>::new(move |_| {
        let Ok(value) = upgrade_request.result() else {
            return;
        };
        let Ok(db) = value.dyn_into::<IdbDatabase>() else {
            return;
        };
        let _ = db.create_object_store(STORE);
    });
    request.set_onupgradeneeded(Some(upgrade.as_ref().unchecked_ref()));
    let result = wait_request(request.unchecked_ref()).await;
    request.set_onupgradeneeded(None);
    drop(upgrade);
    let db = result
        .map_err(|_| BrowserIdentityError::Storage)?
        .dyn_into::<IdbDatabase>()
        .map_err(|_| BrowserIdentityError::Storage)?;
    Ok(db)
}

async fn read_record(
    db: &IdbDatabase,
    scope: &str,
) -> Result<Option<StoredRecord>, BrowserIdentityError> {
    let tx = db
        .transaction_with_str_and_mode(STORE, IdbTransactionMode::Readonly)
        .map_err(|_| BrowserIdentityError::Storage)?;
    let completion = TransactionCompletion::attach(tx.clone())?;
    let store = tx
        .object_store(STORE)
        .map_err(|_| BrowserIdentityError::Storage)?;
    let request = store
        .get(&JsValue::from_str(scope))
        .map_err(|_| BrowserIdentityError::Storage)?;
    let value = wait_request(&request)
        .await
        .map_err(|_| BrowserIdentityError::Storage)?;
    completion.wait().await?;
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    let version = Reflect::get(&value, &"version".into())
        .map_err(|_| BrowserIdentityError::Corrupt)?
        .as_f64();
    let stored_scope = Reflect::get(&value, &"scope".into())
        .map_err(|_| BrowserIdentityError::Corrupt)?
        .as_string();
    let device_id = Reflect::get(&value, &"device_id".into())
        .map_err(|_| BrowserIdentityError::Corrupt)?
        .as_string()
        .filter(|id| nestlink_protocol::valid_id(id))
        .ok_or(BrowserIdentityError::Corrupt)?;
    if version != Some(1.0) || stored_scope.as_deref() != Some(scope) {
        return Err(BrowserIdentityError::Corrupt);
    }
    let key = Reflect::get(&value, &"key".into())
        .map_err(|_| BrowserIdentityError::Corrupt)?
        .dyn_into::<CryptoKey>()
        .map_err(|_| BrowserIdentityError::Corrupt)?;
    if key.extractable() || key.type_() != "secret" {
        return Err(BrowserIdentityError::Corrupt);
    }
    let algorithm = key.algorithm().map_err(|_| BrowserIdentityError::Corrupt)?;
    let algorithm_name = Reflect::get(&algorithm, &"name".into())
        .map_err(|_| BrowserIdentityError::Corrupt)?
        .as_string();
    let key_length = Reflect::get(&algorithm, &"length".into())
        .map_err(|_| BrowserIdentityError::Corrupt)?
        .as_f64();
    let usages = key.usages();
    if algorithm_name.as_deref() != Some("AES-GCM")
        || key_length != Some(256.0)
        || usages.length() != 2
        || !usages.includes(&"encrypt".into(), 0)
        || !usages.includes(&"decrypt".into(), 0)
    {
        return Err(BrowserIdentityError::Corrupt);
    }
    let iv = bytes_field(&value, "iv", 12, 12)?;
    let ciphertext = bytes_field(&value, "ciphertext", 48, 48)?;
    Ok(Some(StoredRecord {
        device_id,
        key,
        iv,
        ciphertext,
    }))
}

async fn encrypt_record(
    scope: &str,
    device_id: &str,
    seed: &[u8; 32],
) -> Result<JsValue, BrowserIdentityError> {
    let subtle = subtle_crypto()?;
    let key_algorithm = Object::new();
    set(&key_algorithm, "name", &"AES-GCM".into())?;
    set(&key_algorithm, "length", &256.into())?;
    let usages = Array::new();
    usages.push(&"encrypt".into());
    usages.push(&"decrypt".into());
    let key = JsFuture::from(
        subtle
            .generate_key_with_object(&key_algorithm, false, usages.as_ref())
            .map_err(|_| BrowserIdentityError::Storage)?,
    )
    .await
    .map_err(|_| BrowserIdentityError::Storage)?
    .dyn_into::<CryptoKey>()
    .map_err(|_| BrowserIdentityError::Storage)?;
    let iv = random_bytes::<12>();
    let algorithm = aes_gcm_algorithm(&iv, scope, device_id)?;
    let encrypted = JsFuture::from(
        subtle
            .encrypt_with_object_and_u8_array(&algorithm, &key, seed)
            .map_err(|_| BrowserIdentityError::Storage)?,
    )
    .await
    .map_err(|_| BrowserIdentityError::Storage)?;
    let ciphertext = Uint8Array::new(&encrypted).to_vec();
    if ciphertext.len() != 48 || key.extractable() {
        return Err(BrowserIdentityError::Storage);
    }
    let record = Object::new();
    set(&record, "version", &1.into())?;
    set(&record, "scope", &scope.into())?;
    set(&record, "device_id", &device_id.into())?;
    set(&record, "key", key.as_ref())?;
    set(&record, "iv", Uint8Array::from(iv.as_slice()).as_ref())?;
    set(
        &record,
        "ciphertext",
        Uint8Array::from(ciphertext.as_slice()).as_ref(),
    )?;
    Ok(record.into())
}

async fn decrypt_record(
    scope: &str,
    record: StoredRecord,
) -> Result<DeviceIdentity, BrowserIdentityError> {
    let algorithm = aes_gcm_algorithm(&record.iv, scope, &record.device_id)?;
    let ciphertext = Uint8Array::from(record.ciphertext.as_slice());
    let decrypted = JsFuture::from(
        subtle_crypto()?
            .decrypt_with_object_and_js_u8_array(&algorithm, &record.key, &ciphertext)
            .map_err(|_| BrowserIdentityError::Corrupt)?,
    )
    .await
    .map_err(|_| BrowserIdentityError::Corrupt)?;
    let mut seed = Zeroizing::new(Uint8Array::new(&decrypted).to_vec());
    if seed.len() != 32 {
        return Err(BrowserIdentityError::Corrupt);
    }
    let seed: &mut [u8; 32] = seed
        .as_mut_slice()
        .try_into()
        .map_err(|_| BrowserIdentityError::Corrupt)?;
    Ok(DeviceIdentity {
        device_id: record.device_id,
        identity: InstallationIdentity::from_seed_zeroizing(seed),
    })
}

fn bytes_field(
    record: &JsValue,
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, BrowserIdentityError> {
    let value = Reflect::get(record, &name.into()).map_err(|_| BrowserIdentityError::Corrupt)?;
    let bytes = value
        .dyn_into::<Uint8Array>()
        .map_err(|_| BrowserIdentityError::Corrupt)?
        .to_vec();
    if !(minimum..=maximum).contains(&bytes.len()) {
        return Err(BrowserIdentityError::Corrupt);
    }
    Ok(bytes)
}

async fn write_record(
    db: &IdbDatabase,
    scope: &str,
    value: &JsValue,
) -> Result<(), BrowserIdentityError> {
    let tx = db
        .transaction_with_str_and_mode(STORE, IdbTransactionMode::Readwrite)
        .map_err(|_| BrowserIdentityError::Storage)?;
    let completion = TransactionCompletion::attach(tx.clone())?;
    let store = tx
        .object_store(STORE)
        .map_err(|_| BrowserIdentityError::Storage)?;
    let request = store
        .put_with_key(value, &JsValue::from_str(scope))
        .map_err(|_| BrowserIdentityError::Storage)?;
    wait_request(&request)
        .await
        .map_err(|_| BrowserIdentityError::Storage)?;
    completion.wait().await
}

fn aes_gcm_algorithm(
    iv: &[u8],
    scope: &str,
    device_id: &str,
) -> Result<Object, BrowserIdentityError> {
    if iv.len() != 12 {
        return Err(BrowserIdentityError::Corrupt);
    }
    let algorithm = Object::new();
    set(&algorithm, "name", &"AES-GCM".into())?;
    set(&algorithm, "iv", Uint8Array::from(iv).as_ref())?;
    let binding = format!("{DATABASE}\0{scope}\0{device_id}");
    set(
        &algorithm,
        "additionalData",
        Uint8Array::from(binding.as_bytes()).as_ref(),
    )?;
    Ok(algorithm)
}

fn subtle_crypto() -> Result<web_sys::SubtleCrypto, BrowserIdentityError> {
    let window = web_sys::window().ok_or(BrowserIdentityError::Storage)?;
    Ok(window
        .crypto()
        .map_err(|_| BrowserIdentityError::Storage)?
        .subtle())
}

fn set(object: &Object, key: &str, value: &JsValue) -> Result<(), BrowserIdentityError> {
    Reflect::set(object.as_ref(), &key.into(), value)
        .map(|_| ())
        .map_err(|_| BrowserIdentityError::Storage)
}

async fn wait_request(request: &IdbRequest) -> Result<JsValue, JsValue> {
    let request = request.clone();
    let callback_request = request.clone();
    let (sender, receiver) = oneshot::channel::<Result<JsValue, JsValue>>();
    let sender = Rc::new(RefCell::new(Some(sender)));
    let success_sender = sender.clone();
    let success = Closure::<dyn FnMut(Event)>::new(move |_| {
        if let Some(sender) = success_sender.borrow_mut().take() {
            let _ = sender.send(callback_request.result());
        }
    });
    let error_sender = sender.clone();
    let error = Closure::<dyn FnMut(Event)>::new(move |_| {
        if let Some(sender) = error_sender.borrow_mut().take() {
            let _ = sender.send(Err(JsValue::UNDEFINED));
        }
    });
    request.set_onsuccess(Some(success.as_ref().unchecked_ref()));
    request.set_onerror(Some(error.as_ref().unchecked_ref()));
    let result = receiver.await.map_err(|_| JsValue::UNDEFINED)?;
    request.set_onsuccess(None);
    request.set_onerror(None);
    drop((success, error));
    result
}

type TransactionCompletionSender = Rc<RefCell<Option<oneshot::Sender<Result<(), ()>>>>>;

struct TransactionCompletion {
    tx: IdbTransaction,
    receiver: oneshot::Receiver<Result<(), ()>>,
    complete: Closure<dyn FnMut(Event)>,
    error: Closure<dyn FnMut(Event)>,
    abort: Closure<dyn FnMut(Event)>,
}

impl TransactionCompletion {
    fn attach(tx: IdbTransaction) -> Result<Self, BrowserIdentityError> {
        let (sender, receiver) = oneshot::channel();
        let sender = Rc::new(RefCell::new(Some(sender)));
        let complete_sender = sender.clone();
        let complete = Closure::<dyn FnMut(Event)>::new(move |_| {
            if let Some(sender) = complete_sender.borrow_mut().take() {
                let _ = sender.send(Ok(()));
            }
        });
        let fail = |sender: TransactionCompletionSender| {
            Closure::<dyn FnMut(Event)>::new(move |_| {
                if let Some(sender) = sender.borrow_mut().take() {
                    let _ = sender.send(Err(()));
                }
            })
        };
        let error = fail(sender.clone());
        let abort = fail(sender);
        tx.set_oncomplete(Some(complete.as_ref().unchecked_ref()));
        tx.set_onerror(Some(error.as_ref().unchecked_ref()));
        tx.set_onabort(Some(abort.as_ref().unchecked_ref()));
        Ok(Self {
            tx,
            receiver,
            complete,
            error,
            abort,
        })
    }

    async fn wait(self) -> Result<(), BrowserIdentityError> {
        let result = self
            .receiver
            .await
            .map_err(|_| BrowserIdentityError::Storage)?
            .map_err(|_| BrowserIdentityError::Storage);
        self.tx.set_oncomplete(None);
        self.tx.set_onerror(None);
        self.tx.set_onabort(None);
        drop((self.complete, self.error, self.abort));
        result
    }
}

struct IdentityLock {
    release: Option<oneshot::Sender<()>>,
}

impl IdentityLock {
    async fn acquire(scope: &str) -> Result<Self, BrowserIdentityError> {
        let window = web_sys::window().ok_or(BrowserIdentityError::Storage)?;
        let manager = Reflect::get(window.navigator().as_ref(), &"locks".into())
            .map_err(|_| BrowserIdentityError::Storage)?;
        let request_function = Reflect::get(&manager, &"request".into())
            .map_err(|_| BrowserIdentityError::Storage)?
            .dyn_into::<Function>()
            .map_err(|_| BrowserIdentityError::Storage)?;
        let (granted, waiting) = oneshot::channel();
        let grant = Rc::new(RefCell::new(Some(granted)));
        let callback_grant = grant.clone();
        let (release, released) = oneshot::channel();
        let callback_released = Rc::new(RefCell::new(Some(released)));
        let callback_release_waiter = callback_released.clone();
        let callback = Closure::<dyn FnMut(JsValue) -> Promise>::new(move |lock: JsValue| {
            let Some(granted) = callback_grant.borrow_mut().take() else {
                return Promise::reject(&JsValue::UNDEFINED);
            };
            if lock.is_null() || lock.is_undefined() {
                let _ = granted.send(Err(()));
                return Promise::resolve(&JsValue::UNDEFINED);
            }
            if granted.send(Ok(())).is_err() {
                return Promise::reject(&JsValue::UNDEFINED);
            }
            let Some(released) = callback_release_waiter.borrow_mut().take() else {
                return Promise::reject(&JsValue::UNDEFINED);
            };
            future_to_promise(async move {
                let _ = released.await;
                Ok(JsValue::UNDEFINED)
            })
        });
        let request = request_function
            .call2(
                &manager,
                &JsValue::from_str(&format!("nestlink-controller-identity:{scope}")),
                callback.as_ref(),
            )
            .map_err(|_| BrowserIdentityError::Storage)?
            .dyn_into::<Promise>()
            .map_err(|_| BrowserIdentityError::Storage)?;
        spawn_local(async move {
            let result = JsFuture::from(request).await.map(|_| ()).map_err(|_| ());
            if let Some(granted) = grant.borrow_mut().take() {
                let _ = granted.send(Err(()));
            }
            drop(callback);
            let _ = result;
        });
        waiting
            .await
            .map_err(|_| BrowserIdentityError::Storage)?
            .map_err(|_| BrowserIdentityError::Storage)?;
        Ok(Self {
            release: Some(release),
        })
    }
}

impl Drop for IdentityLock {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DATABASE;

    #[test]
    fn browser_identity_database_is_versioned_and_separate_from_file_staging() {
        assert_eq!(DATABASE, "nestlink-control-identity-v1");
        assert_ne!(DATABASE, "nestlink-private-v15");
    }
}
