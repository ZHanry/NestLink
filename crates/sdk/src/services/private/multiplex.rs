//! Explicit private TCP/HTTP(S) streams share one original durable owner.
//! Every application stream still uses the original signatures and prepare/
//! reserve gate. Control bytes never become a locally forwarded business flow.
use super::*;
use tokio::{io::AsyncReadExt, sync::Semaphore};

pub(super) const VERSION: u8 = 1;
const HANDSHAKES: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Mode {
    #[serde(rename = "multiplex-control")]
    Control,
    #[serde(rename = "multiplex-stream")]
    Stream,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Accepted {
    version: u8,
    mode: Mode,
}
impl Accepted {
    pub(super) fn validate(&self) -> Result<(), SdkError> {
        if self.version != VERSION || self.mode != Mode::Control {
            return Err(SdkError::Trust);
        }
        Ok(())
    }
}

pub(super) fn control_mode(hello: &Hello) -> Result<bool, SdkError> {
    match (hello.version, hello.mode) {
        (None, None) => Ok(false),
        (Some(VERSION), Some(Mode::Control)) => Ok(true),
        _ => Err(SdkError::Invalid),
    }
}

pub(super) struct Client {
    sdk: Arc<Sdk>,
    fingerprint: [u8; 32],
    handshakes: Arc<Semaphore>,
}
impl Client {
    pub(super) fn new(sdk: Arc<Sdk>, fingerprint: [u8; 32]) -> Self {
        Self {
            sdk,
            fingerprint,
            handshakes: Arc::new(Semaphore::new(HANDSHAKES)),
        }
    }
}

pub(super) async fn open_stream(
    owner: &PrivateServiceConnection,
    consumer: &DeviceIdentity,
) -> Result<BiStream, SdkError> {
    let client = owner.multiplex.as_ref().ok_or(SdkError::Invalid)?;
    let _handshake = client
        .handshakes
        .clone()
        .try_acquire_owned()
        .map_err(|_| SdkError::Invalid)?;
    let lease = &owner.lease;
    lease.check_time(private_wall_ms()?)?;
    if consumer.device_id != lease.claims().consumer_device_id
        || consumer.identity.public_key() != lease.claims().consumer_public_key
    {
        return Err(SdkError::Trust);
    }
    let grant = usage_claims(lease)?;
    tokio::time::timeout(Duration::from_secs(3), async {
        current(&client.sdk, lease, client.fingerprint, &grant).await?;
        let connection = owner
            .connected
            .as_ref()
            .ok_or(SdkError::Trust)?
            .connection()?;
        let (mut send, mut recv) = connection.open_bi().await.map_err(std::io::Error::other)?;
        write_message(
            &mut send,
            &Hello {
                service_id: grant.service_id.clone(),
                grant_id: grant.grant_id.clone(),
                version: Some(VERSION),
                mode: Some(Mode::Stream),
            },
        )
        .await?;
        let nonce: [u8; 32] = read_message(&mut recv).await?;
        let open = consumer.identity.private_service_open(lease, nonce)?;
        write_message(&mut send, &open).await?;
        let ready: PrivateServiceReady = read_message(&mut recv).await?;
        verify_private_service_ready(lease, &open, &ready)?;
        current(&client.sdk, lease, client.fingerprint, &grant).await?;
        Ok(BiStream::new(send, recv))
    })
    .await
    .map_err(|_| SdkError::Timeout)?
}

async fn current(
    sdk: &Sdk,
    lease: &VerifiedPrivateServiceLease,
    fingerprint: [u8; 32],
    grant: &ServiceUsageBudgetGrantClaims,
) -> Result<(), SdkError> {
    lease.check_time(private_wall_ms()?)?;
    let (bundle, verified) = sdk
        .current_private_service_bundle(&grant.service_id, &grant.grant_id)
        .await?;
    if verified.digest() != lease.digest()
        || super::super::network::fingerprint(&bundle)? != fingerprint
    {
        return Err(SdkError::Trust);
    }
    Ok(())
}

struct FlowContext {
    sdk: Arc<Sdk>,
    host: Arc<DeviceIdentity>,
    consent: Arc<LocalServiceTargetConsent>,
    lease: VerifiedPrivateServiceLease,
    fingerprint: [u8; 32],
    grant: ServiceUsageBudgetGrantClaims,
    publication: Arc<PrivateServicePublication>,
    target: Arc<LocalTargetOwner>,
    handshakes: Arc<Semaphore>,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn serve(
    sdk: Arc<Sdk>,
    host: Arc<DeviceIdentity>,
    consent: Arc<LocalServiceTargetConsent>,
    usage: Arc<ServiceUsageStore>,
    mut stop: watch::Receiver<bool>,
    connection: quinn::Connection,
    mut control: BiStream,
    ready: PrivateServiceReady,
    lease: VerifiedPrivateServiceLease,
    fingerprint: [u8; 32],
    grant: ServiceUsageBudgetGrantClaims,
    publication: PrivateServicePublication,
    target: LocalTargetOwner,
) -> Result<(), SdkError> {
    let workers_limit = usize::from(
        lease
            .lease()
            .claims()
            .effective_limits()
            .maximum_connections,
    ) + HANDSHAKES;
    let deadline = tokio::time::Instant::now()
        + Duration::from_millis(
            lease
                .lease()
                .claims()
                .expires_at_unix_ms
                .saturating_sub(private_wall_ms().unwrap_or(u64::MAX)),
        );
    let context = Arc::new(FlowContext {
        sdk: sdk.clone(),
        host: host.clone(),
        consent,
        lease,
        fingerprint,
        grant,
        publication: Arc::new(publication),
        target: Arc::new(target),
        handshakes: Arc::new(Semaphore::new(HANDSHAKES)),
    });
    let (flow_stop, flow_stopped) = watch::channel(false);
    let mut flows = JoinSet::new();
    let mut failed = false;
    let admitted = tokio::select! {biased;
        _=stopped(&mut stop)=>false,
        result=tokio::time::timeout(Duration::from_secs(3), async {
            write_message(control.parts_mut().0, &ready).await?;
            write_message(control.parts_mut().0, &Accepted { version: VERSION, mode: Mode::Control }).await
        })=>matches!(result,Ok(Ok(()))),
    };
    if admitted {
        let monitor = async {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                if let Err(error) = current(&sdk, &context.lease, fingerprint, &context.grant).await
                {
                    return Err::<(), SdkError>(error);
                }
                flush_report(&sdk, &usage, &host, &context.grant.grant_id, false).await?;
            }
        };
        tokio::pin!(monitor);
        let mut byte = [0u8; 1];
        loop {
            tokio::select! {biased;
                _=stopped(&mut stop)=>break,
                _=tokio::time::sleep_until(deadline)=>break,
                _=connection.closed()=>break,
                _=control.read(&mut byte)=>break,
                _=&mut monitor=>break,
                result=flows.join_next(),if !flows.is_empty()=>{
                    if matches!(result,Some(Err(_))) {failed=true;break;}
                },
                incoming=connection.accept_bi()=>{
                    let Ok((mut send,mut recv))=incoming else {break;};
                    let permit=context.handshakes.clone().try_acquire_owned();
                    if flows.len()>=workers_limit || permit.is_err() {
                        let _=send.reset(1u32.into());
                        let _=recv.stop(1u32.into());
                        continue;
                    }
                    if let Ok(permit)=permit {
                        flows.spawn(forward(context.clone(),flow_stopped.clone(),send,recv,permit));
                    }
                }
            }
        }
    }
    // No abort/timeout fabricates a drained grant: every original forwarder
    // closes its real backend and drops its original durable flow reservation.
    context.publication.revoke();
    context.target.revoke();
    flow_stop.send_replace(true);
    connection.close(0u32.into(), b"private multiplex owner ended");
    drop(control);
    while let Some(result) = flows.join_next().await {
        if result.is_err() {
            failed = true;
        }
    }
    let token = context.publication.handle().wait_drained().await?;
    usage.confirm_drained(&token).map_err(usage_error)?;
    for _ in 0..2 {
        if flush_report(&sdk, &usage, &host, &context.grant.grant_id, true).await? {
            break;
        }
    }
    if failed {
        return Err(SdkError::Trust);
    }
    Ok(())
}

async fn forward(
    context: Arc<FlowContext>,
    mut stop: watch::Receiver<bool>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<(), SdkError> {
    let handshake = tokio::time::timeout(Duration::from_secs(3), async {
        let hello: Hello = read_message(&mut recv).await?;
        if hello.version != Some(VERSION)
            || hello.mode != Some(Mode::Stream)
            || hello.service_id != context.grant.service_id
            || hello.grant_id != context.grant.grant_id
        {
            return Err(SdkError::Trust);
        }
        current(
            &context.sdk,
            &context.lease,
            context.fingerprint,
            &context.grant,
        )
        .await?;
        let nonce = random_bytes::<32>();
        write_message(&mut send, &nonce).await?;
        let open: PrivateServiceOpen = read_message(&mut recv).await?;
        if open.nonce != nonce {
            return Err(SdkError::Trust);
        }
        verify_private_service_open(&context.lease, &open)?;
        current(
            &context.sdk,
            &context.lease,
            context.fingerprint,
            &context.grant,
        )
        .await?;
        let prepared =
            context
                .publication
                .prepare(&context.target, &open, nonce, &context.host.identity)?;
        let ready = context
            .host
            .identity
            .private_service_ready(&context.lease, &open)?;
        write_message(&mut send, &ready).await?;
        Ok::<_, SdkError>(prepared)
    });
    let prepared = tokio::select! {biased;
        _=stopped(&mut stop)=>return Ok(()),
        result=handshake=>match result {Ok(Ok(prepared))=>prepared,_=>return Ok(())},
    };
    drop(permit);
    let mut stream = BiStream::new(send, recv);
    let forward = async {
        if let Some(tls) = context.consent.backend_tls.clone() {
            prepared
                .forward_https(&mut stream, move |socket| tls.connect(socket))
                .await?;
        } else {
            prepared.forward_stream(&mut stream).await?;
        }
        Ok::<(), SdkError>(())
    };
    let completed = tokio::select! {biased;
        _=stopped(&mut stop)=>false,
        result=forward=>result.is_ok(),
    };
    if completed {
        tokio::select! {biased;
            _=stopped(&mut stop)=>{},
            _=tokio::time::timeout(Duration::from_secs(3), stream.wait_finished())=>{},
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LegacyHello {
        service_id: String,
        grant_id: String,
    }

    #[test]
    fn explicit_negotiation_preserves_legacy_wire_and_old_host_refusal()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut hello = Hello {
            service_id: "service".into(),
            grant_id: "grant".into(),
            version: None,
            mode: None,
        };
        let bytes = serde_json::to_vec(&hello)?;
        assert_eq!(bytes, br#"{"service_id":"service","grant_id":"grant"}"#);
        let old: LegacyHello = serde_json::from_slice(&bytes)?;
        assert_eq!(old.service_id, "service");
        assert_eq!(old.grant_id, "grant");
        assert!(!control_mode(&hello)?);

        hello.version = Some(VERSION);
        hello.mode = Some(Mode::Control);
        assert!(control_mode(&hello)?);
        assert!(serde_json::from_slice::<LegacyHello>(&serde_json::to_vec(&hello)?).is_err());
        hello.version = Some(VERSION + 1);
        assert!(control_mode(&hello).is_err());
        hello.version = Some(VERSION);
        hello.mode = Some(Mode::Stream);
        assert!(control_mode(&hello).is_err());
        hello.mode = None;
        assert!(control_mode(&hello).is_err());
        Ok(())
    }
}
