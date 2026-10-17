use super::*;

#[derive(Debug, thiserror::Error)]
pub enum ClipboardRpcError {
    #[error("clipboard transport/authority failed: {0}")]
    Remote(#[from] RemoteError),
    #[error("clipboard operation refused: {code:?}, effect: {effect:?}")]
    Refused {
        code: ClipboardErrorCode,
        effect: ClipboardWriteEffect,
    },
    #[error("clipboard source was cancelled before transport delivery")]
    Cancelled,
}
pub struct ClipboardReadResult {
    pub text: Option<Zeroizing<String>>,
}
struct Client {
    receiver: ChannelReceiver,
    sender: ChannelSender,
    lease: LeaseControl,
    binding: ClipboardBinding,
    direction: ClipboardDirection,
    sequence: u64,
    in_flight: bool,
}
impl Client {
    fn attach(
        runtime: &mut ChannelRuntime,
        direction: ClipboardDirection,
        generation: u64,
    ) -> Result<Self, RemoteError> {
        let lease = runtime.lease_control();
        let binding = ClipboardBinding {
            session_id: lease.clipboard_session_id(direction.channel(), generation)?,
            connection_generation: generation,
        };
        let directions = match direction {
            ClipboardDirection::Read => ClipboardDirections {
                read: true,
                write: false,
            },
            ClipboardDirection::Write => ClipboardDirections {
                read: false,
                write: true,
            },
        };
        let mut transport = ClaimedClipboardTransport::claim(runtime, binding, directions)?;
        Self::attach_claimed(&mut transport, direction)
    }

    fn attach_claimed(
        transport: &mut ClaimedClipboardTransport,
        direction: ClipboardDirection,
    ) -> Result<Self, RemoteError> {
        if !transport.directions().allows(direction) {
            return Err(rejected("clipboard direction was not claimed").into());
        }
        let binding = transport.binding().clone();
        let lease = transport.lease.clone();
        lease.check_clipboard_binding(
            &binding.session_id,
            direction.channel(),
            binding.connection_generation,
        )?;
        let receiver = transport.take_receiver(direction)?;
        Ok(Self {
            receiver,
            sender: transport.sender.clone(),
            lease,
            binding,
            direction,
            sequence: 0,
            in_flight: false,
        })
    }
    fn protocol(&self, reason: &'static str) -> RemoteError {
        let _ = self.lease.stop(StopReason::ProtocolViolation);
        rejected(reason).into()
    }
    fn retire(self) -> Result<(), RemoteError> {
        if self.in_flight {
            return Err(self.protocol("clipboard has an unconsumed request"));
        }
        self.receiver.retire_clipboard()
    }
    async fn request(
        &mut self,
        action: Action,
        consent: Option<Arc<dyn ClipboardConsent>>,
        response_consent: Option<Arc<dyn ClipboardConsent>>,
        deadline: Instant,
    ) -> Result<Action, ClipboardRpcError> {
        let mut request = ProtectedMessage(NativeClipboard {
            schema_version: SCHEMA_VERSION,
            connection_generation: self.binding.connection_generation,
            sequence: self
                .sequence
                .checked_add(1)
                .filter(|value| *value <= i64::MAX as u64)
                .ok_or_else(|| self.protocol("clipboard sequence exhausted"))?,
            action: Some(action),
        });
        if self.in_flight {
            return Err(self
                .protocol("cancelled clipboard future still owns its response")
                .into());
        }
        deadline_check(deadline).map_err(RemoteError::from)?;
        self.lease.check_clipboard_binding(
            &self.binding.session_id,
            self.direction.channel(),
            self.binding.connection_generation,
        )?;
        if let Some(consent) = response_consent.as_ref()
            && let Err(error) = consent.check_until(deadline)
        {
            return Err(ClipboardRpcError::Refused {
                code: error_code(&error),
                effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
            });
        }
        let bytes = Zeroizing::new(request.0.encode_validated().map_err(RemoteError::from)?);
        deadline_check(deadline).map_err(RemoteError::from)?;
        let sequence = request.0.sequence;
        // No further await consumes/copies plaintext from the typed request.
        clear_message(&mut request.0);
        self.in_flight = true;
        let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            if let Some(consent) = consent {
                let cancelled = NativeClipboard {
                    schema_version: SCHEMA_VERSION,
                    connection_generation: self.binding.connection_generation,
                    sequence,
                    action: Some(Action::Cancel(true)),
                }
                .encode_validated()?;
                self.sender
                    .send_checked_delivery(
                        self.direction.channel(),
                        &bytes,
                        Arc::new(DispatchGuard {
                            consent,
                            lease: self.lease.clone(),
                            binding: self.binding.clone(),
                            direction: self.direction,
                            cancelled: Arc::new(AtomicBool::new(false)),
                            deadline,
                        }),
                        cancelled.clone(),
                        cancelled,
                    )
                    .await?;
            } else {
                self.sender.send(self.direction.channel(), &bytes).await?;
            }
            let frame = self.receiver.receive().await?;
            let response_bytes = Zeroizing::new(frame.payload);
            let mut response = ProtectedMessage(
                NativeClipboard::decode_validated(&response_bytes).inspect_err(|_| {
                    let _ = self.lease.stop(StopReason::ProtocolViolation);
                })?,
            );
            if response.0.connection_generation != self.binding.connection_generation
                || response.0.sequence != sequence
            {
                return Err(self.protocol("clipboard reply does not match its exact request"));
            }
            self.lease.check_clipboard_binding(
                &self.binding.session_id,
                self.direction.channel(),
                self.binding.connection_generation,
            )?;
            deadline_check(deadline)?;
            let action = response
                .0
                .action
                .as_ref()
                .ok_or_else(|| self.protocol("missing clipboard reply"))?;
            match (self.direction, action) {
                (ClipboardDirection::Read, Action::Text(_))
                | (ClipboardDirection::Write, Action::Written(true))
                | (ClipboardDirection::Write, Action::Cancelled(true)) => {}
                (_, Action::Failure(failure))
                    if self.direction == ClipboardDirection::Write
                        || failure.write_effect
                            == ClipboardWriteEffect::ClipboardWriteNotApplied as i32 => {}
                _ => {
                    return Err(
                        self.protocol("clipboard reply is for another direction or endpoint")
                    );
                }
            }
            if let Some(consent) = response_consent.as_ref()
                && let Err(error) = consent.check_until(deadline)
            {
                clear_message(&mut response.0);
                response.0.action = Some(failure(
                    error_code(&error),
                    ClipboardWriteEffect::ClipboardWriteNotApplied,
                ));
            }
            response
                .0
                .action
                .take()
                .ok_or_else(|| self.protocol("missing clipboard reply"))
        })
        .await;
        let action = match result {
            Ok(result) => {
                if result.is_err() {
                    crate::queues::stop_io_result(&self.lease, &result);
                }
                result?
            }
            Err(_) => {
                let _ = self.lease.stop(StopReason::TransportLost);
                return Err(RemoteError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "clipboard response deadline expired",
                ))
                .into());
            }
        };
        self.in_flight = false;
        self.sequence = sequence;
        match action {
            Action::Failure(failed) => Err(ClipboardRpcError::Refused {
                code: ClipboardErrorCode::try_from(failed.code)
                    .map_err(|_| self.protocol("unknown clipboard failure"))?,
                effect: ClipboardWriteEffect::try_from(failed.write_effect)
                    .map_err(|_| self.protocol("unknown clipboard effect"))?,
            }),
            Action::Cancelled(true) => Err(ClipboardRpcError::Cancelled),
            action => Ok(action),
        }
    }
}
/// Low-level clients are exclusive. Dropping a request future leaves it sticky
/// in flight, so only an owner which consumes every result should use them.
pub struct ClipboardReadClient(Client);
impl ClipboardReadClient {
    pub fn attach(runtime: &mut ChannelRuntime, generation: u64) -> Result<Self, RemoteError> {
        Ok(Self(Client::attach(
            runtime,
            ClipboardDirection::Read,
            generation,
        )?))
    }
    pub fn attach_claimed(transport: &mut ClaimedClipboardTransport) -> Result<Self, RemoteError> {
        Ok(Self(Client::attach_claimed(
            transport,
            ClipboardDirection::Read,
        )?))
    }
    pub async fn read_text(&mut self) -> Result<ClipboardReadResult, ClipboardRpcError> {
        self.read_text_until(Instant::now() + Duration::from_millis(CLIPBOARD_OPERATION_MS))
            .await
    }
    pub async fn read_text_until(
        &mut self,
        deadline: Instant,
    ) -> Result<ClipboardReadResult, ClipboardRpcError> {
        self.read_text_until_with_consent(deadline, None).await
    }

    /// Checks local consent before dispatch and after consuming the exact
    /// matching reply. Revocation replaces a consumed response with a denial,
    /// preserving the channel sequence while keeping its text undisclosed.
    pub async fn read_text_until_with_consent(
        &mut self,
        deadline: Instant,
        consent: Option<Arc<dyn ClipboardConsent>>,
    ) -> Result<ClipboardReadResult, ClipboardRpcError> {
        match self
            .0
            .request(Action::Read(true), None, consent, deadline)
            .await?
        {
            Action::Text(text) => Ok(ClipboardReadResult {
                text: text.text.map(Zeroizing::new),
            }),
            _ => Err(self.0.protocol("missing clipboard text reply").into()),
        }
    }
    pub fn retire(self) -> Result<(), RemoteError> {
        self.0.retire()
    }
}
pub struct ClipboardWriteClient(Client);
impl ClipboardWriteClient {
    pub fn attach(runtime: &mut ChannelRuntime, generation: u64) -> Result<Self, RemoteError> {
        Ok(Self(Client::attach(
            runtime,
            ClipboardDirection::Write,
            generation,
        )?))
    }
    pub fn attach_claimed(transport: &mut ClaimedClipboardTransport) -> Result<Self, RemoteError> {
        Ok(Self(Client::attach_claimed(
            transport,
            ClipboardDirection::Write,
        )?))
    }
    pub async fn write_text(
        &mut self,
        text: Zeroizing<String>,
        consent: Arc<dyn ClipboardConsent>,
    ) -> Result<(), ClipboardRpcError> {
        self.write_text_until(
            text,
            consent,
            Instant::now() + Duration::from_millis(CLIPBOARD_OPERATION_MS),
        )
        .await
    }
    pub async fn write_text_until(
        &mut self,
        mut text: Zeroizing<String>,
        consent: Arc<dyn ClipboardConsent>,
        deadline: Instant,
    ) -> Result<(), ClipboardRpcError> {
        match self
            .0
            .request(
                Action::Write(std::mem::take(&mut *text)),
                Some(consent),
                None,
                deadline,
            )
            .await?
        {
            Action::Written(true) => Ok(()),
            _ => Err(self
                .0
                .protocol("missing clipboard write acknowledgement")
                .into()),
        }
    }
    pub fn retire(self) -> Result<(), RemoteError> {
        self.0.retire()
    }
}
