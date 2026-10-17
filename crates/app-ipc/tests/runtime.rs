use nestlink_app_core::{
    Action, AppCore, BrowserHostBinding, BrowserHostDataView, CoreHandle, Limits, Page,
    ShutdownState,
};
use nestlink_app_ipc::{
    Client, Error, ExitRequest,
    browser_data::{
        BrowserHostDataCommand, BrowserHostDataReply, BrowserHostDataReplyFuture,
        LocalBrowserHostDataHandler,
    },
    serve, serve_with_browser_data,
    wire::*,
};
use nestlink_local_ipc::{LocalServer, LocalStream};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{sync::mpsc, task::JoinSet};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct BrowserDataBindingProbe {
    seen: mpsc::UnboundedSender<(BrowserHostBinding, u64, bool)>,
}

impl LocalBrowserHostDataHandler for BrowserDataBindingProbe {
    fn handle(
        &self,
        _core: CoreHandle,
        binding: BrowserHostBinding,
        generation: u64,
        command: BrowserHostDataCommand,
    ) -> BrowserHostDataReplyFuture<'_> {
        let seen = self.seen.clone();
        Box::pin(async move {
            let expected_action = matches!(
                command,
                BrowserHostDataCommand::SetClipboardDirections {
                    read: false,
                    write: true
                }
            );
            let _ = seen.send((binding, generation, expected_action));
            BrowserHostDataReply::Applied {
                data: BrowserHostDataView::default(),
            }
        })
    }
}

async fn client(
    server: &LocalServer,
    root: &Path,
    core: nestlink_app_core::CoreHandle,
    exit: mpsc::Sender<ExitRequest>,
    tasks: &mut JoinSet<std::result::Result<(), Error>>,
) -> Result<Client> {
    let connecting = Client::connect(root);
    let accepting = async { server.accept().await?.authenticate().await };
    let (client, accepted) = tokio::join!(connecting, accepting);
    let accepted = accepted?;
    tasks.spawn(serve(accepted, core, exit));
    Ok(client?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_tls_connections_own_their_tickets_and_reject_old_generation_commands() -> Result {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("state");
    let server = LocalServer::bind(&root).await?;
    let mut core = AppCore::start(Limits::default())?;
    let handle = core.handle();
    let (exit, _requests) = mpsc::channel(1);
    let mut tasks = JoinSet::new();
    let mut first = client(&server, &root, handle.clone(), exit.clone(), &mut tasks).await?;
    let mut second = client(&server, &root, handle.clone(), exit, &mut tasks).await?;
    let initial = first.request(0, Command::Snapshot).await?;
    let generation = initial.snapshot.generation;
    let response = first
        .request(
            generation,
            Command::Submit {
                action: Action::Load {
                    page: Page::Devices,
                },
            },
        )
        .await?;
    let Reply::Accepted { operation } = response.result else {
        return Err("valid action was not accepted".into());
    };
    assert!(matches!(
        second
            .request(0, Command::Completion { operation })
            .await?
            .result,
        Reply::Rejected {
            reason: Rejection::UnknownOperation
        }
    ));
    assert!(matches!(
        second
            .request(generation, Command::Cancel { operation })
            .await?
            .result,
        Reply::Rejected {
            reason: Rejection::UnknownOperation
        }
    ));
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let reply = first.request(0, Command::Completion { operation }).await?;
            match reply.result {
                Reply::Pending { .. } => tokio::task::yield_now().await,
                Reply::Completed {
                    operation,
                    sensitive,
                } => return Ok::<_, Error>((operation, sensitive)),
                _ => return Err(Error::Protocol),
            }
        }
    })
    .await??;
    assert_eq!(result.0.generation, generation);
    assert!(result.1.is_none());
    assert!(matches!(
        first
            .request(0, Command::Completion { operation })
            .await?
            .result,
        Reply::Rejected {
            reason: Rejection::UnknownOperation
        }
    ));
    let cancel_candidate = second
        .request(
            generation,
            Command::Submit {
                action: Action::Load {
                    page: Page::Devices,
                },
            },
        )
        .await?;
    let Reply::Accepted {
        operation: cancel_candidate,
    } = cancel_candidate.result
    else {
        return Err("valid cancel target was not accepted".into());
    };
    let _logout = handle.logout_for_generation(generation)?.wait().await?;
    let replaced = handle.snapshot().generation;
    assert!(replaced > generation);
    assert!(matches!(
        second
            .request(
                generation,
                Command::Submit {
                    action: Action::Load {
                        page: Page::Accounts
                    }
                }
            )
            .await?
            .result,
        Reply::Rejected {
            reason: Rejection::StaleGeneration
        }
    ));
    assert!(matches!(
        first.request(generation, Command::Logout).await?.result,
        Reply::Rejected {
            reason: Rejection::StaleGeneration
        }
    ));
    assert!(matches!(
        second
            .request(
                generation,
                Command::Cancel {
                    operation: cancel_candidate
                }
            )
            .await?
            .result,
        Reply::Rejected {
            reason: Rejection::StaleGeneration
        }
    ));
    assert_eq!(
        core.shutdown(Duration::from_secs(2)).await,
        ShutdownState::Complete
    );
    server.stop();
    drop(first);
    drop(second);
    while let Some(result) = tasks.join_next().await {
        assert!(matches!(
            result?,
            Err(Error::Transport(nestlink_local_ipc::Error::Stopped))
        ));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_host_data_ipc_preserves_exact_binding_and_generation() -> Result {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("state");
    let server = LocalServer::bind(&root).await?;
    let mut core = AppCore::start(Limits::default())?;
    let handle = core.handle();
    let (exit, _requests) = mpsc::channel(1);
    let (seen, mut received) = mpsc::unbounded_channel();
    let handler = Arc::new(BrowserDataBindingProbe { seen });
    let connecting = Client::connect(&root);
    let accepting = async { server.accept().await?.authenticate().await };
    let (client, accepted) = tokio::join!(connecting, accepting);
    let mut client = client?;
    let task = tokio::spawn(serve_with_browser_data(
        accepted?,
        handle,
        exit,
        None,
        Some(handler),
    ));

    let generation = client
        .request(0, Command::Snapshot)
        .await?
        .snapshot
        .generation;
    let binding = BrowserHostBinding {
        request_id: "00000000-0000-4000-8000-000000000001".into(),
        session_id: "00000000-0000-4000-8000-000000000002".into(),
        controller_device_id: "controller".into(),
        host_device_id: "host".into(),
        controller_key_sha256: [1; 32],
        host_key_sha256: [2; 32],
        permit_sha256: [3; 32],
        connection_generation: 9,
    };
    let response = client
        .request(
            generation,
            Command::BrowserHostData {
                binding: binding.clone(),
                action: BrowserHostDataCommand::SetClipboardDirections {
                    read: false,
                    write: true,
                },
            },
        )
        .await?;
    let Reply::BrowserHostData {
        binding: response_binding,
        generation: response_generation,
        result: BrowserHostDataReply::Applied { .. },
    } = response.result
    else {
        return Err("browser-host data reply did not preserve its expected shape".into());
    };
    assert_eq!(response_binding, binding);
    assert_eq!(response_generation, generation);
    let (handled_binding, handled_generation, expected_action) = received
        .try_recv()
        .map_err(|_| "browser-host data handler was not called")?;
    assert_eq!(handled_binding, response_binding);
    assert_eq!(handled_generation, response_generation);
    assert!(expected_action);

    // Keep the peer open until the daemon stop is observed. Closing it first
    // races a legitimate TLS EOF against the behavior this assertion checks.
    server.stop();
    let stopped = tokio::time::timeout(Duration::from_secs(2), task).await??;
    assert!(
        matches!(
            stopped,
            Err(Error::Transport(nestlink_local_ipc::Error::Stopped))
        ),
        "daemon stop while the peer remains open: {stopped:?}"
    );
    drop(client);
    assert_eq!(
        core.shutdown(Duration::from_secs(2)).await,
        ShutdownState::Complete
    );
    Ok(())
}

#[test]
fn connect_retry_classification_excludes_authentication_and_protocol_failures() {
    assert!(Error::Transport(nestlink_local_ipc::Error::Timeout).is_transient_connect());
    assert!(Error::Transport(nestlink_local_ipc::Error::Stopped).is_transient_connect());
    assert!(
        Error::Transport(nestlink_local_ipc::Error::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionRefused,
        )))
        .is_transient_connect()
    );
    assert!(
        Error::Transport(nestlink_local_ipc::Error::Io(std::io::Error::from(
            std::io::ErrorKind::NotFound,
        )))
        .is_transient_connect()
    );
    assert!(!Error::Transport(nestlink_local_ipc::Error::Authentication).is_transient_connect());
    assert!(!Error::Transport(nestlink_local_ipc::Error::Protocol).is_transient_connect());
    assert!(!Error::Protocol.is_transient_connect());
}

#[tokio::test]
async fn repeated_or_wrong_runtime_requests_close_the_authenticated_connection() -> Result {
    for wrong_runtime in [false, true] {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("state");
        let server = LocalServer::bind(&root).await?;
        let mut core = AppCore::start(Limits::default())?;
        let (exit, _requests) = mpsc::channel(1);
        let (client, accepted) = tokio::join!(LocalStream::connect(&root), async {
            server.accept().await?.authenticate().await
        });
        let mut client = client?;
        let accepted = accepted?;
        let runtime = client.runtime_id().to_owned();
        let task = tokio::spawn(serve(accepted, core.handle(), exit));
        let request = Request {
            version: nestlink_local_ipc::VERSION,
            runtime_id: runtime.clone(),
            sequence: 1,
            expected_generation: 0,
            command: Command::Snapshot,
        };
        client.send(&request).await?;
        let response: Response = client.receive().await?;
        assert_eq!(response.sequence, 1);
        client
            .send(&Request {
                runtime_id: if wrong_runtime {
                    nestlink_auth::random_id()
                } else {
                    runtime
                },
                sequence: if wrong_runtime { 2 } else { 1 },
                ..request
            })
            .await?;
        assert!(matches!(task.await?, Err(Error::Protocol)));
        assert!(client.receive::<Response>().await.is_err());
        assert_eq!(
            core.shutdown(Duration::from_secs(2)).await,
            ShutdownState::Complete
        );
    }
    Ok(())
}

#[tokio::test]
async fn exit_reports_the_owner_cleanup_and_waits_for_response_delivery() -> Result {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("state");
    let server = Arc::new(LocalServer::bind(&root).await?);
    let mut core = AppCore::start(Limits::default())?;
    let handle = core.handle();
    let (exit, mut requests) = mpsc::channel::<ExitRequest>(1);
    let owner = tokio::spawn(async move {
        let request = requests.recv().await.ok_or("exit not delivered")?;
        let result = if core.shutdown(Duration::from_secs(2)).await == ShutdownState::Complete {
            ExitResult::Complete
        } else {
            ExitResult::Failed
        };
        let _ = request.reply.send(result);
        tokio::time::timeout(Duration::from_secs(1), request.delivered).await??;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let mut tasks = JoinSet::new();
    let mut client = client(&server, &root, handle, exit, &mut tasks).await?;
    let generation = client
        .request(0, Command::Snapshot)
        .await?
        .snapshot
        .generation;
    assert!(matches!(
        client.request(generation, Command::Exit).await?.result,
        Reply::Exited {
            result: ExitResult::Complete
        }
    ));
    owner.await??;
    server.stop();
    drop(client);
    while let Some(result) = tasks.join_next().await {
        let _ = result?;
    }
    Ok(())
}

#[test]
fn application_commands_deny_ambiguous_fields_and_do_not_serialize_secrets_in_snapshots() -> Result
{
    for text in [
        r#"{"command":"snapshot","action":"sign_in"}"#,
        r#"{"command":"logout","password":"test-only-secret"}"#,
        r#"{"command":"exit","sequence":2}"#,
        r#"{"command":"cancel","operation":1,"extra":true}"#,
    ] {
        assert!(serde_json::from_str::<Command>(text).is_err());
    }
    let snapshot = nestlink_app_core::Snapshot::default();
    let value = serde_json::to_value(snapshot)?;
    for forbidden in [
        "password",
        "access_token",
        "refresh_token",
        "totp_seed",
        "recovery_codes",
        "private_key",
    ] {
        assert!(value.get(forbidden).is_none());
    }
    let action = Command::Submit {
        action: Action::SignIn {
            username: "test-account".into(),
            password: nestlink_auth::Secret::from_text("test-only-secret".into()),
            factor: None,
        },
    };
    let encoded = zeroize::Zeroizing::new(serde_json::to_vec(&action)?);
    let _: Command = serde_json::from_slice(&encoded)?;
    Ok(())
}
