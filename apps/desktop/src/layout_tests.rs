#![allow(clippy::expect_used)]
use super::*;
use eframe::App;
use nestlink_app_core::{InstallationView, ServerView};
use nestlink_protocol::api::{DeviceDescriptor, DeviceView, HealthResponse, Principal};
use std::{collections::HashMap, sync::Arc};

struct Workspace {
    context: egui::Context,
    app: DesktopApp,
    nodes: HashMap<egui::accesskit::NodeId, egui::accesskit::Node>,
    root: Option<egui::accesskit::NodeId>,
}

#[test]
fn namespace_ui_requires_explicit_revision_zero_and_isolates_selected_node() {
    use nestlink_app_core::{Failure, FailureKind};
    use nestlink_protocol::api::{NodeRegistration, NodeView};
    use nestlink_protocol::service_plane::publication::{
        ServiceEdgeNamespace, ServiceEdgeNamespaceView,
    };
    let mut snapshot = enrolled_snapshot();
    snapshot.nodes.data = Some(Arc::new(
        [
            "00000000-0000-4000-8000-000000000010",
            "00000000-0000-4000-8000-000000000011",
        ]
        .map(|id| NodeView {
            node: NodeRegistration {
                id: id.into(),
                name: id.into(),
                public_key: String::new(),
                roles: vec![2],
                max_connections: 10,
                bytes_per_second: 1000,
            },
            revoked: false,
            last_issued_at_unix_ms: 0,
            runtime_id: None,
            runtime_generation: 1,
        })
        .into_iter()
        .collect(),
    ));
    let size = egui::vec2(1400., 1200.);
    let mut workspace = Workspace::new(snapshot.clone());
    workspace.app.bridge.layout_enable_commands();
    workspace.app.screen = Screen::Nodes;
    for _ in 0..3 {
        workspace.frame(size, vec![]);
    }
    let select = |workspace: &mut Workspace, index: usize| {
        let bounds = workspace.bounds("公网入口配置");
        assert_eq!(bounds.len(), 2);
        let pos = bounds[index].center();
        for pressed in [true, false] {
            workspace.frame(
                size,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: Default::default(),
                    },
                ],
            );
        }
    };
    select(&mut workspace, 0);
    let submission = namespace_submission(&workspace);
    snapshot.revision += 1;
    snapshot.service_edge_namespace.error = Some(Failure {
        kind: FailureKind::Rejected,
        code: None,
        status: Some(403),
    });
    workspace.app.bridge.layout_snapshot(snapshot.clone());
    namespace_completion(&workspace, submission, &snapshot, false, false);
    workspace.frame(size, vec![]);
    assert!(
        workspace.bounds("保存").is_empty(),
        "denial must not create an editable empty namespace"
    );
    workspace.click(size, "首次配置");
    assert_eq!(workspace.bounds("配置版本 0").len(), 1);
    assert_eq!(workspace.bounds("保存").len(), 1);
    workspace.click(size, "重新读取");
    let submission = namespace_submission(&workspace);
    snapshot.revision += 1;
    snapshot.service_edge_namespace.error = None;
    snapshot.service_edge_namespace.data = Some(Arc::new(ServiceEdgeNamespaceView {
        node_id: "00000000-0000-4000-8000-000000000010".into(),
        revision: 5,
        config: ServiceEdgeNamespace {
            service_suffix: "services.example.com".into(),
            management_hostname: "manage.example.com".into(),
            public_ports: vec![29100],
            quic_address: "127.0.0.1:29101".into(),
        },
    }));
    workspace.app.bridge.layout_snapshot(snapshot.clone());
    namespace_completion(&workspace, submission, &snapshot, true, false);
    workspace.frame(size, vec![]);
    assert_eq!(workspace.bounds("配置版本 5").len(), 1);
    for (previous, edited) in [
        ("services.example.com", "draft.example.com"),
        ("manage.example.com", "admin.example.com"),
        ("29100", "29102, 29103"),
        ("127.0.0.1:29101", "127.0.0.2:29104"),
    ] {
        workspace.replace_text(size, previous, edited);
    }
    workspace.click(size, "保存");
    let submission = namespace_submission(&workspace);
    snapshot.service_edge_namespace.data = None;
    snapshot.service_edge_namespace.error = Some(Failure {
        kind: FailureKind::Rejected,
        code: None,
        status: Some(409),
    });
    workspace.app.bridge.layout_snapshot(snapshot.clone());
    namespace_completion(&workspace, submission, &snapshot, false, true);
    workspace.frame(size, vec![]);
    assert_eq!(
        workspace.bounds("配置版本 5").len(),
        1,
        "CAS failure must retain the user's draft"
    );
    for value in [
        "draft.example.com",
        "admin.example.com",
        "29102, 29103",
        "127.0.0.2:29104",
    ] {
        assert_eq!(
            workspace.bounds(value).len(),
            1,
            "save failure must retain {value}"
        );
    }
    assert!(workspace.bounds("首次配置").is_empty());
    workspace.click(size, "保存");
    assert!(
        workspace.app.bridge.layout_submission().is_none(),
        "save remains locked until an explicit read succeeds"
    );
    // Begin a read of A, then choose B before A's reply arrives.
    workspace.click(size, "重新读取");
    let late_a = namespace_submission(&workspace);
    select(&mut workspace, 1);
    let current_b = namespace_submission(&workspace);
    snapshot.revision += 1;
    snapshot.service_edge_namespace.error = None;
    snapshot.service_edge_namespace.data = Some(Arc::new(ServiceEdgeNamespaceView {
        node_id: "00000000-0000-4000-8000-000000000010".into(),
        revision: 6,
        config: ServiceEdgeNamespace {
            service_suffix: "a.example.com".into(),
            management_hostname: "manage.example.com".into(),
            public_ports: vec![29100],
            quic_address: "127.0.0.1:29101".into(),
        },
    }));
    // A late successful response for A cannot become B's editable CAS revision.
    workspace.app.bridge.layout_snapshot(snapshot.clone());
    namespace_completion(&workspace, late_a, &snapshot, true, false);
    workspace.frame(size, vec![]);
    assert!(workspace.bounds("配置版本 5").is_empty());
    assert!(workspace.bounds("保存").is_empty());
    let mut denied_a = snapshot.clone();
    denied_a.service_edge_namespace.error = Some(Failure {
        kind: FailureKind::Rejected,
        code: None,
        status: Some(403),
    });
    workspace.app.bridge.layout_snapshot(denied_a.clone());
    workspace.frame(size, vec![]);
    let old_error = widgets::failure(
        denied_a
            .service_edge_namespace
            .error
            .as_ref()
            .expect("A error"),
        false,
    );
    assert!(
        workspace.bounds(&old_error).is_empty(),
        "A section error must not appear in B's panel"
    );
    assert_eq!(workspace.bounds("正在读取公网入口…").len(), 1);
    namespace_completion(&workspace, late_a, &denied_a, false, false);
    workspace
        .app
        .bridge
        .layout_notice(bridge::Notice::Rejected {
            submission_id: Some(late_a),
            reason: nestlink_app_ipc::wire::Rejection::StaleGeneration,
        });
    workspace.frame(size, vec![]);
    assert!(workspace.bounds("首次配置").is_empty());
    assert!(workspace.bounds("保存").is_empty());
    snapshot.service_edge_namespace.data = Some(Arc::new(ServiceEdgeNamespaceView {
        node_id: "00000000-0000-4000-8000-000000000011".into(),
        revision: 9,
        config: ServiceEdgeNamespace {
            service_suffix: "b.example.com".into(),
            management_hostname: "manage.example.com".into(),
            public_ports: vec![29100],
            quic_address: "127.0.0.1:29101".into(),
        },
    }));
    workspace.app.bridge.layout_snapshot(snapshot.clone());
    namespace_completion(&workspace, current_b, &snapshot, true, false);
    workspace.frame(size, vec![]);
    assert_eq!(
        workspace.bounds("配置版本 9").len(),
        1,
        "B's matching reply must finish B's read"
    );
    workspace.click(size, "保存");
    let (submission, command) = workspace.app.bridge.layout_submission().expect("B save");
    assert!(
        matches!(command, nestlink_app_ipc::wire::Command::Submit { action: Action::SetServiceEdgeNamespace { node_id, update } } if node_id.ends_with("0011") && update.expected_revision == 9)
    );
    snapshot.service_edge_namespace.data =
        snapshot.service_edge_namespace.data.as_ref().map(|view| {
            let mut view = (**view).clone();
            view.revision = 10;
            Arc::new(view)
        });
    workspace.app.bridge.layout_snapshot(snapshot.clone());
    namespace_completion(&workspace, submission, &snapshot, true, true);
    workspace.frame(size, vec![]);
    assert_eq!(workspace.bounds("配置版本 10").len(), 1);
    let mut stale_section = snapshot.clone();
    stale_section.service_edge_namespace.error = denied_a.service_edge_namespace.error.clone();
    stale_section.service_edge_namespace.loading =
        Some(serde_json::from_str("99").expect("operation ID"));
    workspace.app.bridge.layout_snapshot(stale_section);
    workspace.frame(size, vec![]);
    assert!(workspace.bounds(&old_error).is_empty());
    assert!(workspace.bounds("正在加载…").is_empty());
    assert!(workspace.bounds("正在读取公网入口…").is_empty());
    workspace.app.bridge.layout_snapshot(snapshot.clone());
    // A's old denial and command rejection cannot unlock first-time setup or
    // replace B's successful result, even after B has finished.
    let mut old_a = snapshot.clone();
    old_a.service_edge_namespace.error = Some(Failure {
        kind: FailureKind::Rejected,
        code: None,
        status: Some(403),
    });
    namespace_completion(&workspace, late_a, &old_a, false, false);
    workspace
        .app
        .bridge
        .layout_notice(bridge::Notice::Rejected {
            submission_id: Some(late_a),
            reason: nestlink_app_ipc::wire::Rejection::StaleGeneration,
        });
    workspace.frame(size, vec![]);
    assert_eq!(workspace.bounds("配置版本 10").len(), 1);
    assert!(workspace.bounds("首次配置").is_empty());
    workspace.click(size, "保存");
    let (rejected, command) = workspace
        .app
        .bridge
        .layout_submission()
        .expect("B second save");
    assert!(matches!(command, nestlink_app_ipc::wire::Command::Submit {
        action: Action::SetServiceEdgeNamespace { node_id, update }
    } if node_id.ends_with("0011") && update.expected_revision == 10));
    workspace
        .app
        .bridge
        .layout_notice(bridge::Notice::Rejected {
            submission_id: Some(rejected),
            reason: nestlink_app_ipc::wire::Rejection::StaleGeneration,
        });
    workspace.frame(size, vec![]);
    assert_eq!(workspace.bounds("配置版本 10").len(), 1);
    workspace.click(size, "重新读取");
    let reload = namespace_submission(&workspace);
    namespace_completion(&workspace, reload, &snapshot, true, false);
    workspace.frame(size, vec![]);
    workspace.click(size, "重新读取");
    let _disconnected = namespace_submission(&workspace);
    workspace
        .app
        .bridge
        .layout_notice(bridge::Notice::Disconnected);
    workspace.frame(size, vec![]);
    assert_eq!(workspace.bounds("配置版本 10").len(), 1);
    workspace.click(size, "重新读取");
    let reload = namespace_submission(&workspace);
    namespace_completion(&workspace, reload, &snapshot, true, false);
    workspace.frame(size, vec![]);
    // The default layout bridge rejects sends. A send failure must retain the
    // draft and expose reload, rather than leaving an operation busy forever.
    workspace.app.bridge = Bridge::for_layout(snapshot);
    workspace.click(size, "保存");
    workspace.frame(size, vec![]);
    assert_eq!(workspace.bounds("配置版本 10").len(), 1);
    assert_eq!(workspace.bounds("请求未送出，请重新读取配置。").len(), 1);
    assert!(workspace.bounds("首次配置").is_empty());
    workspace.click(size, "重新读取");
    workspace.frame(size, vec![]);
    assert_eq!(workspace.bounds("请求未送出，请重新读取配置。").len(), 1);
}

fn namespace_submission(workspace: &Workspace) -> u64 {
    while let Some((submission, command)) = workspace.app.bridge.layout_submission() {
        if matches!(
            command,
            nestlink_app_ipc::wire::Command::Submit {
                action: Action::LoadServiceEdgeNamespace { .. }
                    | Action::SetServiceEdgeNamespace { .. }
            }
        ) {
            return submission;
        }
    }
    panic!("namespace command was not submitted");
}

fn namespace_completion(
    workspace: &Workspace,
    submission: u64,
    snapshot: &Snapshot,
    succeeded: bool,
    saving: bool,
) {
    workspace
        .app
        .bridge
        .layout_notice(bridge::Notice::Completed {
            submission_id: Some(submission),
            sensitive: None,
            result: nestlink_app_core::OperationResult {
                id: serde_json::from_str("1").expect("operation ID"),
                generation: snapshot.generation,
                kind: if saving {
                    nestlink_app_core::OperationKind::SetServiceEdgeNamespace
                } else {
                    nestlink_app_core::OperationKind::LoadServiceEdgeNamespace
                },
                status: if succeeded {
                    OperationStatus::Succeeded
                } else {
                    OperationStatus::Failed
                },
                remote_effect: nestlink_app_core::RemoteEffect::None,
                failure: snapshot.service_edge_namespace.error.clone(),
                output: nestlink_app_core::PublicOutput::None,
            },
        });
}

fn enrolled_snapshot() -> Snapshot {
    let mut snapshot = Snapshot {
        authentication: Authentication::SignedIn,
        principal: Some(Principal {
            account_id: "account".into(),
            session_id: "session".into(),
            name: "Admin".into(),
            is_admin: true,
            access_expires: u64::MAX,
        }),
        server: Some(ServerView {
            origin: "https://console.example.test/".into(),
            deployment_id: "deployment".into(),
            approved_issuer: [0; 32],
            error: None,
            verified_health: Some(HealthResponse {
                product: "NestLink".into(),
                version: "0.7.0-rc.1".into(),
                api_base: "/api".into(),
                alpn: "test".into(),
                deployment_id: "deployment".into(),
                security_epoch: 1,
                permit_issuer: String::new(),
                node_policy_issuer: String::new(),
            }),
        }),
        installation: Some(InstallationView {
            device_id: "00000000-0000-4000-8000-000000000001".into(),
            public_key_sha256: [0; 32],
        }),
        ..Snapshot::default()
    };
    snapshot.devices.data = Some(Arc::new(
        [
            "00000000-0000-4000-8000-000000000001",
            "00000000-0000-4000-8000-000000000002",
        ]
        .map(|id| DeviceView {
            device: DeviceDescriptor {
                id: id.into(),
                name: format!("Test computer {}", &id[id.len() - 1..]),
                platform: "windows".into(),
                public_key: String::new(),
                capabilities: vec!["host".into(), "view".into()],
                path_mode: "direct_preferred".into(),
            },
            revoked: false,
        })
        .into_iter()
        .collect(),
    ));
    snapshot.requests.data = Some(Arc::new(Vec::new()));
    snapshot
}

impl Workspace {
    fn new(snapshot: Snapshot) -> Self {
        let context = egui::Context::default();
        context.enable_accesskit();
        let tokens = theme::tokens().expect("tokens");
        theme::apply(&context, &tokens, false);
        theme::fonts(&context).expect("fonts");
        let mut app = DesktopApp::from_parts(
            PathBuf::new(),
            tokens,
            Bridge::for_layout(snapshot),
            None,
            None,
            MessageTone::Neutral,
        );
        app.screen = Screen::Remote;
        app.connected = true;
        // Layout fixtures start in an already attached workspace; draining
        // notices must not replace their explicitly selected page on frame one.
        app.workspace_attached = true;
        Self {
            context,
            app,
            nodes: HashMap::new(),
            root: None,
        }
    }

    fn frame(&mut self, size: egui::Vec2, events: Vec<egui::Event>) {
        // The native runner drains bridge replies in App::logic before ui.
        // Exercise that same state transition without maintenance/tray work.
        self.app.notices(&self.context);
        let output = self.context.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                events,
                ..Default::default()
            },
            |ui| self.app.ui(ui, &mut eframe::Frame::_new_kittest()),
        );
        let update = output
            .platform_output
            .accesskit_update
            .expect("accessibility tree");
        if let Some(tree) = update.tree {
            self.root = Some(tree.root);
        }
        self.nodes.extend(update.nodes);
    }

    fn bounds(&self, label: &str) -> Vec<egui::Rect> {
        let mut visible = Vec::new();
        let mut queue: Vec<_> = self.root.into_iter().collect();
        while let Some(id) = queue.pop() {
            if let Some(node) = self.nodes.get(&id) {
                visible.push(node);
                queue.extend(node.children());
            }
        }
        let mut rects: Vec<_> = visible
            .into_iter()
            .filter(|node| node.label().or_else(|| node.value()) == Some(label))
            .filter_map(|node| node.bounds())
            .map(|rect| {
                egui::Rect::from_min_max(
                    egui::pos2(rect.x0 as f32, rect.y0 as f32),
                    egui::pos2(rect.x1 as f32, rect.y1 as f32),
                )
            })
            .collect();
        rects.sort_by(|a, b| {
            a.min
                .y
                .total_cmp(&b.min.y)
                .then(a.min.x.total_cmp(&b.min.x))
        });
        rects
    }

    fn replace_text(&mut self, size: egui::Vec2, previous: &str, value: &str) {
        self.click(size, previous);
        self.frame(
            size,
            vec![egui::Event::Key {
                key: egui::Key::A,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers {
                    ctrl: true,
                    command: true,
                    ..Default::default()
                },
            }],
        );
        self.frame(
            size,
            vec![
                egui::Event::Key {
                    key: egui::Key::A,
                    physical_key: None,
                    pressed: false,
                    repeat: false,
                    modifiers: Default::default(),
                },
                egui::Event::Text(value.into()),
            ],
        );
        assert_eq!(self.bounds(value).len(), 1);
    }

    fn click(&mut self, size: egui::Vec2, label: &str) {
        let bounds = self.bounds(label);
        assert_eq!(bounds.len(), 1, "ambiguous or missing control: {label}");
        let pos = bounds[0].center();
        for pressed in [true, false] {
            self.frame(
                size,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: Default::default(),
                    },
                ],
            );
        }
    }
}

#[test]
fn bounded_remote_workspace_keeps_connection_action_visible_after_section_changes() {
    use nestlink_app_core::{Failure, FailureKind};
    for size in [egui::vec2(760., 560.), egui::vec2(1200., 800.)] {
        let mut workspace = Workspace::new(enrolled_snapshot());
        for _ in 0..5 {
            workspace.frame(size, Vec::new());
        }
        let baseline = workspace.bounds("进入桌面");
        assert_eq!(baseline.len(), 1);
        let viewport = egui::Rect::from_min_size(egui::Pos2::ZERO, size);
        assert!(
            viewport.contains_rect(baseline[0]),
            "connect action outside viewport: {baseline:?}"
        );
        let audio = workspace.bounds("系统声音");
        let view_only = workspace.bounds("仅查看");
        assert_eq!(audio.len(), 1);
        assert_eq!(view_only.len(), 1);
        assert!(
            viewport.contains_rect(audio[0]),
            "audio option outside the minimum workspace"
        );
        assert!(
            audio[0].top() > view_only[0].bottom(),
            "connection options inherited a horizontal parent layout"
        );
        workspace.click(size, "本机访问");
        assert!(
            workspace.bounds("进入桌面").is_empty(),
            "host settings did not replace the device workspace"
        );
        workspace.click(size, "连接设备");
        workspace.frame(size, Vec::new());
        assert_eq!(workspace.bounds("进入桌面"), baseline);
        for revision in 1..8 {
            let mut snapshot = enrolled_snapshot();
            snapshot.revision = revision;
            if revision % 2 == 0 {
                snapshot.devices.error = Some(Failure {
                    kind: FailureKind::Transport,
                    status: Some(503),
                    code: None,
                });
            } else {
                Arc::get_mut(snapshot.devices.data.as_mut().expect("devices"))
                    .expect("owned devices")[1]
                    .device
                    .name = "A very long computer name ".repeat(80);
                snapshot.requests.loading = Some(serde_json::from_str("1").expect("operation id"));
            }
            workspace.app.bridge.layout_snapshot(snapshot);
            workspace.frame(size, Vec::new());
            assert_eq!(
                workspace.bounds("进入桌面"),
                baseline,
                "polling moved the anchored connect action"
            );
        }
    }
}

#[test]
fn remote_workspace_controls_stay_still_between_frames() {
    for size in [
        egui::vec2(1200., 800.),
        egui::vec2(1000., 640.),
        egui::vec2(800., 560.),
    ] {
        let mut workspace = Workspace::new(enrolled_snapshot());
        // Allow fonts and the initial scroll measurement to settle.
        for _ in 0..5 {
            workspace.frame(size, Vec::new());
        }
        let labels = ["进入桌面", "刷新"];
        let baseline: Vec<_> = labels.iter().map(|label| workspace.bounds(label)).collect();
        assert!(
            baseline.iter().all(|rects| !rects.is_empty()),
            "missing controls: {baseline:?}"
        );
        for rect in baseline.iter().flatten() {
            assert!(
                rect.min.x >= 0. && rect.max.x <= size.x,
                "control extends outside viewport: {rect:?}"
            );
        }
        for frame in 0..20 {
            let mut snapshot = enrolled_snapshot();
            snapshot.revision = frame + 1;
            if frame % 2 == 0 {
                snapshot.requests.loading = Some(serde_json::from_str("1").expect("operation ID"));
                snapshot.devices.loading = Some(serde_json::from_str("2").expect("operation ID"));
            }
            workspace.app.bridge.layout_snapshot(snapshot);
            workspace.frame(size, Vec::new());
            let actual: Vec<_> = labels.iter().map(|label| workspace.bounds(label)).collect();
            assert_eq!(
                actual, baseline,
                "controls moved at {size:?}, frame {frame}"
            );
        }
    }
}

#[test]
fn refresh_indicator_does_not_move_the_following_button() {
    let context = egui::Context::default();
    theme::apply(&context, &theme::tokens().expect("tokens"), false);
    let mut section = nestlink_app_core::Section {
        data: Some(Arc::new(())),
        ..Default::default()
    };
    let mut baseline = None;
    for frame in 0..10 {
        section.loading =
            (frame % 2 == 0).then(|| serde_json::from_str("1").expect("operation ID"));
        let mut rect = egui::Rect::NOTHING;
        let _ = context.run_ui(Default::default(), |ui| {
            widgets::section(ui, &section, false);
            rect = ui.button("Save local consent").rect;
        });
        if let Some(baseline) = baseline {
            assert_eq!(rect, baseline, "loading state moved the save button");
        } else {
            baseline = Some(rect);
        }
    }
}

#[test]
fn a_refresh_and_notification_between_press_and_release_keep_the_click() {
    let size = egui::vec2(1200., 800.);
    let mut workspace = Workspace::new(enrolled_snapshot());
    for _ in 0..5 {
        workspace.frame(size, Vec::new());
    }
    let baseline = workspace.bounds("系统声音");
    assert_eq!(baseline.len(), 1, "audio checkbox must be accessible");
    let position = baseline[0].center();
    assert!(egui::Rect::from_min_size(egui::Pos2::ZERO, size).contains(position));
    workspace.frame(
        size,
        vec![
            egui::Event::PointerMoved(position),
            egui::Event::PointerButton {
                pos: position,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: Default::default(),
            },
        ],
    );
    let mut snapshot = enrolled_snapshot();
    snapshot.requests.loading = Some(serde_json::from_str("1").expect("operation ID"));
    workspace.app.bridge.layout_snapshot(snapshot);
    workspace.app.set_message(
        "网络请求失败，请刷新查看状态。".repeat(12),
        MessageTone::Danger,
    );
    workspace.frame(size, Vec::new());
    assert_eq!(workspace.bounds("系统声音"), baseline);
    workspace.frame(
        size,
        vec![egui::Event::PointerButton {
            pos: position,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: Default::default(),
        }],
    );
    assert!(
        workspace.app.remote.permissions[2],
        "refresh or notification swallowed the click"
    );
}

#[test]
fn refreshing_an_empty_device_list_keeps_the_connection_controls_in_place() {
    let empty = || {
        let mut snapshot = enrolled_snapshot();
        Arc::get_mut(snapshot.devices.data.as_mut().expect("device list"))
            .expect("exclusive test snapshot")
            .truncate(1);
        snapshot
    };
    let size = egui::vec2(800., 560.);
    let mut workspace = Workspace::new(empty());
    for _ in 0..5 {
        workspace.frame(size, Vec::new());
    }
    let baseline = workspace.bounds("进入桌面");
    assert_eq!(baseline.len(), 1);
    for frame in 0..10 {
        let mut snapshot = empty();
        if frame % 2 == 0 {
            snapshot.devices.loading = Some(serde_json::from_str("1").expect("operation ID"));
        }
        workspace.app.bridge.layout_snapshot(snapshot);
        workspace.frame(size, Vec::new());
        assert_eq!(
            workspace.bounds("进入桌面"),
            baseline,
            "empty list refresh moved the connection controls"
        );
    }
}

#[test]
fn incoming_requests_and_browser_host_lifecycle_do_not_push_device_controls() {
    use nestlink_app_core::{BrowserHostView, Failure, FailureKind};
    use nestlink_protocol::api::RemoteView;
    let size = egui::vec2(1200., 800.);
    let mut workspace = Workspace::new(enrolled_snapshot());
    for _ in 0..5 {
        workspace.frame(size, Vec::new());
    }
    let labels = ["进入桌面", "系统声音", "刷新"];
    let baseline: Vec<_> = labels.iter().map(|label| workspace.bounds(label)).collect();
    for phase in 0..12 {
        let mut snapshot = enrolled_snapshot();
        if phase % 3 == 1 {
            snapshot.browser_host.data = Some(Arc::new(BrowserHostView {
                request_id: "00000000-0000-4000-8000-000000000010".into(),
                connection_generation: 1,
                lease_sequence: 0,
                status: BrowserHostStatus::Establishing,
                host_view_authorized: false,
                binding: None,
                displays: nestlink_app_core::BrowserHostDisplayView {
                    approval_required: true,
                    ..Default::default()
                },
                data: Default::default(),
                path: None,
                stop_reason: None,
                stop_effects: None,
                cleanup: None,
                failure: None,
            }));
            snapshot.requests.data = Some(Arc::new(vec![RemoteView {
                id: "00000000-0000-4000-8000-000000000010".into(),
                controller_device_id: "00000000-0000-4000-8000-000000000002".into(),
                host_device_id: "00000000-0000-4000-8000-000000000001".into(),
                permissions: vec![1],
                paths: vec![1],
                nonce: "test".into(),
                policy_revision: 1,
                expires_at_unix_ms: u64::MAX,
                status: "pending".into(),
                lease_sequence: 0,
                connection_generation: 1,
                trust_revision: None,
                password_revision: None,
            }]));
        } else if phase % 3 == 2 {
            snapshot.browser_host.error = Some(Failure {
                kind: FailureKind::Transport,
                status: None,
                code: None,
            });
        }
        workspace.app.bridge.layout_snapshot(snapshot);
        workspace.frame(size, Vec::new());
        let actual: Vec<_> = labels.iter().map(|label| workspace.bounds(label)).collect();
        assert_eq!(
            actual, baseline,
            "host lifecycle or incoming requests moved the device controls"
        );
    }
}

fn browser_popup_snapshot() -> Snapshot {
    use nestlink_app_core::BrowserHostView;
    let mut snapshot = enrolled_snapshot();
    snapshot.browser_host.data = Some(Arc::new(BrowserHostView {
        request_id: "00000000-0000-4000-8000-000000000010".into(),
        connection_generation: 1,
        lease_sequence: 1,
        status: BrowserHostStatus::Connected,
        host_view_authorized: true,
        binding: None,
        displays: Default::default(),
        data: Default::default(),
        path: Some(1),
        stop_reason: None,
        stop_effects: None,
        cleanup: None,
        failure: None,
    }));
    snapshot
}

fn request_task_snapshot(status: &str) -> Snapshot {
    let mut snapshot = browser_popup_snapshot();
    let request = nestlink_protocol::api::RemoteView {
        id: "00000000-0000-4000-8000-000000000010".into(),
        controller_device_id: "00000000-0000-4000-8000-000000000002".into(),
        host_device_id: "00000000-0000-4000-8000-000000000001".into(),
        permissions: vec![1, 2, 3, 4, 5, 6, 7],
        paths: vec![1, 2],
        nonce: "test-only-nonce".into(),
        policy_revision: 1,
        expires_at_unix_ms: u64::MAX,
        status: status.into(),
        lease_sequence: u64::from(status == "approved"),
        connection_generation: 1,
        trust_revision: None,
        password_revision: None,
    };
    snapshot.selected_request.data = Some(Arc::new(request.clone()));
    snapshot.requests.data = Some(Arc::new(vec![request]));
    snapshot
}

#[test]
fn request_task_closes_when_approval_state_and_errors_change_during_a_click() {
    use nestlink_app_core::{Failure, FailureKind};
    for scale in [1., 1.25, 1.5, 2.] {
        for size in [egui::vec2(1200., 800.), egui::vec2(760., 560.)] {
            let mut workspace = Workspace::new(request_task_snapshot("pending"));
            workspace.context.set_pixels_per_point(scale);
            workspace.app.remote.selected = Some("00000000-0000-4000-8000-000000000010".into());
            for _ in 0..5 {
                workspace.frame(size, Vec::new());
            }
            let close = workspace.bounds("关闭详情");
            assert_eq!(close.len(), 1);
            workspace.frame(
                size,
                vec![
                    egui::Event::PointerMoved(egui::pos2(size.x * 0.5, size.y * 0.5)),
                    egui::Event::MouseWheel {
                        unit: egui::MouseWheelUnit::Point,
                        delta: egui::vec2(0., -240.),
                        phase: egui::TouchPhase::Move,
                        modifiers: Default::default(),
                    },
                ],
            );
            assert_eq!(
                workspace.bounds("关闭详情"),
                close,
                "scroll moved the request-task footer"
            );
            let position = close[0].center();
            workspace.frame(
                size,
                vec![
                    egui::Event::PointerMoved(position),
                    egui::Event::PointerButton {
                        pos: position,
                        button: egui::PointerButton::Primary,
                        pressed: true,
                        modifiers: Default::default(),
                    },
                ],
            );
            let mut snapshot = request_task_snapshot("approved");
            snapshot.revision = 2;
            snapshot.selected_request.error = Some(Failure {
                kind: FailureKind::Transport,
                status: Some(503),
                code: None,
            });
            workspace.app.bridge.layout_snapshot(snapshot);
            workspace.frame(size, Vec::new());
            assert_eq!(
                workspace.bounds("关闭详情"),
                close,
                "refresh moved close at scale {scale}"
            );
            workspace.frame(
                size,
                vec![egui::Event::PointerButton {
                    pos: position,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: Default::default(),
                }],
            );
            assert!(
                workspace.app.remote.selected.is_none(),
                "refresh swallowed request-task close at scale {scale}, size {size:?}, position {position:?}"
            );
        }
    }
}

#[test]
fn full_app_records_the_request_task_surface_in_the_private_layout_log() {
    let directory = std::env::temp_dir().join(format!(
        "nestlink-request-task-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    nestlink_platform_security::new_private_directory(&directory).expect("private test state");
    let result = std::panic::catch_unwind(|| {
        let mut workspace = Workspace::new(request_task_snapshot("pending"));
        workspace.app.directory = directory.clone();
        workspace.app.remote.selected = Some("00000000-0000-4000-8000-000000000010".into());
        workspace.frame(egui::vec2(1200., 800.), Vec::new());
        std::thread::sleep(Duration::from_millis(1100));
        workspace.frame(egui::vec2(1200., 800.), Vec::new());
        let text = std::fs::read_to_string(directory.join("local-session-layout.jsonl"))
            .expect("layout log");
        let rows: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("record"))
            .collect();
        assert!(
            rows.iter()
                .any(|row| row["event"] == "frame_heartbeat"
                    && row["request_task_requested"] == true)
        );
        assert!(rows.iter().any(|row| row["event"] == "window_geometry"
            && row["surface"] == "request_task"
            && row["sizing_pass"] == false));
        assert!(
            rows.iter()
                .any(|row| row["event"] == "button_geometry" && row["surface"] == "request_task")
        );
    });
    std::fs::remove_dir_all(directory).expect("remove private test state");
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[test]
fn full_app_popup_records_geometry_and_heartbeat_in_private_state_directory() {
    let directory = std::env::temp_dir().join(format!(
        "nestlink-app-layout-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    nestlink_platform_security::new_private_directory(&directory).expect("private test state");
    let result = std::panic::catch_unwind(|| {
        super::check_layout_diagnostics(&directory).expect("installed storage check");
        let mut workspace = Workspace::new(browser_popup_snapshot());
        workspace.app.directory = directory.clone();
        workspace.app.remote.browser_host_details = true;
        let size = egui::vec2(1200., 800.);
        for _ in 0..5 {
            workspace.frame(size, Vec::new());
        }
        std::thread::sleep(std::time::Duration::from_millis(1050));
        workspace.frame(size, Vec::new());
        let log = nestlink_platform_security::read_private(
            &directory.join("local-session-layout.jsonl"),
            65_536,
        )
        .expect("production full-app log");
        let rows: Vec<serde_json::Value> = std::str::from_utf8(&log)
            .expect("utf8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("jsonl"))
            .collect();
        for event in ["frame_heartbeat", "window_geometry", "button_geometry"] {
            assert!(
                rows.iter().any(|row| row["event"] == event),
                "missing {event}"
            );
        }
        assert!(rows.iter().any(|row| {
            row["event"] == "frame_heartbeat"
                && row["dialog_requested"] == true
                && row["geometry_records"]
                    .as_u64()
                    .is_some_and(|count| count > 0)
        }));
    });
    let _ = std::fs::remove_dir_all(directory);
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[test]
fn local_session_popup_action_stays_still_when_polling_reports_an_error() {
    use nestlink_app_core::{Failure, FailureKind};
    let size = egui::vec2(1200., 800.);
    let mut workspace = Workspace::new(browser_popup_snapshot());
    workspace.app.remote.browser_host_details = true;
    for _ in 0..5 {
        workspace.frame(size, Vec::new());
    }
    let baseline = workspace.bounds("停止会话");
    assert_eq!(baseline.len(), 1);
    for frame in 0..12 {
        let mut snapshot = browser_popup_snapshot();
        if frame % 2 == 0 {
            snapshot.browser_host.loading = Some(serde_json::from_str("1").expect("operation ID"));
            snapshot.browser_host.error = Some(Failure {
                kind: FailureKind::Transport,
                status: Some(503),
                code: None,
            });
        }
        workspace.app.bridge.layout_snapshot(snapshot);
        workspace.frame(size, Vec::new());
        assert_eq!(
            workspace.bounds("停止会话"),
            baseline,
            "popup moved at {frame}"
        );
    }
}

#[test]
fn local_session_popup_closes_when_an_error_arrives_during_a_click() {
    use nestlink_app_core::{Failure, FailureKind};
    for size in [egui::vec2(1200., 800.), egui::vec2(760., 560.)] {
        let mut workspace = Workspace::new(browser_popup_snapshot());
        workspace.app.remote.browser_host_details = true;
        for _ in 0..5 {
            workspace.frame(size, Vec::new());
        }
        let close = workspace.bounds("关闭");
        assert_eq!(close.len(), 1);
        let position = close[0].center();
        workspace.frame(
            size,
            vec![
                egui::Event::PointerMoved(position),
                egui::Event::PointerButton {
                    pos: position,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: Default::default(),
                },
            ],
        );
        let mut snapshot = browser_popup_snapshot();
        snapshot.browser_host.error = Some(Failure {
            kind: FailureKind::Transport,
            status: Some(503),
            code: None,
        });
        workspace.app.bridge.layout_snapshot(snapshot);
        workspace.frame(size, Vec::new());
        assert_eq!(workspace.bounds("关闭"), close);
        workspace.frame(
            size,
            vec![egui::Event::PointerButton {
                pos: position,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: Default::default(),
            }],
        );
        assert!(
            !workspace.app.remote.browser_host_details,
            "polling swallowed the popup close click"
        );
    }
}

#[test]
fn selecting_devices_and_refreshing_long_names_keep_the_entry_visible_and_fixed() {
    for size in [
        egui::vec2(1200., 800.),
        egui::vec2(1000., 640.),
        egui::vec2(760., 560.),
    ] {
        let mut workspace = Workspace::new(enrolled_snapshot());
        for _ in 0..5 {
            workspace.frame(size, Vec::new());
        }
        let baseline = workspace.bounds("进入桌面");
        assert_eq!(baseline.len(), 1);
        assert!(
            egui::Rect::from_min_size(egui::Pos2::ZERO, size - egui::vec2(0., 104.))
                .contains_rect(baseline[0]),
            "desktop entry is clipped at {size:?}: {baseline:?}"
        );
        let row = workspace.bounds("Test computer 2");
        assert_eq!(row.len(), 1);
        let position = row[0].center();
        workspace.frame(
            size,
            vec![
                egui::Event::PointerMoved(position),
                egui::Event::PointerButton {
                    pos: position,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: Default::default(),
                },
            ],
        );
        workspace.frame(
            size,
            vec![egui::Event::PointerButton {
                pos: position,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: Default::default(),
            }],
        );
        assert_eq!(
            workspace.app.remote.host_device_id.as_deref(),
            Some("00000000-0000-4000-8000-000000000002"),
            "device row did not accept click at {size:?}: {row:?}"
        );
        for phase in 0..12 {
            let mut snapshot = enrolled_snapshot();
            if phase % 3 != 0 {
                Arc::get_mut(snapshot.devices.data.as_mut().expect("devices"))
                    .expect("exclusive snapshot")[1]
                    .device
                    .name = "很长的设备名称 Long device name ".repeat(40);
                snapshot.devices.loading = Some(serde_json::from_str("1").expect("operation ID"));
            }
            workspace.app.bridge.layout_snapshot(snapshot);
            workspace.frame(size, Vec::new());
            assert_eq!(
                workspace.bounds("进入桌面"),
                baseline,
                "selection or name moved the entry at {size:?}"
            );
            assert!(
                workspace
                    .bounds("断开连接")
                    .iter()
                    .all(|rect| rect.max.x <= size.x)
            );
        }
    }
}

#[test]
fn local_session_popup_has_no_second_display_approval() {
    use nestlink_app_core::{BrowserHostDisplayView, DisplayDescriptor};
    let mut snapshot = browser_popup_snapshot();
    let host = Arc::make_mut(snapshot.browser_host.data.as_mut().expect("host"));
    host.displays = BrowserHostDisplayView {
        catalog: Some(nestlink_app_core::DisplayCatalogKey {
            request_id: host.request_id.clone(),
            connection_generation: 1,
            revision: 1,
            sha256: [1; 32],
        }),
        displays: vec![DisplayDescriptor {
            source: 1,
            left: 0,
            top: 0,
            width: 1920,
            height: 1080,
            label: "Main display".into(),
        }],
        approval_required: false,
        approved_sources: vec![1],
        initial_source: Some(1),
    };
    let mut workspace = Workspace::new(snapshot);
    workspace.app.remote.browser_host_details = true;
    for _ in 0..5 {
        workspace.frame(egui::vec2(1200., 800.), Vec::new());
    }
    assert!(workspace.bounds("批准并开始共享").is_empty());
    assert!(workspace.bounds("选择允许浏览器查看的屏幕").is_empty());
    assert_eq!(workspace.bounds("停止会话").len(), 1);
    assert_eq!(workspace.bounds("关闭").len(), 1);
}

#[cfg(windows)]
#[test]
fn embedded_remote_viewport_stops_gpu_and_uses_cpu() {
    let snapshot = enrolled_snapshot();
    let mut workspace = Workspace::new(snapshot.clone());
    workspace.app.gpu_video = gpu_video::GpuVideo::layout_active_presenter();
    workspace.app.native_control_enabled = true;
    workspace.app.native_ime_composing = true;
    assert!(workspace.app.gpu_video.active());
    assert!(!workspace.app.update_gpu_video(
        &workspace.context,
        &snapshot,
        true,
        egui::ViewportClass::EmbeddedWindow,
    ));
    assert!(!workspace.app.gpu_video.active());
    assert!(!workspace.app.gpu_video.ready());
    assert!(!workspace.app.native_control_enabled);
    assert!(!workspace.app.native_ime_composing);
    assert_eq!(workspace.app.bridge.compressed_authority_deadline(), 0);
    // Remaining embedded frames must not create a replacement GPU owner.
    assert!(!workspace.app.update_gpu_video(
        &workspace.context,
        &snapshot,
        true,
        egui::ViewportClass::EmbeddedWindow,
    ));
    assert!(!workspace.app.gpu_video.active());
}
