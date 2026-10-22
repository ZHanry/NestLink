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
        Self {
            context,
            app,
            nodes: HashMap::new(),
            root: None,
        }
    }

    fn frame(&mut self, size: egui::Vec2, events: Vec<egui::Event>) {
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
