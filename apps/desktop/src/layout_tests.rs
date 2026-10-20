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
