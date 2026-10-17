//! Freedesktop StatusNotifierItem and DBusMenu implementation.
//!
//! The worker owns its session-bus connection and never grants remote
//! authority. A tray is available only while a watcher reports a registered
//! host and remains the same watcher across the property call.
use super::*;
use std::{
    collections::HashMap,
    future::Future,
    sync::mpsc::SyncSender,
    thread::{self, JoinHandle},
};
use tokio::sync::watch;
use zbus::{
    Connection,
    connection::Builder,
    fdo,
    names::BusName,
    zvariant::{OwnedObjectPath, OwnedValue, Value},
};

const ITEM_PATH: &str = "/StatusNotifierItem";
const MENU_PATH: &str = "/StatusNotifierItem/Menu";
const WATCHER: &str = "org.kde.StatusNotifierWatcher";
const WATCHER_PATH: &str = "/StatusNotifierWatcher";
const WATCHER_INTERFACE: &str = "org.kde.StatusNotifierWatcher";
const POLL_INTERVAL: Duration = Duration::from_millis(750);
const RPC_BUDGET: Duration = Duration::from_millis(750);

type Pixmap = (i32, i32, Vec<u8>);
// StatusNotifierItem.ToolTip uses (icon name, icon pixmaps, title, description).
// Its D-Bus signature is (sa(iiay)ss).
type ToolTip = (String, Vec<Pixmap>, String, String);

pub(super) struct Worker {
    stop: watch::Sender<bool>,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    pub(super) fn start(
        icon: Icon,
        labels: Labels,
        sink: Sink,
        available: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let (stop, stopped) = watch::channel(false);
        let (ready, waiting) = std::sync::mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("nestlink-tray-dbus".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                let result = match runtime {
                    Ok(runtime) => runtime.block_on(run(
                        icon,
                        labels,
                        sink,
                        available.clone(),
                        stopped,
                        &ready,
                    )),
                    Err(error) => Err(error),
                };
                if let Err(error) = result {
                    available.store(false, Ordering::Release);
                    let _ = ready.try_send(Err(error));
                }
            })?;
        let mut worker = Self {
            stop,
            thread: Some(thread),
        };

        match waiting.recv_timeout(STARTUP) {
            Ok(Ok(())) => Ok(worker),
            Ok(Err(error)) => {
                worker.stop();
                Err(error)
            }
            Err(_) => {
                worker.stop();
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "session bus tray startup timed out",
                ))
            }
        }
    }

    pub(super) fn stop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn while_running<T>(
    stop: &mut watch::Receiver<bool>,
    future: impl Future<Output = T>,
) -> Option<T> {
    if *stop.borrow() {
        return None;
    }
    tokio::select! {
        biased;
        _ = stop.changed() => None,
        result = future => Some(result),
    }
}

async fn run(
    icon: Icon,
    labels: Labels,
    sink: Sink,
    available: Arc<AtomicBool>,
    mut stop: watch::Receiver<bool>,
    ready: &SyncSender<io::Result<()>>,
) -> io::Result<()> {
    let status = StatusNotifierItem {
        icon,
        sink: sink.clone(),
    };
    let menu = Menu { labels, sink };
    let builder = Builder::session()
        .map_err(io::Error::other)?
        .method_timeout(RPC_BUDGET)
        .serve_at(ITEM_PATH, status)
        .map_err(io::Error::other)?
        .serve_at(MENU_PATH, menu)
        .map_err(io::Error::other)?;
    let connection =
        match while_running(&mut stop, tokio::time::timeout(STARTUP, builder.build())).await {
            None => return Ok(()),
            Some(Err(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "session bus connection timed out",
                ));
            }
            Some(Ok(Err(error))) => return Err(io::Error::other(error)),
            Some(Ok(Ok(connection))) => connection,
        };
    let item_name = connection
        .unique_name()
        .map(ToString::to_string)
        .ok_or_else(|| io::Error::other("session bus did not assign a unique name"))?;
    let _ = ready.try_send(Ok(()));

    let mut registered_owner = None;
    let mut interval = tokio::time::interval(POLL_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let Some(result) = while_running(
            &mut stop,
            inspect_host(&connection, &item_name, &mut registered_owner),
        )
        .await
        else {
            break;
        };
        available.store(result.unwrap_or(false), Ordering::Release);
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            _ = interval.tick() => {},
        }
    }
    available.store(false, Ordering::Release);
    drop(connection);
    Ok(())
}

async fn inspect_host(
    connection: &Connection,
    item_name: &str,
    registered_owner: &mut Option<String>,
) -> Result<bool, zbus::Error> {
    let dbus = fdo::DBusProxy::new(connection).await?;
    let owner = match dbus.get_name_owner(watcher_name()?).await {
        Ok(owner) => owner.to_string(),
        Err(_) => {
            *registered_owner = None;
            return Ok(false);
        }
    };

    if registered_owner.as_deref() != Some(owner.as_str()) {
        let watcher =
            zbus::Proxy::new(connection, owner.as_str(), WATCHER_PATH, WATCHER_INTERFACE).await?;
        let _: () = watcher
            .call("RegisterStatusNotifierItem", &item_name)
            .await?;
        if dbus.get_name_owner(watcher_name()?).await?.as_str() != owner {
            *registered_owner = None;
            return Ok(false);
        }
        *registered_owner = Some(owner.clone());
    }

    let watcher =
        zbus::Proxy::new(connection, owner.as_str(), WATCHER_PATH, WATCHER_INTERFACE).await?;
    let host_registered: bool = watcher
        .get_property("IsStatusNotifierHostRegistered")
        .await?;
    let current_owner = dbus.get_name_owner(watcher_name()?).await?;
    Ok(host_registered && current_owner.as_str() == owner)
}

fn watcher_name() -> Result<BusName<'static>, zbus::Error> {
    WATCHER.try_into().map_err(Into::into)
}

struct StatusNotifierItem {
    icon: Icon,
    sink: Sink,
}

impl StatusNotifierItem {
    fn pixmap(&self) -> Vec<(i32, i32, Vec<u8>)> {
        let mut argb = Vec::with_capacity(self.icon.rgba.len());
        for pixel in self.icon.rgba.chunks_exact(4) {
            let alpha = u16::from(pixel[3]);
            let premultiply = |channel: u8| ((u16::from(channel) * alpha) / 255) as u8;
            argb.extend_from_slice(&[
                pixel[3],
                premultiply(pixel[0]),
                premultiply(pixel[1]),
                premultiply(pixel[2]),
            ]);
        }
        vec![(self.icon.width as i32, self.icon.height as i32, argb)]
    }
}

#[zbus::interface(name = "org.kde.StatusNotifierItem")]
impl StatusNotifierItem {
    fn activate(&self, _x: i32, _y: i32) {
        self.sink.send(Action::Open);
    }

    fn secondary_activate(&self, _x: i32, _y: i32) {
        self.sink.send(Action::Open);
    }

    fn context_menu(&self, _x: i32, _y: i32) {}

    fn scroll(&self, _delta: i32, _orientation: String) {}

    #[zbus(property)]
    fn category(&self) -> &'static str {
        "ApplicationStatus"
    }

    #[zbus(property)]
    fn id(&self) -> &'static str {
        "nestlink"
    }

    #[zbus(property)]
    fn title(&self) -> &'static str {
        "NestLink"
    }

    #[zbus(property)]
    fn status(&self) -> &'static str {
        "Active"
    }

    #[zbus(property)]
    fn window_id(&self) -> u32 {
        0
    }

    #[zbus(property)]
    fn icon_name(&self) -> &'static str {
        ""
    }

    #[zbus(property)]
    fn icon_pixmap(&self) -> Vec<(i32, i32, Vec<u8>)> {
        self.pixmap()
    }

    #[zbus(property)]
    fn overlay_icon_name(&self) -> &'static str {
        ""
    }

    #[zbus(property)]
    fn overlay_icon_pixmap(&self) -> Vec<(i32, i32, Vec<u8>)> {
        Vec::new()
    }

    #[zbus(property)]
    fn attention_icon_name(&self) -> &'static str {
        ""
    }

    #[zbus(property)]
    fn attention_icon_pixmap(&self) -> Vec<(i32, i32, Vec<u8>)> {
        Vec::new()
    }

    #[zbus(property)]
    fn attention_movie_name(&self) -> &'static str {
        ""
    }

    #[zbus(property)]
    fn tool_tip(&self) -> ToolTip {
        (
            String::new(),
            self.pixmap(),
            "NestLink".into(),
            String::new(),
        )
    }

    #[zbus(property)]
    fn menu(&self) -> Result<OwnedObjectPath, fdo::Error> {
        OwnedObjectPath::try_from(MENU_PATH).map_err(|error| fdo::Error::Failed(error.to_string()))
    }
}

struct Menu {
    labels: Labels,
    sink: Sink,
}

type MenuLayout = (i32, HashMap<String, OwnedValue>, Vec<OwnedValue>);

impl Menu {
    fn selected_properties(
        mut properties: HashMap<String, OwnedValue>,
        names: &[String],
    ) -> HashMap<String, OwnedValue> {
        if !names.is_empty() {
            properties.retain(|name, _| names.iter().any(|requested| requested == name));
        }
        properties
    }

    fn item_properties(
        label: Option<&str>,
        item_type: &str,
        names: &[String],
    ) -> fdo::Result<HashMap<String, OwnedValue>> {
        let mut properties = HashMap::<String, OwnedValue>::new();
        properties.insert("type".into(), Self::variant(item_type.to_owned())?);
        properties.insert("visible".into(), OwnedValue::from(true));
        if item_type != "separator" {
            properties.insert(
                "label".into(),
                Self::variant(label.unwrap_or_default().to_owned())?,
            );
            properties.insert("enabled".into(), OwnedValue::from(true));
        }
        Ok(Self::selected_properties(properties, names))
    }

    fn item(
        id: i32,
        label: Option<&str>,
        item_type: &str,
        names: &[String],
    ) -> fdo::Result<MenuLayout> {
        Ok((
            id,
            Self::item_properties(label, item_type, names)?,
            Vec::new(),
        ))
    }

    fn variant(value: String) -> fdo::Result<OwnedValue> {
        OwnedValue::try_from(Value::from(value))
            .map_err(|error| fdo::Error::Failed(error.to_string()))
    }

    fn root(&self, include_children: bool, names: &[String]) -> fdo::Result<MenuLayout> {
        let mut properties = HashMap::<String, OwnedValue>::new();
        properties.insert("children-display".into(), Self::variant("submenu".into())?);
        let properties = Self::selected_properties(properties, names);
        let children = if include_children {
            vec![
                OwnedValue::try_from(Value::from(Self::item(
                    1,
                    Some(&self.labels.open),
                    "standard",
                    names,
                )?))
                .map_err(|error| fdo::Error::Failed(error.to_string()))?,
                OwnedValue::try_from(Value::from(Self::item(2, None, "separator", names)?))
                    .map_err(|error| fdo::Error::Failed(error.to_string()))?,
                OwnedValue::try_from(Value::from(Self::item(
                    3,
                    Some(&self.labels.exit),
                    "standard",
                    names,
                )?))
                .map_err(|error| fdo::Error::Failed(error.to_string()))?,
            ]
        } else {
            Vec::new()
        };
        Ok((0_i32, properties, children))
    }

    fn properties_for(
        id: i32,
        label: &str,
        item_type: &str,
        names: &[String],
    ) -> fdo::Result<(i32, HashMap<String, OwnedValue>)> {
        Ok((id, Self::item_properties(Some(label), item_type, names)?))
    }
}

#[zbus::interface(name = "com.canonical.dbusmenu")]
impl Menu {
    fn get_layout(
        &self,
        parent_id: i32,
        recursion_depth: i32,
        property_names: Vec<String>,
    ) -> fdo::Result<(u32, MenuLayout)> {
        match parent_id {
            0 => Ok((1, self.root(recursion_depth != 0, &property_names)?)),
            1 => Ok((
                1,
                Self::item(1, Some(&self.labels.open), "standard", &property_names)?,
            )),
            2 => Ok((1, Self::item(2, None, "separator", &property_names)?)),
            3 => Ok((
                1,
                Self::item(3, Some(&self.labels.exit), "standard", &property_names)?,
            )),
            _ => Err(fdo::Error::InvalidArgs("unknown menu item".into())),
        }
    }

    fn get_group_properties(
        &self,
        ids: Vec<i32>,
        property_names: Vec<String>,
    ) -> fdo::Result<Vec<(i32, HashMap<String, OwnedValue>)>> {
        ids.into_iter()
            .map(|id| match id {
                1 => Self::properties_for(id, &self.labels.open, "standard", &property_names),
                2 => Self::properties_for(id, "", "separator", &property_names),
                3 => Self::properties_for(id, &self.labels.exit, "standard", &property_names),
                _ => Err(fdo::Error::InvalidArgs("unknown menu item".into())),
            })
            .collect()
    }

    fn event(&mut self, id: i32, event_id: String, _data: OwnedValue, _timestamp: u32) {
        if event_id == "clicked" {
            match id {
                1 => self.sink.send(Action::Open),
                3 => self.sink.send(Action::Exit),
                _ => {}
            }
        }
    }

    fn event_group(&mut self, events: Vec<(i32, String, OwnedValue, u32)>) -> Vec<(i32, String)> {
        let mut errors = Vec::new();
        for (id, event_id, data, timestamp) in events {
            if !(1..=3).contains(&id) {
                errors.push((id, "unknown_id".into()));
            } else {
                self.event(id, event_id, data, timestamp);
            }
        }
        errors
    }

    fn about_to_show(&self, _id: i32) -> bool {
        false
    }

    fn about_to_show_group(&self, _ids: Vec<i32>) -> (Vec<i32>, Vec<i32>) {
        (Vec::new(), Vec::new())
    }

    #[zbus(property)]
    fn version(&self) -> u32 {
        3
    }

    #[zbus(property)]
    fn text_direction(&self) -> &'static str {
        "ltr"
    }

    #[zbus(property)]
    fn status(&self) -> &'static str {
        "normal"
    }

    #[zbus(property)]
    fn icon_theme_path(&self) -> Vec<String> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::zvariant::Type;
    #[test]
    fn status_item_icon_is_argb_and_menu_children_are_variants() {
        let item = StatusNotifierItem {
            icon: Icon {
                width: 16,
                height: 16,
                rgba: [255, 0, 0, 128].repeat(16 * 16),
            },
            sink: Sink {
                actions: std::sync::mpsc::sync_channel(1).0,
                wake: Arc::new(|| {}),
            },
        };
        let pixmap = item.pixmap();
        assert_eq!(pixmap[0].0, 16);
        assert_eq!(pixmap[0].1, 16);
        assert_eq!(&pixmap[0].2[..4], &[128, 128, 0, 0]);

        // Check the freedesktop wire contract, including the pixmap array and
        // description string. A wrong property signature breaks real hosts.
        assert_eq!(ToolTip::SIGNATURE.to_string(), "(sa(iiay)ss)");
        let tooltip = item.tool_tip();
        assert_eq!(tooltip.1, pixmap);
        assert_eq!(tooltip.2, "NestLink");
        assert!(tooltip.3.is_empty());

        let menu = Menu {
            labels: Labels {
                open: "Open".into(),
                exit: "Exit".into(),
            },
            sink: item.sink,
        };
        let root = menu.root(true, &[]);
        assert!(root.is_ok());
        if let Ok(root) = root {
            assert_eq!(MenuLayout::SIGNATURE.to_string(), "(ia{sv}av)");
            assert_eq!(root.2.len(), 3);
        }
    }
}
