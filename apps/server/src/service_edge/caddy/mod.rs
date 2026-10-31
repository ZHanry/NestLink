//! Dedicated, private Caddy control. Route workers survive dropped observers
//! until DELETE and subsequent absence are both acknowledged by Caddy.
use super::*;
use futures_util::FutureExt;
use serde_json::{Value, json};
use std::net::SocketAddr;
use tokio::sync::{mpsc, watch};
mod admin;
mod config;
mod dns;
mod route;
pub use config::{CaddyAdmin, CaddyServiceConfig,CaddyEdgeGroupConfig};

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Pending,
    Ready,
    Removing,
    Removed,
}
struct Entry {
    id: String,
    node_id: String,
    service_suffix: String,
    service_id: String,
    hostname: String,
    scheme: &'static str,
    private_address: SocketAddr,
    private_token: String,
    probe_path: String,
    probe_response: String,
    publication: ServicePublicationHandle,
    node: Arc<NodeControl>,
    connection: Connection,
    edge_group: Option<nestlink_protocol::service_plane::group::ServiceEdgeGroupBinding>,
    stop: watch::Sender<bool>,
    state: watch::Sender<State>,
}
impl Entry {
    fn stopped(&self) -> bool {
        *self.stop.borrow()
            || self.connection.close_reason().is_some()
            || *self.node.stopped().borrow()
            || self
                .publication
                .lease()
                .and_then(|lease| self.node.inspect_service_lease(&lease).map_err(Into::into))
                .is_err()
    }
}
struct Registry {
    entries: HashMap<String, Arc<Entry>>,
    stopping: bool,
}
#[derive(Clone)]
pub(super) struct Controller {
    sender: mpsc::Sender<Arc<Entry>>,
    registry: Arc<Mutex<Registry>>,
    node_id: String,
    deployment_id: String,
    service_suffix: String,
    failure: watch::Sender<bool>,
    edge_group: Option<CaddyEdgeGroupConfig>,
    public_ips: Vec<IpAddr>,
}
pub(super) struct Driver {
    controller: Controller,
    worker: Option<tokio::task::JoinHandle<io::Result<()>>>,
}
pub(super) struct Route {
    entry: Arc<Entry>,
    state: watch::Receiver<State>,
}
impl Drop for Route {
    fn drop(&mut self) {
        self.entry.stop.send_replace(true);
    }
}
impl Route {
    pub(super) async fn ready(&mut self) -> io::Result<()> {
        loop {
            match *self.state.borrow() {
                State::Ready => return Ok(()),
                State::Removing | State::Removed => return Err(denied()),
                State::Pending => {}
            }
            self.state.changed().await.map_err(fault)?;
        }
    }
    pub(super) async fn ended(&mut self) {
        loop {
            if matches!(*self.state.borrow(), State::Removing | State::Removed) {
                return;
            }
            if self.state.changed().await.is_err() {
                return;
            }
        }
    }
    pub(super) async fn close(&mut self) {
        self.entry.stop.send_replace(true);
        loop {
            if *self.state.borrow() == State::Removed {
                return;
            }
            if self.state.changed().await.is_err() {
                return;
            }
        }
    }
}
impl Controller {
    pub(super) async fn start(
        config: CaddyServiceConfig,
        namespace: &ServiceEdgeNamespaceView,
    ) -> io::Result<Driver> {
        let node_id = &namespace.node_id;
        config.validate()?;
        if !valid_id(node_id) {
            return Err(denied());
        }
        let admin = admin::Admin::new(&config)?;
        admin
            .reconcile(node_id, &namespace.config.service_suffix)
            .await?;
        let (sender, mut receiver) = mpsc::channel::<Arc<Entry>>(SERVICE_PUBLICATIONS_PER_NODE);
        let (failure, _) = watch::channel(false);
        let controller = Self {
            sender,
            registry: Arc::new(Mutex::new(Registry {
                entries: HashMap::new(),
                stopping: false,
            })),
            node_id: node_id.into(),
            deployment_id: config.deployment_id.clone(),
            service_suffix: namespace.config.service_suffix.clone(),
            failure,
            edge_group:config.edge_group.clone(),
            public_ips:config.public_ips.clone(),
        };
        let copy = controller.clone();
        let config = Arc::new(config);
        let worker = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            let mut failed = false;
            let mut tick = tokio::time::interval(Duration::from_millis(25));
            loop {
                let stopping = copy.registry.lock().map_err(|_| denied())?.stopping;
                if stopping {
                    receiver.close();
                }
                if stopping && tasks.is_empty() && receiver.is_empty() {
                    return if failed { Err(denied()) } else { Ok(()) };
                }
                tokio::select! {biased;
                    Some(joined)=tasks.join_next()=>{
                        if !matches!(joined,Ok(false)) {
                            failed=true;copy.failure.send_replace(true);
                            let mut registry=copy.registry.lock().map_err(|_|denied())?;registry.stopping=true;
                            for entry in registry.entries.values(){entry.stop.send_replace(true);}
                        }
                    },
                    Some(entry)=receiver.recv()=>{
                        let config=config.clone();let admin=admin.clone();let registry=copy.registry.clone();
                        tasks.spawn(async move {
                            let panicked=std::panic::AssertUnwindSafe(route::run(&config,&admin,&entry)).catch_unwind().await.is_err();
                            if panicked {
                                entry.stop.send_replace(true);entry.state.send_replace(State::Removing);
                                route::cleanup(&admin,&entry).await;
                            }
                            if let Ok(mut registry)=registry.lock()
                                && registry.entries.get(&entry.hostname).is_some_and(|current|Arc::ptr_eq(current,&entry)) {
                                registry.entries.remove(&entry.hostname);
                            }
                            panicked
                        });
                    },
                    _=tick.tick()=>{},
                }
            }
        });
        Ok(Driver {
            controller,
            worker: Some(worker),
        })
    }
    pub(super) fn register(
        &self,
        ingress: &nestlink_node::service_plane::ServiceWebIngress,
        publication: ServicePublicationHandle,
        node: Arc<NodeControl>,
        connection: Connection,
    ) -> io::Result<Route> {
        let lease = publication.lease().map_err(fault)?;
        let c = lease.claims();
        if c.deployment_id != self.deployment_id || c.edge_node_id() != self.node_id {
            return Err(denied());
        }
        match (&self.edge_group,&c.edge_group) {
            (None,None)=>{},
            (Some(selected),Some(binding)) if selected.group_id==binding.group.group_id
                && selected.revision==binding.group.revision && selected.aggregate_sha256==binding.aggregate_sha256
                && self.public_ips==binding.group.public_ips
                && binding.group.member(&self.node_id).is_ok_and(|member|member.ingress_ip==selected.ingress_ip)=>{},
            _=>return Err(denied()),
        }
        let (stop, _) = watch::channel(false);
        let (state, rx) = watch::channel(State::Pending);
        let entry = Arc::new(Entry {
            id: format!("nestlink-pub-{}-{}", self.node_id, uuid::Uuid::new_v4()),
            node_id: self.node_id.clone(),
            service_suffix: self.service_suffix.clone(),
            service_id: c.service_id.clone(),
            hostname: ingress.hostname().into(),
            scheme: ingress.scheme(),
            private_address: ingress.private_address().map_err(fault)?,
            private_token: ingress.private_token().into(),
            probe_path: format!(
                "/.well-known/nestlink-ready/{}",
                uuid::Uuid::new_v4().simple()
            ),
            probe_response: uuid::Uuid::new_v4().simple().to_string(),
            publication,
            node,
            connection,
            edge_group:c.edge_group.clone(),
            stop,
            state,
        });
        let mut registry = self.registry.lock().map_err(|_| denied())?;
        if registry.stopping
            || registry.entries.len() >= SERVICE_PUBLICATIONS_PER_NODE
            || registry.entries.contains_key(&entry.hostname)
        {
            return Err(denied());
        }
        registry
            .entries
            .insert(entry.hostname.clone(), entry.clone());
        if self.sender.try_send(entry.clone()).is_err() {
            registry.entries.remove(&entry.hostname);
            return Err(denied());
        }
        Ok(Route { entry, state: rx })
    }
    pub(super) async fn failed(&self) {
        let mut failed = self.failure.subscribe();
        loop {
            if *failed.borrow() {
                return;
            }
            if failed.changed().await.is_err() {
                return;
            }
        }
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        // Cancellation requests a cooperative stop. The retained driver task
        // keeps all routes until Caddy acknowledges actual removal.
        if let Ok(mut registry) = self.controller.registry.lock() {
            registry.stopping = true;
            for entry in registry.entries.values() {
                entry.stop.send_replace(true);
            }
        }
    }
}
impl Driver {
    pub(super) fn controller(&self) -> Controller {
        self.controller.clone()
    }
    pub(super) async fn shutdown(mut self) -> io::Result<()> {
        {
            let mut registry = self.controller.registry.lock().map_err(|_| denied())?;
            registry.stopping = true;
            for entry in registry.entries.values() {
                entry.stop.send_replace(true);
            }
        }
        self.worker
            .take()
            .ok_or_else(denied)?
            .await
            .map_err(fault)??;
        if !self
            .controller
            .registry
            .lock()
            .map_err(|_| denied())?
            .entries
            .is_empty()
        {
            return Err(denied());
        }
        Ok(())
    }
}
