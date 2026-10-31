//! Linux subnet gateways use a completely owned namespace. The ordinary
//! process owns online business/transport; the separate root process owns only
//! a bounded public plan, mature kernel networking and its protected journal.
mod helper;
mod journal;
mod kernel;
#[cfg(test)]
mod native_tests;
mod owner;
mod pipe;
mod plan;
mod wireguard;
mod worker;

use crate::{
    network_packet_runtime::Result,
    space_dns_system::{process_identity, require_system_admin, system_wall_ms},
};
use plan::{Plan, Receipt};
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};

pub(crate) use helper::{SystemSubnetArgs, run};
pub(crate) use owner::{SubnetArgs, run as run_owner};
pub(crate) use wireguard::owner::{PortalArgs as WireGuardPortalArgs, run as run_wireguard_portal};
pub(crate) use worker::{SubnetWorkerArgs, run as run_worker};
