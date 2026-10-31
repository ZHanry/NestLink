//! Linux subnet gateways use a completely owned namespace. The ordinary
//! process owns online business/transport; the separate root process owns only
//! a bounded public plan, mature kernel networking and its protected journal.
mod plan;
mod pipe;
mod kernel;
mod journal;
mod helper;
mod worker;
mod owner;
mod wireguard;
#[cfg(test)]
mod native_tests;

use crate::{network_packet_runtime::Result,space_dns_system::{process_identity,system_wall_ms,require_system_admin}};
use std::{io,path::{Path,PathBuf},time::Duration};
use serde::{Deserialize,Serialize};
use plan::{Plan,Receipt};

pub(crate) use owner::{SubnetArgs,run as run_owner};
pub(crate) use helper::{SystemSubnetArgs,run};
pub(crate) use worker::{SubnetWorkerArgs,run as run_worker};
pub(crate) use wireguard::owner::{PortalArgs as WireGuardPortalArgs,run as run_wireguard_portal};
