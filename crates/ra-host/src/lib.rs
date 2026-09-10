//! Host agent library (also used by `ra-desk` to show the local ID and
//! change the access password).
pub mod agent;
pub mod apollo;
pub mod config;

pub use agent::{pretty_id, Agent};
pub use config::Config;
