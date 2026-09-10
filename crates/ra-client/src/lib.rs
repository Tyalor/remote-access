//! Client-side library: resolve an ID, probe endpoints, run the password
//! pairing exchange, and drive the Moonlight binary. Shared by the `ra` CLI
//! and the `ra-desk` GUI.

pub mod config;
pub mod moonlight;
pub mod session;

pub use config::ClientConfig;
pub use session::{Resolved, Session};
