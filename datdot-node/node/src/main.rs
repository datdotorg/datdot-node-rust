//! Kitchen Node CLI library.

#![warn(missing_docs)]
#![warn(unused_extern_crates)]

pub mod chain_spec;
mod service;
mod cli;
mod command;
mod rpc;

pub use cli::*;
pub use command::*;

fn main() -> sc_cli::Result<()> {
	command::run()
}
