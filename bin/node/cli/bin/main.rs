// Copyright 2018-2020 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

//! Substrate Node CLI

#![warn(missing_docs)]

use sc_cli::VersionInfo;

fn main() -> sc_cli::Result<()> {
<<<<<<< HEAD
	let version = VersionInfo {
		name: "Datdot Node",
		commit: env!("VERGEN_SHA_SHORT"),
		version: env!("CARGO_PKG_VERSION"),
		executable_name: "datdot-node",
		author: "Datdot Authors <placeholder@email.com>",
		description: "Datdot Service Node",
		support_url: "https://github.com/playproject-io/datdot",
		copyright_start_year: 2019,
	};

	node_cli::run(std::env::args(), version)
=======
	node_cli::run()
>>>>>>> 028a71594f93edc1c105c85f425760943a362f8e
}
