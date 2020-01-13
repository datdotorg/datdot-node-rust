# DatDot
a p2p solution for hosting files with Dat protocol ([...more](https://github.com/playproject-io/datdot-substrate/issues/12))

join our [telegram](https://t.me/joinchat/CgTftxXJvp6iYayqDjP7lQ) or [gitter](https://gitter.im/playproject-io/community) chat

![](https://i.imgur.com/oGPIbZQ.jpg)

datdot code is currently located in `bin/node`

currently datdot modules and runtime are "spliced" into the default substrate node cli - with custom governance, and most unneeded features removed. After the runtime module has a stable api, the scaffolding will be reduced and this repo will consist of a minimal test node and FRAME pallet.

### Building

to build the datdot dev runtime, run:

`cargo build -p node-runtime`

to build the test node, run:

`cargo build -p node-cli`

add the `--release` flag to either of those commands to create a release build - debug and release builds will be located in `./target/release` or `./target/debug`

### Running

currently, executing `./target/release/substrate --dev` (or `./target/debug/substrate --dev` if you didn't use a `--release` flag) runs a dev node. You can interact with this node by using the [Polkadot.js Apps UI](https://polkadot.js.org/apps/) - selecting "local node" as your endpoint in the settings page should connect you to your node; however, until you [specify the additional types](https://polkadot.js.org/api/start/types.extend.html#user-defined-types) in the developer tab, all functionality of the Apps UI will remain disabled.

Optionally, additionally running with `--execution Native` (case sensitive) will allow you to see more verbose logging from parts of the runtime using `native::info!(...)` calls.

``` 

    Datdot is built using Substrate - Original Readme:

```
# Substrate &middot; [![GitHub license](https://img.shields.io/github/license/paritytech/substrate)](LICENSE) [![GitLab Status](https://gitlab.parity.io/parity/substrate/badges/master/pipeline.svg)](https://gitlab.parity.io/parity/substrate/pipelines) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](docs/CONTRIBUTING.adoc)

Substrate is a next-generation framework for blockchain innovation.

## Trying it out

Simply go to [substrate.dev](https://substrate.dev) and follow the [getting started](https://substrate.dev/docs/en/overview/getting-started/) instructions.

## Contributions & Code of Conduct

Please follow the contributions guidelines as outlined in [`docs/CONTRIBUTING.adoc`](docs/CONTRIBUTING.adoc). In all communications and contributions, this project follows the [Contributor Covenant Code of Conduct](docs/CODE_OF_CONDUCT.adoc).

## Security

The security policy and procedures can be found in [`docs/SECURITY.md`](docs/SECURITY.md).

## License

Substrate is [GPL 3.0 licensed](LICENSE).
