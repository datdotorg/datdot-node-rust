# DatDot
a p2p solution for hosting files with Dat protocol ([...more](https://github.com/playproject-io/datdot-substrate/issues/12))

join our [telegram](https://t.me/joinchat/CgTftxXJvp6iYayqDjP7lQ) or [gitter](https://gitter.im/playproject-io/community) chat

![](https://i.imgur.com/oGPIbZQ.jpg)

datdot code is currently located in `pallets/datdot`.

the template node uses instant-seal consensus, and a minimal runtime.

### Building

to build the datdot dev runtime, run:

`cargo build -p datdot-runtime`

to build the test node, run:

`cargo build -p datdot-node` 

add the `--release` flag to either of those commands to create a release build - debug and release builds will be located in `./target/release` or `./target/debug` respectively.

### Note

If you are having trouble building with the commands above, you can try this recipe (shared by @erangell)

```bash
git clone https://github.com/playproject-io/datdot-substrate.git
curl --proto '=https' --tlsv1.2 https://sh.rustup.rs/ -sSf | sh
rustup toolchain install nightly-2020-08-14
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
rustup default nightly-2020-08-14
rustup update
rustup update nightly-2020-08-14
rustup target add wasm32-unknown-unknown --toolchain nightly-2020-08-14
cargo +nightly-2020-08-14 check 
cargo build -p datdot-node --release
```

### Custom Types

You can aggregate the custom types of any pallets in `datdot-node/pallets` by running: 
`node datdot-node/runtime/aggregate_types.js`
This will produce a `types.json` file.

Performing this requires each pallet defined in `aggregate_types.js` have their own types.json file premade.

### Running

currently, executing `./target/release/datdot-node --dev` (or `./target/debug/datdot-node --dev` if you didn't use a `--release` flag) runs a dev node. You can interact with this node by using the [Polkadot.js Apps UI](https://polkadot.js.org/apps/) - selecting "local node" as your endpoint in the settings page should connect you to your node; however, until you [specify the additional types](https://polkadot.js.org/api/start/types.extend.html#user-defined-types) in the developer tab, all functionality of the Apps UI will remain disabled.

Optionally, additionally running with `--execution Native` (case sensitive) will allow you to see more verbose logging from parts of the runtime using `native::info!(...)` calls.

NOTE: due to the nature of the instantseal consensus used in this node implementation, there is no concept of finality.

``` 

    Datdot is built using Substrate - Original Readme:

```
# Substrate &middot; [![GitHub license](https://img.shields.io/github/license/paritytech/substrate)](LICENSE) [![GitLab Status](https://gitlab.parity.io/parity/substrate/badges/master/pipeline.svg)](https://gitlab.parity.io/parity/substrate/pipelines) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](docs/CONTRIBUTING.adoc)

Substrate is a next-generation framework for blockchain innovation.

## Trying it out

Simply go to [substrate.dev](https://substrate.dev) and follow the [getting started](https://substrate.dev/docs/en/) instructions.

## Contributions & Code of Conduct

Please follow the contributions guidelines as outlined in [`docs/CONTRIBUTING.adoc`](docs/CONTRIBUTING.adoc). In all communications and contributions, this project follows the [Contributor Covenant Code of Conduct](docs/CODE_OF_CONDUCT.adoc).

## Security

The security policy and procedures can be found in [`docs/SECURITY.md`](docs/SECURITY.md).

## License

Substrate is [GPL 3.0 licensed](LICENSE).
