# DatDot

a p2p solution for hosting files with Dat protocol ([...more](https://github.com/playproject-io/datdot-substrate/issues/12))

join our [telegram](https://t.me/joinchat/CgTftxXJvp6iYayqDjP7lQ) or [gitter](https://gitter.im/playproject-io/community) chat.

Clone this from [Radicle](https://radicle.xyz):
`rad:git:hwd1yre84t7u59qhg5itq7ut6c5oa7r8fmmyb43rx4mjbto74jsr1n68e1w`

![](https://i.imgur.com/oGPIbZQ.jpg)

datdot code is currently located in `pallets/datdot`.

### Building

to build the datdot dev runtime, run:

`cargo build -p datdot-runtime`

to build the test node, run:

`cargo build -p node-template` 

add the `--release` flag to either of those commands to create a release build - debug and release builds will be located in `./target/release` or `./target/debug` respectively.

### Running

currently, executing `./target/release/node-template --dev` (or `./target/debug/node-template --dev` if you didn't use a `--release` flag) runs a dev node. You can interact with this node by using the [Polkadot.js Apps UI](https://polkadot.js.org/apps/) - selecting "local node" as your endpoint in the settings page should connect you to your node; however, until you [specify the additional types](https://polkadot.js.org/api/start/types.extend.html#user-defined-types) in the developer tab, all functionality of the Apps UI will remain disabled.

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
