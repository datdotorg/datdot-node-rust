# DatDot

a p2p solution for hosting files with Dat protocol ([...more](https://github.com/playproject-io/datdot-substrate/issues/12))

join our [telegram](https://t.me/joinchat/CgTftxXJvp6iYayqDjP7lQ) or [gitter](https://gitter.im/playproject-io/community) chat.

Clone this from [Radicle](https://radicle.xyz):
`rad:git:hnrkrtkf5e393g6ygndd7jky5z5ko9xwpg3yy`

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
