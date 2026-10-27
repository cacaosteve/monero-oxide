# monero-oxide

monero-oxide is an organization to maintain and develop the `monero-oxide`
family of libraries, implementing large swaths of the Monero protocol in Rust.
For information on the organization's information, please see our
[governance document](./Governance.md).

The organization primarily develops and maintains two crates (with many crates
underneath them):

- [`monero-oxide`](./monero-oxide): A Rust implementation of the Monero
  blockchain protocol.
- [`monero-wallet`](./monero-oxide/wallet): Wallet functionality for the Monero
  protocol.

The latest copy of the documentation is available [here](
  https://monero-oxide.github.io/monero-oxide/monero_wallet/index.html
).

We welcome contributions, either via making issues or opening pull requests.
For the latter, please see our [contributing guidelines](./Contributing.md).

To report a security issue, please see our [disclosure policy](./Security.md).

## WalletCore fork: hash-to-point dependency maintenance

This fork requires Rust 1.87 or newer for `monero-ed25519` and its consumers
(wallet/daemon crates already require 1.89). The hash-to-point implementation uses
`crypto-bigint` 0.7.10 or newer, including the constant-time fixes for
[RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html)
and the subsequent upstream arithmetic fixes. It retains the same Elligator 2
algorithm, field modulus, encoding, sign selection, and cofactor multiplication.

`cargo test -p monero-ed25519 --test biased_hash` checks the Monero reference
vectors and a 4,610-input corpus digest captured from revision `34201e5` using
`crypto-bigint` 0.5.5 before the upgrade. This is compatibility regression
coverage, not independent proof of constant-time execution. Optional multisig
and development-only dependencies have separate maintenance requirements; this
change does not claim to upgrade their older `crypto-bigint` dependencies.
