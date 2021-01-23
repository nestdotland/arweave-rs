<p align="center">

<img src="logo.png" />

<p align="center">
    <code>arweave_rs</code>
</center>

</p>

Arweave Rust SDK.

> Currently, it supports most of HTTP API interaction. Wallet signing, sending
> transactions is WIP.

### `installation`

Add arweave_rs to your Cargo.toml

```toml
[dependencies]
arweave_rs = { git = "https://github.com/nestdotland/arweave-rs" }
```

### `example`

```rust
use arweave_rs::api::{Api, Protocol};
use arweave_rs::tx::Transaction;

// Interact with the HTTP API
let api = Api::new("arweave.net", Protocol::HTTPS, 443);
let height = api.network_info().await?;

// Work with transactions
let txs = Transaction::new(api);
let price = txs.get_price("100", "vT90H6CshD4xHzIU9h6gUF3WsTOuj2a4cpn1v2CfvkQ");
```
