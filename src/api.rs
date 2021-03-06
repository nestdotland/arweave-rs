use reqwest::Client;
use serde::Deserialize;
use std::fmt;

use crate::get;

pub enum Protocol {
    HTTP,
    HTTPS,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Protocol::HTTP => write!(f, "http"),
            Protocol::HTTPS => write!(f, "https"),
        }
    }
}

pub type Peers = Vec<String>;

pub type Error = reqwest::Error;

#[derive(Deserialize, Debug)]
pub struct TransactionOffsetResponse {
    pub size: String,
    pub offset: String,
}

#[derive(Deserialize, Debug)]
pub struct TransactionChunkResponse {
    chunk: String,
    data_path: String,
    tx_path: String,
}

#[derive(Deserialize, Debug)]
pub struct NetworkInfo {
    pub network: String,
    pub version: usize,
    pub release: usize,
    pub height: usize,
    pub current: String,
    pub blocks: usize,
    pub peers: usize,
    pub queue_length: usize,
    pub node_state_latency: usize,
}

pub struct Api<'a> {
    pub host: &'a str,
    pub protocol: Protocol,
    pub port: usize,
    client: Client,
}

/// API client for Arweave.
///
/// Uses `reqwest` for HTTP requests and `serde` & `serde_derive` for deserializing response data.
///
/// ## usage
/// ```rust
/// use arweave_rs::api::{Protocol, Api};
///
/// let client = Api::new("arweave.net", Protocol::HTTPS, 443);
/// // Interact with Arweave HTTP API asyncronously
/// // client.network_info().await?
/// ```
impl<'a> Api<'a> {
    pub fn new(host: &'a str, protocol: Protocol, port: usize) -> Self {
        Self {
            host,
            protocol,
            port,
            client: Client::new(),
        }
    }

    pub fn default() -> Self {
        Self {
            host: "127.0.0.1",
            protocol: Protocol::HTTP,
            port: 80,
            client: Client::new(),
        }
    }

    fn build_url(&self, route: &'a str) -> String {
        format!("{}://{}:{}/{}", self.protocol, self.host, self.port, route)
    }

    pub async fn get<T: for<'de> Deserialize<'de>>(
        &self,
        url: &'a str,
    ) -> Result<T, reqwest::Error> {
        get!(self, url, T)
    }

    pub async fn network_info(&self) -> Result<NetworkInfo, reqwest::Error> {
        get!(self, "info", NetworkInfo)
    }

    pub async fn peer_info(&self) -> Result<Peers, reqwest::Error> {
        get!(self, "peers", Peers)
    }

    pub async fn transaction_offset(
        &self,
        id: &'a str,
    ) -> Result<TransactionOffsetResponse, reqwest::Error> {
        get!(
            self,
            &format!("tx/{}/offset", id),
            TransactionOffsetResponse
        )
    }

    pub async fn get_chunk(
        &self,
        offset: usize,
    ) -> Result<TransactionChunkResponse, reqwest::Error> {
        get!(self, &format!("chunk/{}", offset), TransactionChunkResponse)
    }

    pub async fn tx_anchor(&self) -> Result<String, reqwest::Error> {
        get!(self, "tx_anchor", String)
    }
}

#[cfg(test)]
mod tests {
    use crate::api::{Api, Protocol};
    use crate::wait;
    use tokio_test;

    #[test]
    fn test_network_info() {
        let client = Api::new("arweave.net", Protocol::HTTPS, 443);
        let _network_info = wait!(client.network_info()).unwrap();
    }

    #[test]
    fn test_peer_info() {
        let client = Api::new("arweave.net", Protocol::HTTPS, 443);
        let _peer_info = wait!(client.peer_info()).unwrap();
    }
}
