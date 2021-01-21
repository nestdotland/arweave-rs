use reqwest::Client;
use serde::Deserialize;
use std::fmt;

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

    pub async fn network_info(&self) -> Result<NetworkInfo, reqwest::Error> {
        self.client
            .get(&self.build_url("info"))
            .send()
            .await?
            .json::<NetworkInfo>()
            .await
    }

    pub async fn peer_info(&self) -> Result<Vec<String>, reqwest::Error> {
        self.client
            .get(&self.build_url("peers"))
            .send()
            .await?
            .json::<Vec<String>>()
            .await
    }
}

#[cfg(test)]
mod tests {
    use crate::api::{Api, Protocol};
    use tokio_test;

    macro_rules! wait {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

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
