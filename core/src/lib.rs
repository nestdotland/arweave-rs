use arweave_crypto::pkey::PrivateKey;
use arweave_crypto::Driver;
use async_trait::async_trait;
use pretend::pretend;
use pretend::resolver::UrlResolver;
use pretend::JsonResult;
use pretend::Pretend;
use pretend::Result;
pub use pretend::Url;
use pretend_reqwest::Client as HttpClient;
use serde::Deserialize;

pub mod tx;

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

#[derive(Deserialize, Debug)]
pub struct Tag {
  pub name: String,
  pub value: String,
}

#[derive(Deserialize, Debug)]
pub struct TransactionData {
  pub format: usize,
  pub id: String,
  pub last_tx: String,
  pub owner: String,
  pub tags: Vec<Tag>,
  pub target: String,
  pub quantity: String,
  pub data: Vec<u8>,
  pub reward: String,
  pub signature: String,
  pub data_size: String,
  pub data_root: String,
}

#[derive(Deserialize, Debug)]
pub struct TransactionConfirmedData {
  block_indep_hash: String,
  block_height: usize,
  number_of_confirmations: usize,
}

#[derive(Deserialize, Debug)]
pub struct TransactionStatusResponse {
  status: usize,
  confirmed: Option<TransactionConfirmedData>,
}

#[pretend]
trait ArweaveHttp {
  // Network
  #[request(method = "GET", path = "/info")]
  async fn network_info(&self) -> Result<JsonResult<NetworkInfo, ()>>;

  #[request(method = "GET", path = "/peers")]
  async fn peer_info(&self) -> Result<JsonResult<Vec<String>, ()>>;

  // Transaction
  #[request(method = "GET", path = "/price/{byte_size}")]
  async fn tx_get_price(&self, byte_size: &str) -> Result<String>;

  #[request(method = "GET", path = "/tx/{id}")]
  async fn tx_get(&self, id: &str) -> Result<JsonResult<TransactionData, ()>>;

  #[request(method = "GET", path = "/tx/{id}/status")]
  async fn tx_status(
    &self,
    id: &str,
  ) -> Result<JsonResult<TransactionStatusResponse, ()>>;

  // Wallet
  #[request(method = "GET", path = "/wallet/{address}/balance")]
  async fn wallet_balance(&self, address: &str) -> Result<String>;

  #[request(method = "GET", path = "/wallet/{address}/last_tx")]
  async fn wallet_last_tx_id(&self, address: &str) -> Result<String>;
}

pub struct Client(Pretend<HttpClient, UrlResolver>);

impl Client {
  pub fn new(url: Url) -> Self {
    let client = HttpClient::default();
    let pretend = Pretend::for_client(client).with_url(url);
    Self(pretend)
  }

  pub async fn network_info(&self) -> Result<NetworkInfo> {
    let response = self.0.network_info().await?;
    match response {
      JsonResult::Ok(n) => Ok(n),
      JsonResult::Err(_) => todo!(),
    }
  }

  pub async fn peer_info(&self) -> Result<Vec<String>> {
    let response = self.0.peer_info().await?;
    match response {
      JsonResult::Ok(n) => Ok(n),
      JsonResult::Err(_) => todo!(),
    }
  }
}

#[async_trait]
pub trait TxClient {
  async fn get_price(&self, byte_size: &str) -> Result<String>;
  async fn get(&self, id: &str) -> Result<TransactionData>;
  async fn get_status(&self, id: &str) -> Result<TransactionStatusResponse>;
}

#[async_trait]
impl TxClient for Client {
  async fn get_price(&self, byte_size: &str) -> Result<String> {
    let response = self.0.tx_get_price(byte_size).await?;
    Ok(response)
  }

  async fn get(&self, id: &str) -> Result<TransactionData> {
    let response = self.0.tx_get(id).await?;
    match response {
      JsonResult::Ok(n) => Ok(n),
      JsonResult::Err(_) => todo!(),
    }
  }

  async fn get_status(&self, id: &str) -> Result<TransactionStatusResponse> {
    let response = self.0.tx_status(id).await?;
    match response {
      JsonResult::Ok(n) => Ok(n),
      JsonResult::Err(_) => todo!(),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::Client;
  use super::Url;
  use tokio_test::block_on;

  #[test]
  fn test_network_info() {
    let url = Url::parse("https://arweave.net/").unwrap();
    let client = Client::new(url);
    let network_info = block_on(client.network_info()).unwrap();

    assert_eq!(network_info.network, "arweave.N.1".to_string());
  }

  #[test]
  fn test_peer_info() {
    let url = Url::parse("https://arweave.net/").unwrap();
    let client = Client::new(url);
    let peer_info = block_on(client.peer_info()).unwrap();

    assert!(peer_info.len() > 0);
  }
}
