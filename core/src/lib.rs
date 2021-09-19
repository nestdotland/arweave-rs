use pretend::pretend;
use pretend::JsonResult;
use pretend::Result;
use serde::Deserialize;

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
    #[request(method = "GET", path = "/network")]
    async fn network_info(&self) -> Result<JsonResult<NetworkInfo, ()>>;

    #[request(method = "GET", path = "/peers")]
    async fn peer_info(&self) -> Result<JsonResult<Vec<String>, ()>>;

    // Transaction
    #[request(method = "GET", path = "/price/{byte_size}")]
    async fn tx_get_price(&self, byte_size: &str) -> Result<String>;

    #[request(method = "GET", path = "/tx/{id}")]
    async fn tx_get(&self, id: &str) -> Result<JsonResult<TransactionData, ()>>;

    #[request(method = "GET", path = "/tx/{id}/status")]
    async fn tx_status(&self, id: &str) -> Result<JsonResult<TransactionStatusResponse, ()>>;

    // Wallet
    #[request(method = "GET", path = "/wallet/{address}/balance")]
    async fn wallet_balance(&self, address: &str) -> Result<String>;

    #[request(method = "GET", path = "/wallet/{address}/last_tx")]
    async fn wallet_last_tx_id(&self, address: &str) -> Result<String>;
}
