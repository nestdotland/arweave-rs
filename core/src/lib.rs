use pretend::pretend;
use pretend::Result;
use pretend::JsonResult;
use pretend::Deserialize;

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

#[pretend]
trait ArweaveHttp {
    #[request(method = "GET", path = "/network")]
    async fn network_info(&self) -> Result<NetworkInfo>;
}
 