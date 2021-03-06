use serde::Deserialize;

use crate::api::{Api, Error};

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

pub struct Transaction<'a> {
    api: Api<'a>,
}

/// A new Transaction instance.
///
/// Has various methods for interacting Arweave transactions.
impl<'a> Transaction<'a> {
    /// Creates a new transaction instance with the client API instance.
    pub fn new(api: Api<'a>) -> Self {
        Self { api: api }
    }

    /// Get price of a transaction payload based on its size along with its target address.
    ///
    /// Sends a GET request to the respective endpoint via the API client.
    /// Returns back amount as string to avoid loss in precision while casting.
    pub async fn get_price(
        &self,
        byte_size: &'a str,
        target_address: Option<&'a str>,
    ) -> Result<String, Error> {
        let endpoint = match target_address {
            Some(addr) => format!("price/{}/{}", byte_size, addr),
            None => format!("price/{}", byte_size),
        };

        // XXX: Investigate whether it will convert Winston to Integer.
        //      It really shouldn't because serde doesn't type cast like JSON.parse
        //      But just in case, yk.
        self.api.get::<String>(&endpoint).await
    }

    /// Get transaction data from a transaction ID.
    ///
    /// Transaction is of the form `arweave_rs::tx::TransactionData`
    pub async fn get(&self, id: &'a str) -> Result<TransactionData, Error> {
        let response = self
            .api
            .get::<TransactionData>(&format!("tx/{}", id))
            .await?;
        // TODO(@littledivy): use self.get_data() for check for tx format >= 2
        // https://github.com/ArweaveTeam/arweave-js/blob/d91ff7f89bf6b29d4e823d69ac1245e1517d5a56/src/common/transactions.ts#L74
        Ok(response)
    }

    /// Get status of the transaction from it's transaction ID.
    ///
    /// Sends a GET request to `tx/<id>/status`.
    /// Returns transaction status in the form of `arweave_rs::tx::TransactionStatusResponse`.
    pub async fn get_status(&self, id: &'a str) -> Result<TransactionStatusResponse, Error> {
        self.api
            .get::<TransactionStatusResponse>(&format!("tx/{}/status", id))
            .await
    }
}
