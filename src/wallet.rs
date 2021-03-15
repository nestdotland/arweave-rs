use crate::api::{Api, Error};
use crate::jwk::JwkPrivate;
use serde::{Deserialize, Serialize};

pub struct Wallet<'a> {
    api: Api<'a>,
}

/// A new wallet instance.
///
/// Implements wallet generation and other convinience methods for interacting with Arweave JWK wallets.
impl<'a> Wallet<'a> {
    /// Create a new wallet instance with the client API
    pub fn new(api: Api<'a>) -> Self {
        Self { api: api }
    }

    /// Get balance of a particular wallet address.
    ///
    /// Basically sends a GET request to wallet/<address>/balance and returns the resposne as string.
    pub async fn balance(&self, address: &'a str) -> Result<String, Error> {
        self.api
            .get::<String>(&format!("wallet/{}/balance", address))
            .await
    }

    /// Get last transaction ID of the wallet address.
    ///
    /// Sends a GET requedst nto wallet/<address>/last_tx and returns the response as string.
    pub async fn last_tx_id(&self, address: &'a str) -> Result<String, Error> {
        self.api
            .get::<String>(&format!("wallet/{}/last_tx", address))
            .await
    }

    pub async fn generate() -> Result<JwkPrivate, rsa::errors::Error> {
        crate::crypto::generate_jwk().await
    }
}
