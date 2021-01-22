use serde::Deserialize;

use crate::api::{Api, Error};

pub struct Tag {
    pub name: String,
    pub value: String,
}

pub struct Transaction<'a> {
    api: Api<'a>,

    pub format: usize,
    pub id: &'a str,
    pub last_tx: &'a str,
    pub owner: &'a str,
    pub tags: Vec<Tag>,
    pub target: &'a str,
    pub quantity: &'a str,
    pub data: Vec<u8>,
    pub reward: &'a str,
    pub signature: &'a str,
    pub data_size: &'a str,
    pub data_root: &'a str,
}

/// A new Transaction instance.
///
/// Has various methods for interacting Arweave transactions.
impl<'a> Transaction<'a> {
    pub fn add_tag(&mut self, name: String, value: String) {
        self.tags.push(Tag { name, value })
    }

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
}
