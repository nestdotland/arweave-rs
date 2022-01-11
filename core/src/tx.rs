use crate::TransactionData;

pub struct Transaction {
  inner: TransactionData,
}

impl Transaction {
  pub fn new(tx_data: TransactionData) -> Self {
    Self { inner: tx_data }
  }

  // pub fn add_tag(&mut self, tag: Tag) {
  //   self.0.tags.push(tag);
  // }

  pub fn set_owner(&mut self, owner: String) {
    self.inner.owner = owner;
  }
}
