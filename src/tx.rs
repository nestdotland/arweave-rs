use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Tag {
    pub name: String,
    pub value: String,
}

#[derive(Deserialize, Debug)]
pub struct Transaction<'a> {
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

impl<'a> Transaction<'a> {
    pub fn add_tag(&mut self, name: String, value: String) {
        self.tags.push(Tag { name, value })
    }
}
