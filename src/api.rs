use reqwest;

pub enum Protocol {
    HTTP,
    HTTPS,
}

pub struct Api<'a> {
    pub host: &'a str,
    pub protocol: Protocol,
    pub port: usize,
}

impl<'a> Api<'a> {
    pub fn new(host: &'a str, protocol: Protocol, port: usize) -> Self {
        Self {
            host,
            protocol,
            port,
        }
    }

    pub fn default() -> Self {
        Self {
            host: "127.0.0.1",
            protocol: Protocol::HTTP,
            port: 80,
        }
    }
}
