use base64::{decode_config, encode_config, DecodeError, URL_SAFE};

type DeError = Result<Vec<u8>, DecodeError>;

pub fn encode_url(data: &[u8]) -> String {
    encode_config(data, URL_SAFE)
}

pub fn decode_url(data: &[u8]) -> DeError {
    decode_config(data, URL_SAFE)
}
