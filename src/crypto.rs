use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use sha2::{Digest, Sha256, Sha384};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const RSA_KEY_LENGTH: u32 = 4096;
const PUBLIC_EXPONENT: u32 = 0x10001;

fn hash_SHA256(data: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().as_slice().to_vec()
}
