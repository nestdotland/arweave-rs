use aes::Aes256;
use block_modes::{BlockMode, Cbc, block_padding::{Pkcs7}};
use sha2::{Digest, Sha256, Sha384};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const RSA_KEY_LENGTH: u32 = 4096;
const PUBLIC_EXPONENT: u32 = 0x10001;

fn hash_SHA256(data: &[u8]) -> &[u8] {
    let mut hasher = Sha256::new();

    hasher.update(data);

    hasher.finalize()[..]
}
