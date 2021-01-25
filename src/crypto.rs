use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use sha2::{Digest, Sha256, Sha384};

use rsa::{RSAPrivateKey,RSAPublicKey, PaddingScheme};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const RSA_KEY_LENGTH: u32 = 4096;
const PUBLIC_EXPONENT: u32 = 0x10001;

pub fn get_rng () -> impl rand::RngCore {
    rand::thread_rng()
}

fn hash<H: Digest>(data: Vec<u8>) -> Vec<u8> {
    let mut hasher = H::new();
    hasher.update(data);
    hasher.finalize().as_slice().to_vec()
}

pub fn sign(key: &str, data: Vec<u8>, salt_len: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let private_key = crate::jwk::read_private_jwk(key)?;
    let data_hash = hash::<Sha256>(data);

    let signature = private_key.sign(PaddingScheme::new_pss_with_salt(get_rng(), salt_len), &data_hash);

    Ok(block_modes.as_slice().to_vec())
}
