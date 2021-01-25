use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use sha2::{Digest, Sha256, Sha384};

use rsa::{RSAPrivateKey,RSAPublicKey, PaddingScheme};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const RSA_KEY_LENGTH: u32 = 4096;
const PUBLIC_EXPONENT: u32 = 0x10001;

fn hash<H: Digest>(data: Vec<u8>) -> Vec<u8> {
    let mut hasher = H::new();
    hasher.update(data);
    hasher.finalize().as_slice().to_vec()
}

pub fn sign(key: &str, data: Vec<u8>, salt_len: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let private_key = crate::jwk::read_private_jwk(key)?;

    let pad = PaddingScheme::new_pss_with_salt::<Sha256, rand::rngs::ThreadRng>(rand::thread_rng(), salt_len);

    let signature = private_key.sign(pad, &data)?;

    Ok(signature.as_slice().to_vec())
}

pub fn verify(key: &str, data: Vec<u8>, signature: Vec<u8>) {
    let public_key = crate::jwk::read_public_jwk(key)?;


}