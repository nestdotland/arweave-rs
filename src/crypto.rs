use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use sha2::{Digest, Sha256};
use hmac::{Hmac};
use rsa::{PublicKey, PaddingScheme};
use rand::{RngCore};

pub fn hash<H: Digest>(data: &[u8]) -> Vec<u8> {
    let mut hasher = H::new();
    hasher.update(data);
    hasher.finalize().as_slice().to_vec()
}

pub fn sign(key: &str, data: &[u8], salt_len: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let private_key = crate::jwk::read_private_jwk(key)?;

    let pad = PaddingScheme::new_pss_with_salt::<Sha256, rand::rngs::ThreadRng>(rand::thread_rng(), salt_len);

    let signature = private_key.sign(pad, &data)?;

    Ok(signature.as_slice().to_vec())
}

pub fn verify(key: &str, data: Vec<u8>, signature: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    let public_key = crate::jwk::read_public_jwk(key)?;

    let pad = PaddingScheme::new_pss::<Sha256, rand::rngs::ThreadRng>(rand::thread_rng());

    public_key.verify(pad, &hash::<Sha256>(&data), &signature)?;

    Ok(())
}

pub fn derive_password(password: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut out = [0u8; 32];

    pbkdf2::pbkdf2::<Hmac<Sha256>>(password.as_bytes(), b"salt", 100000, &mut out);

    Ok(Vec::from(out))
}

pub fn encrypt(password: &str, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = derive_password(password)?;
    let mut iv = [0u8; 32];

    rand::thread_rng().fill_bytes(&mut iv);

    let cipher = Cbc::<Aes256, Pkcs7>::new_var(&key, &iv)?;

    let output_data = cipher.encrypt_vec(data);

    let mut output_vecs = Vec::<&[u8]>::new();

    output_vecs.push(&iv);
    output_vecs.push(&output_data);

    Ok(output_vecs.concat())
}

pub fn decrypt(password: &str, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = derive_password(password)?;
    let iv = &ciphertext[0..16];

    let decipher = Cbc::<Aes256, Pkcs7>::new_var(&key, &iv)?;

    let output_data = decipher.decrypt_vec(&ciphertext[16..])?;

    Ok(output_data)
}