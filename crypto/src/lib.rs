use pkey::PrivateKey;
use rand::rngs::OsRng;
use rsa::padding::PaddingScheme;
use rsa::BigUint;
use rsa::PublicKey;
use rsa::RsaPrivateKey;
use sha2::Digest;
use sha2::Sha256;

pub mod pkey;

/// A generic interface for interacting with
/// a cryptographic "backend".
pub struct Driver;

impl Driver {
  /// Generate a new JWK key.
  pub fn generate_key() -> PrivateKey {
    // Generate an RSA private key
    // > modulusLength = 4096
    // > publicExponent = 65537
    // > RSA-PSS (SHA-256)

    let exponent = BigUint::from_bytes_be(&[0x01, 0x00, 0x01]);
    // TODO(@littledivy): Let users pass RNG.
    let mut rng = OsRng;
    let p_key = RsaPrivateKey::new_with_exp(&mut rng, 4096, &exponent)
      .expect("Key generation failed");
    PrivateKey(p_key)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_generate_key() {
    // It should just work
    Driver::generate_key();
  }

  #[test]
  fn test_sign_verify() {
    let key = Driver::generate_key();

    let signature = key.sign(&[0; 16]);
    assert!(signature.len() > 0);

    let verified = key.verify(&[0; 16], &signature);
    assert!(verified);
  }
}
