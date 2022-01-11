use rand::rngs::OsRng;
use rsa::padding::PaddingScheme;
use rsa::PublicKey;
use rsa::RsaPrivateKey;
use sha2::Digest;
use sha2::Sha256;

/// Generic wrapper around an underlying RSA private key.
pub struct PrivateKey(pub(crate) RsaPrivateKey);

impl PrivateKey {
  pub fn to_jwk() {
    // Perform Private key (PKCS#1) to JWK conversion.
    unimplemented!()
  }

  pub fn sign(&self, data: &[u8]) -> Vec<u8> {
    // Perform RSA-PSS signing operation
    // > saltLength = 32
    let rng = OsRng;
    let padding =
      PaddingScheme::new_pss_with_salt::<Sha256, rand::rngs::OsRng>(rng, 32);
    let digest = {
      let mut hasher = Sha256::new();
      hasher.update(data);
      hasher.finalize()
    };
    // TODO(@littledivy): Handle operation failures
    let signature = self.0.sign(padding, &digest).expect("Signing failed");
    signature
  }

  pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
    // Perform RSA-PSS verification operation
    // > saltLength = 32
    let rng = OsRng;
    let padding =
      PaddingScheme::new_pss_with_salt::<Sha256, rand::rngs::OsRng>(rng, 32);
    let hashed = {
      let mut hasher = Sha256::new();
      hasher.update(data);
      hasher.finalize()
    };
    self
      .0
      .to_public_key()
      .verify(padding, &hashed, &signature)
      .is_ok()
  }
}
