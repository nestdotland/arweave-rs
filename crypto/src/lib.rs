use rand::rngs::OsRng;
use rsa::padding::PaddingScheme;
use rsa::BigUint;
use rsa::PublicKey;
use rsa::RsaPrivateKey;
use sha2::Sha256;

pub struct Driver;

/// Wrapper type for private key.
pub struct Key(RsaPrivateKey);

impl Key {
    pub fn to_jwk() {
        // Perform Private key (PKCS#1) to JWK conversion.
        unimplemented!()
    }
}

impl Driver {
    /// Generate a new JWK key.
    pub fn generate_key() -> Key {
        // Generate an RSA private key
        // > modulusLength = 4096
        // > publicExponent = 65537
        // > RSA-PSS (SHA-256)

        let exponent = BigUint::from_bytes_be(&[0x01, 0x00, 0x01]);
        // TODO(@littledivy): Let users pass a RNG.
        let mut rng = OsRng;
        let p_key =
            RsaPrivateKey::new_with_exp(&mut rng, 4096, &exponent).expect("Key generation failed");
        Key(p_key)
    }

    pub fn sign(key: &Key, data: &[u8]) -> Vec<u8> {
        // Perform RSA-PSS signing operation
        // > saltLength = 32
        let rng = OsRng;
        let padding = PaddingScheme::new_pss_with_salt::<Sha256, rand::rngs::OsRng>(rng, 32);
        // TODO(@littledivy): Handle operation failures
        let signature = key.0.sign(padding, &data).expect("Signing failed");
        signature
    }

    pub fn verify(key: &Key, data: &[u8], signature: &[u8]) -> bool {
        // Perform RSA-PSS verification operation
        // > saltLength = 32
        let rng = OsRng;
        let padding = PaddingScheme::new_pss_with_salt::<Sha256, rand::rngs::OsRng>(rng, 32);
        key.0
            .to_public_key()
            .verify(padding, &data, &signature)
            .is_ok()
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

        let signature = Driver::sign(&key, &[0; 16]);
        assert!(signature.len() > 0);

        let verified = Driver::verify(&key, &[0; 16], &signature);
        assert!(verified);
    }
}
