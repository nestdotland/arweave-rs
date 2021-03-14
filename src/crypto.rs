use crate::jwk;
use crate::jwk::{JwkPrivate, JwkPublic};
use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use hmac::Hmac;
use rand::RngCore;
use rsa::{PaddingScheme, PublicKey};
use sha2::{Digest, Sha256};

pub type CryptoResult = Result<Vec<u8>, Box<dyn std::error::Error>>;

pub trait CryptoInterface {
    // TODO: async fn generateKey()
    fn hash<H: Digest>(data: &[u8]) -> Vec<u8>;
    fn sign(key: JwkPrivate, data: &[u8], salt_len: Option<usize>) -> CryptoResult;
    fn verify(
        key: JwkPublic,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>>;
    fn derive_password(password: &str) -> CryptoResult;
    fn encrypt(password: &str, data: &[u8]) -> CryptoResult;
    fn decrypt(password: &str, ciphertext: &[u8]) -> CryptoResult;
}

pub struct Crypto;

impl CryptoInterface for Crypto {
    fn hash<H: Digest>(data: &[u8]) -> Vec<u8> {
        let mut hasher = H::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    fn sign(
        key: JwkPrivate,
        data: &[u8],
        salt_len: Option<usize>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let salt_len = if let Some(salt) = salt_len { salt } else { 32 };

        let private_key = jwk::read_private_jwk(key)?;
        let rng = rand::thread_rng();
        let pad = PaddingScheme::new_pss_with_salt::<Sha256, rand::rngs::ThreadRng>(rng, salt_len);

        let signature = private_key.sign_blinded(&mut rng.clone(), pad, &data)?;

        Ok(signature.to_vec())
    }

    fn verify(
        key: JwkPublic,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let public_key = crate::jwk::read_public_jwk(key)?;

        let pad = PaddingScheme::new_pss::<Sha256, rand::rngs::ThreadRng>(rand::thread_rng());

        public_key.verify(pad, &Crypto::hash::<Sha256>(&data), &signature)?;

        Ok(())
    }

    fn derive_password(password: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut out = [0u8; 32];
        pbkdf2::pbkdf2::<Hmac<Sha256>>(password.as_bytes(), b"salt", 100000, &mut out);
        Ok(Vec::from(out))
    }

    fn encrypt(password: &str, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let key = Crypto::derive_password(password)?;
        let mut iv = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut iv);
        let cipher = Cbc::<Aes256, Pkcs7>::new_var(&key, &iv)?;
        let output_data = cipher.encrypt_vec(data);
        let mut output_vecs = Vec::<&[u8]>::new();
        output_vecs.push(&iv);
        output_vecs.push(&output_data);
        Ok(output_vecs.concat())
    }

    fn decrypt(password: &str, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let key = Crypto::derive_password(password)?;
        let iv = &ciphertext[0..16];

        let decipher = Cbc::<Aes256, Pkcs7>::new_var(&key, &iv)?;

        let output_data = decipher.decrypt_vec(&ciphertext[16..])?;

        Ok(output_data)
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{Crypto, CryptoInterface, Sha256};
    use crate::jwk::JwkPrivate;
    #[test]
    fn test_hash() {
        assert_eq!(
            Crypto::hash::<Sha256>(b"hello"),
            &[
                44, 242, 77, 186, 95, 176, 163, 14, 38, 232, 59, 42, 197, 185, 226, 158, 27, 22,
                30, 92, 31, 167, 66, 94, 115, 4, 51, 98, 147, 139, 152, 36,
            ]
        );
    }

    #[test]
    #[should_panic]
    fn test_encrypt_fail_ivlen() {
        Crypto::encrypt("test_password", &[1, 5, 6, 23, 7, 10, 34]).unwrap();
    }

    #[test]
    fn test_sign_verify() {
        // https://github.com/ArweaveTeam/arweave-js/blob/master/test/fixtures/arweave-keyfile-fOVzBRTBnyt4VrUUYadBH8yras_-jhgpmNgg-5b3vEw.json
        let wallet: JwkPrivate = JwkPrivate {
            d: b"F2UEjuzxUuqCaE0UEurZTxdyRI65Hgmz0maPAU9b1hgGlxKXZ4JW8q4PJHKWXqffdNptrlY9Y85t0yUOuPkmH7ChMbxpPKxffjq9qnMvbUn8Ye46hnQsqS093lWY-qdhy37TmXEC9eGxfpRpPKvbw-F7L2mVoV3gyzS99yJNtNuXhxgBMsN8ApSdpmB0QzUonix4jFiLZ6rYQzYh4tqnxkZnIg2HgrEo2kJ-l7TkRZFvbH2X2aPwmplJ7aKa0aBfad_MizxLsc6yU7z16lcr6qzUZhiW5SZoVegDan5gRIgyICVyklwtl9N8pT41ESk_iMweWofBiuCIIB7Gu_9wN4Ee_oe15ZmwACKqdsMUH6Xs2FPNRnqEs6Wc-5H1-6yuHxOE3X6XznsqCOvzkJH-DGFB8si1JGaHbxluY8ExJf_IcuOhGEzRsCOEP8jQJpNByUufbSMYIKau3hlRVdA3duKeGzCT-LEKang7DbIBnoenMt32xtHp1t6dNWPlRbynS8l8irpoEi3b-Xd7ERVuQMckArIhmefK5T99xJJGpwIX-lOcuCtnYuSCk-Qtc2R8-Jcg5fM_tdkgNA9724MBa5WYxXqnj8sFlwrCoCXu7ofag3SsLWiuoGCAgYtGA-sSAzwXo_Lu47VMiZqdjAgjNhhEshb8-Ss1BXk8OwPbMfk".to_vec(),
            dp: b"GqbwEzo9_1MFEQkw9pm3yW5LqJCP6bERxxzad_M1i9oyDtvOUZn-lBYSW4qOioXjsAYorpqQPgSj8t1eEyU1JY8O49ED092D8JCniFqzvDB7PRpID5TxRhPvoFD6Pom3PgVvJwUgL5VF3W56bV4WEmdhSWxPQsBbpz5lix6LteFJOxqAcry_6Fw0nQ2GFeBag58L1VqZwIwcyq9n0ftT50UwxbhFedrf-cfFTuyMONTPFCqQZTdRDcTrZU51sEjLj8k4-RZQSmeFq5bbIr-TEhGka6PwfyWRbnCmPqagOj2FAeUxRhHKTjbkBDVhfm5iT7TyBisEcfbC4CfOuvECGQ".to_vec(),
            dq: b"WoqQuHnl2y3UxGBPyvydCZcAyyzTdC7_ThZyXzouBYuEFSZ5pICVZDLG14Jm8uJ1A1vL52iFeiv_greYGwsp5keijQdPrJjHGW2mC6pMGoIBI_jhoUIzgUwkYdEp1lIH-TW8YcZ5GMFH7ZlVbCMtk8l_fDuoz2KpCMZChBR2vOP9ZKL7DqFJ9IUEi6raGOSIeny-VRlQOPmnEgRoZB9GJBfmliGbNocvqEWYkoM6bq27pi9QIiILWsIcLa3NSzCRm2h-f3_SDr7cN7AUZOwvcD2NCuc2NCJM4a3FstU9eUbaweQjNBvWuUG2saDgeHPvdOKuMSqkCnnc7sVeZnUriQ".to_vec(),
            e: b"AQAB".to_vec(),
            kty: "RSA".to_string(),
            n: b"lTBMnymUu-q1w3S2cNDAWn3t0NhcL5k3xqqrIN2HOQP6TE3H57s1wZnD1IAbiBbew2QgZu0WJWkJR-Mmotu7xHvf4A45EiZQ0rHOD2pjNBJ5m8cEbRLI9SlmywDOD81LX-TgGNNYrUpKfNi2XjykTMD6t2gTNFLayVxe2qqnhhKxLUy0hFbBgKA6EKR4wVZCSzSaXNeD2pdmtI62N10N8qcU3GuM691QXr3JGndq__fBLNaiC5pS0HGzzGZXcJkSqeqWe2zOG5wqAlLkTr4ele1LYDO84tAilTg0eRtx4t3qIzZL-H7wrjKUO45eSyLqjbqt405xgXWGgVrq-GghD2KbaTgQfHLEtUICATBEARkvYGvpe0jZxqQW25qF55mcGimht_V2mD6BahJ4u4No4uZ5c9qWo2yhLvcupT1e2sQNpls8HQXVHySGlUUhJKj2pdeefdMiwh6zES0wePqkGjWqs20b5db5U_9jI7q5PxoACpLPkXIzpq0iKptK9qs4LsA-3t1d76RdL3ZNjVcIf_pxivQnqz4mWJOt6MzN0WXM7oe2HQLq1QVVCxbXko-hIvWVBDFWWj3tBNuImaYKiVex85OisfqqsQI5MKPvsG8mmytN3-JM6G2PmKaf49nQyc2xMwfcf1oKBXFluL3crmkiMYoHXkZXoSkGou1bM9M".to_vec(),
            p: b"xJFHGzSGpHkgNeGFCR-WEn9757D1-022XlcMwcMynqyuRPc334MWeT-ftTy7hb7W25SeeTVDmoBQ4edAQnipeo-ZSn-Ovze2MVa4EDKXgVw7KZY-26vmvBo1Pzmih0mhYenogTBvOXzmyIXm37DQ0wqmio-4hpYbwsCzH2efU_qsaA09SM6U6zPxSS4DNZkarT8xKQl7OM7jyjCWT0JCGxzAwsgHb7uaCKKwZBRfV1JzJnqg-vqXdAsYqtXaDPpoE39quAN_L2oxhskNeKyQGBrsCxK644nIdK4kvZc3gwSHu5zBsWGPLsNkScrPMQevR15BqOkV3aLpjhuCeGpk5Q".to_vec(),
            q: b"wkvN_8DzM11ydKjBw0fr7yKFqwP6gnOSqx4DVV8Z2WL1x2xTHJ6cn83ulWtQ4njXLQmMwF0vzXMOCch_kcgL8t6CvP1S0V0kqqOwJJ4OufC9sdNRdjmCj5JWjoxRvccNVqfDTpWRJN6Ca-jSnOyq7R1u3TBb1IHl4CQJ4JuI6dwTQFjIyjiaa3zoTNhh8DrBdW580DeR6EbQuGBALjOFTyW-VQh-iuaJIeAnXWmPSe9BLmWDndfPbAuXp0v4S-S_OGGWcrmRI3LdSNRHIAabv92kiNZU7Oz_Qx2I1xWyQ_e36szGkMYM_Db9CzqYGjCvO80x0vFkIRwgZSUpLFKiVw".to_vec(),
            qi: b"G-mOGewvS8rYyBoHUFPKwbAxXRL3PlnjIFhwvv15PnMaH5xqHJc0m_lO8nTJoPH1qznQHF0JOfZL0k5CMxoVVX0mtM4JjYz-7jUmlRHwSQ9ved41_rrew9yeLtnLRusfeGQWAVQxWAXxWqeSK9tPnbHCMGqsLnNXSZjVXHV99epKaAyKMI3V3qOtITjDVSM2_ajN30SKdPEEzHtEdNV3sSH4IDZEPXt8QQ8HU00W9fWAK7qjq4bs03jsfhe9h7SHifDBgYngfXxcecWqTvTbUbmUgzAjzORCGgAPg5CFdGD0urN8qd3ro3cZfjoAtF5NuRjL3W_sMjY26BqRhmHLeA".to_vec(),
        };
        Crypto::sign(wallet, &Crypto::hash::<Sha256>(b"hello"), None).unwrap();
    }
}
