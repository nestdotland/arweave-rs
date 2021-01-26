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
    fn hash<H: Digest>(data: &[u8]) -> Vec<u8>;
    fn sign(key: JwkPrivate, data: &[u8], salt_len: usize) -> CryptoResult;
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
        hasher.finalize().as_slice().to_vec()
    }

    fn sign(
        key: JwkPrivate,
        data: &[u8],
        salt_len: usize,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let private_key = jwk::read_private_jwk(key)?;

        let pad = PaddingScheme::new_pss_with_salt::<Sha256, rand::rngs::ThreadRng>(
            rand::thread_rng(),
            salt_len,
        );

        let signature = private_key.sign(pad, &data)?;

        Ok(signature.as_slice().to_vec())
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
            kty: "RSA".to_string(),
            e: b"AQAB".to_vec(),
            n: b"kmM4O08BJB85RbxfQ2nkka9VNO6Czm2Tc_IGQNYCTSXRzOc6W9bHRrlZ_eDhWO0OdfaRalgLeuYCXx9DV-n1djeerKHdFo2ZAjRv5WjL_b4IxbQnPFnHOSNHVg49yp7CUWUgDQOKtylt3x0YENIW37RQPZJ-Fvyk7Z0jvibj2iZ0K3K8yNenJ4mWswyQdyPaJcbP6AMWvUWT62giWHa3lDgBZNhXqakkYdoaM157kRUfrZDRSWXbilr-4f40PQF1DV5YSj81Fl72N7j30r0vL1yoj0bZn74WRquQ5j3QsiAA-SzhAxpecWniljj1wvZlyIgJpCYCvCrKZCcCq_JW1nYP6to5YM3fAqcYRadbTNdQ3oH0Sjy8vyvLYNe48Ur_TFTTAwZxJV70BgZfkJ00BxiNTb8EhSchejabeExUkCNlOrQsCHDxOig-WXOrjX5fb4NeR3jedeYWbhN922ORLuEwVLeyjc7hBfQXU2-mYraFAVTc0QST201P7rRu-UGtZ4gRavFuOvAyYrMimFVW9dTwTrcYXFK2zKCEv2aRRQAHZanKjBv0Xq9m3BqvxKy-_3Cj1O6ft7FT21drPoDRDzfnkyOeUjlXzRJzn-iQ0nqgHAQr9WBWPzLEcaTFpw3KmwDYHW_6JOkUWDyMW9anuS8cyqt_2O29SK_rHHuucD8".to_vec(),
            d: b"Bq6C13vknF6Ln1MrKI3Ilq-83IuSvQpe7NRAuT69u7i8sv4XwsHOJAV7qpGvp37NXT5R1G3ehEZ6qoSxJbcN4IVrQMKq5mMiCY6DBv5C6fHZGoNZE2gxXV7uydf8I1Vnnw4xYIj5oyC_5nSJlFAc3U-MAcbkfJuvrhGxLVGsrqHmjoqQPGG_hTxCjuAOlOBs-9cmWTujbm1-OyjaAQwfTbXYbUy7hC1TCE05SxLPmTUwaJxY8AXJigpbYqjpWsc15HjRlv38A44tEnIwHjHda_3JpmbSsffSslRej2vPCCgSPHHyLeO437Nc7DraogKStugisRfhoe89yY4QSBVXbtvWJeF1LxPtg8uPtfoKt3wdnGWKaLDqYNDeA3AckbKrPp50kHEMR7hnNHq3lAoMAXTz8BbI_Czo5n9-f9DQpvJC8kpM7gCGG8DptA2nTPuQG02MOx7AsEE99EN8ltD_dA0l0MgG7CDsaQC5IPMHcRs1wyvZMBGA8fvZdURiVv9YSnCddndXjBJuetf5KdES-1EmrSLzo5hobQbkc7dkHMS5dmLm5YtK-aLYXZi31nRIGkA1UfZhf2TtfRxP6uKlRT106EtDX1rT3RgsLqg06y_xoS4SFQ6u-8wHqgbIHBmKdsWVtBkC4SGUlYDPgrJe2V9CaPFAcoSDFK1D_IPvU2U".to_vec(),
            p: b"zhyauK0ISMg9Wk7iZK2ifW2cj5KSr-_k_Em0nfUrtsaKp0iXOsCKxOH__zcAVj7oLxaEP2l8i2Pdi7CzhVRiqrjgVwA1JuLPgxtryuVqwRCYbO_Y_2Xutk404iKmDX6_LQ7BeIzUI8GD6rQCeLq1HBd3Yvok9bPvbbMZjFtUmBf_Kfb0cYP8tewMmV_USGpqwJXdB_4aHF6qBrZBtd1KLoO1E7MNkAPk7pbiA1-KO2Xa6oY6fy2pztNe1MO7tz_QywqlDdymfhnpk41arY3A6US-ZFXOinqXKdh9uEfxiyZwzaLMNWVKEaWxRxbqSUOLV3uZS05N6B2ZqvOp2h9Csw".to_vec(),
            q: b"tdHmYcbJpZ0U27d_j0YvUeb6sdcuFLg2vmDgKwUamC5_vvV41LSm8LIkLuY2DAN5MKg6-HTWetKWQhgbCIbubLtX5164MFrES1YVZI-aggrYohhH8MRn_hwMZZQndv9H07WUVgQ1GZ2ZDvhO7XxPDIXyBNQ46x6V1AikHtyTmqARjgrkgs-1XN55S9rhcffixOlJ-egIDPVei_Z6YNdSpLlhtiqHOp_lX37mrPSYGxjgIZVxevpPgBhVFlnAMqC2iRd87XupmWgiluSos8I7i1VESBzwlFZGk5hRb8och4zwmDBDwx65XWngg6LneSXTWcKjKKGM2NnX7wHrZBuyRQ".to_vec(),
            dp: b"Gfo49fW5CZNTSEKQ_id0R2K9TMsoecw-jB2uCgqQi-TSLOtVRC5oTxA896my_SvIj8bCvEtLSzY3AhgvSCqulN3gSJbaHCCSDvAx0czAe7zfuTsxml76izeoKqg7TZAgAEnP0KXPRwJo4ff2J8lAcl3yyiLE7cLT9nuQSMRqERFVM7DQdk4wV618mQge9VGUStmYlh1MpS65N0dZWNafNuWauPTkTLZw8DFMIyizf3EC-nQYg1b6A_tYBHD3A82jPzQEQY8B3PrfGZ3DRASNv9jONk8qTQHOc5O5pLRMmUErDn_qRQCTKU483bzhooJE2a3WUEt6Pjsc1xMG4Vr3SQ".to_vec(),
            dq: b"cCVai36Yi-06m1cwd8fbkhH9GUpXIvKI2Z5ZRk-smqc7piY0dEZFHftS9BaMyZYu3wM09GDklfdkNLo3mmfXkftv-cbjpvelUa50HYWx0HouKrT9UpVia0sTnmfme7BztjKunuuTcQxTBvfDfxoIi_nmUHIx9Vv1IEaALITzChGnIky3q7O_8ttKR65nFevG1JvsRBeJN6z0tzG9RBQr5mxtx3Wt2Uwcp21XjOCFHVmXjT9nMmpINQNNIC8VrGSSkjaJmNWIw5WGmDnLkKzCG2vpZO1suqIIgCsYN_Ka7ETTdZt3gFdoECUpFSiay4-4MAospvgWLv8XAFXXwfSPXQ".to_vec(),
            qi: b"n-R81MpbwfWfqRSVgD8nDk7D8zlJ-tpMaojfTwNNqDt34Cr-BpMjxaQyEfMnzOd2dY4OV0rKhd29DIuwFEb2UERHdVWF3gM8f2byYGj4357CRkiwq6I050bUxd1ODgAXjVGNpOK_fmaNHDWfe5v3wVIcCmwH0mJxEu9kuz7fr9TJNxGJBGUphpGS6NQZDCbDXg9-FPafMeNV-Jdo0NQaKMwm8uZyW7YGSNpUXYnksrWt4Fa-B9H2KoC4PPSWESPxNooXdxK7Y0J1KbzNyrUmOl4dT6p_oFKcU-1unuDCZ11e6EmMKyUGjpDzTIAZ2XxmyWUJ06yzEw7oLo8noiCE_Q".to_vec(),
        };
        Crypto::sign(wallet, &Crypto::hash::<Sha256>(b"hello"), 640).unwrap();
    }
}
