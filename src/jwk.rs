use crate::b64::decode_url;
use rsa::{BigUint, PublicKeyParts, RSAPrivateKey, RSAPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::from_str;

macro_rules! push_prime {
    ($e:expr, $v: expr) => {
        match $e {
            Some(x) => $v.push(BigUint::from_bytes_be(&decode_url(&x)?)),
            None => (),
        }
    };
}

#[derive(Serialize, Deserialize)]
pub struct JwkPublic {
    pub kty: String,
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct JwkPrivate {
    pub kty: String,
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub d: Vec<u8>,
    pub p: Option<Vec<u8>>,
    pub q: Option<Vec<u8>>,
    pub dp: Option<Vec<u8>>,
    pub dq: Option<Vec<u8>>,
    pub qi: Option<Vec<u8>>,
}

impl Default for JwkPrivate {
    fn default() -> Self {
        Self {
            kty: "RSA".to_string(),
            n: vec![],
            e: vec![],
            d: vec![],
            p: None,
            q: None,
            dp: None,
            dq: None,
            qi: None,
        }
    }
}

impl JwkPrivate {
    pub fn from_rsa(private_key: RSAPrivateKey) -> Self {
        Self {
            n: private_key.n().to_bytes_be(),
            e: private_key.e().to_bytes_be(),
            d: private_key.d().to_bytes_be(),
            ..Default::default()
        }
    }
}

pub fn read_public_jwk(components: JwkPublic) -> Result<RSAPublicKey, Box<dyn std::error::Error>> {
    if components.kty != "RSA" {
        // TODO: return error
        panic!("invalid key type")
    }

    let e = BigUint::from_bytes_be(&components.e);
    let n = BigUint::from_bytes_be(&components.n);

    let public_key = RSAPublicKey::new(e, n)?;

    Ok(public_key)
}

pub fn read_private_jwk(
    components: JwkPrivate,
) -> Result<RSAPrivateKey, Box<dyn std::error::Error>> {
    if components.kty != "RSA" {
        // TODO: return error
        panic!("invalid key type")
    }

    let n = BigUint::from_bytes_be(&decode_url(&components.n)?);
    let e = BigUint::from_bytes_be(&decode_url(&components.e)?);
    let d = BigUint::from_bytes_be(&decode_url(&components.d)?);

    let mut primes = Vec::<BigUint>::new();
    push_prime!(components.p, primes);
    push_prime!(components.q, primes);
    push_prime!(components.dp, primes);
    push_prime!(components.dq, primes);
    push_prime!(components.qi, primes);

    let private_key = RSAPrivateKey::from_components(n, e, d, primes);

    Ok(private_key)
}

#[cfg(test)]
mod test {
    use crate::jwk::read_private_jwk;
    use crate::jwk::JwkPrivate;

    #[test]
    fn test_jwk_to_pk() -> Result<(), Box<dyn std::error::Error>> {
        let wallet: JwkPrivate = JwkPrivate {
            kty: "RSA".to_string(),
            e: b"AQAB".to_vec(),
            n: b"kmM4O08BJB85RbxfQ2nkka9VNO6Czm2Tc_IGQNYCTSXRzOc6W9bHRrlZ_eDhWO0OdfaRalgLeuYCXx9DV-n1djeerKHdFo2ZAjRv5WjL_b4IxbQnPFnHOSNHVg49yp7CUWUgDQOKtylt3x0YENIW37RQPZJ-Fvyk7Z0jvibj2iZ0K3K8yNenJ4mWswyQdyPaJcbP6AMWvUWT62giWHa3lDgBZNhXqakkYdoaM157kRUfrZDRSWXbilr-4f40PQF1DV5YSj81Fl72N7j30r0vL1yoj0bZn74WRquQ5j3QsiAA-SzhAxpecWniljj1wvZlyIgJpCYCvCrKZCcCq_JW1nYP6to5YM3fAqcYRadbTNdQ3oH0Sjy8vyvLYNe48Ur_TFTTAwZxJV70BgZfkJ00BxiNTb8EhSchejabeExUkCNlOrQsCHDxOig-WXOrjX5fb4NeR3jedeYWbhN922ORLuEwVLeyjc7hBfQXU2-mYraFAVTc0QST201P7rRu-UGtZ4gRavFuOvAyYrMimFVW9dTwTrcYXFK2zKCEv2aRRQAHZanKjBv0Xq9m3BqvxKy-_3Cj1O6ft7FT21drPoDRDzfnkyOeUjlXzRJzn-iQ0nqgHAQr9WBWPzLEcaTFpw3KmwDYHW_6JOkUWDyMW9anuS8cyqt_2O29SK_rHHuucD8".to_vec(),
            d: b"Bq6C13vknF6Ln1MrKI3Ilq-83IuSvQpe7NRAuT69u7i8sv4XwsHOJAV7qpGvp37NXT5R1G3ehEZ6qoSxJbcN4IVrQMKq5mMiCY6DBv5C6fHZGoNZE2gxXV7uydf8I1Vnnw4xYIj5oyC_5nSJlFAc3U-MAcbkfJuvrhGxLVGsrqHmjoqQPGG_hTxCjuAOlOBs-9cmWTujbm1-OyjaAQwfTbXYbUy7hC1TCE05SxLPmTUwaJxY8AXJigpbYqjpWsc15HjRlv38A44tEnIwHjHda_3JpmbSsffSslRej2vPCCgSPHHyLeO437Nc7DraogKStugisRfhoe89yY4QSBVXbtvWJeF1LxPtg8uPtfoKt3wdnGWKaLDqYNDeA3AckbKrPp50kHEMR7hnNHq3lAoMAXTz8BbI_Czo5n9-f9DQpvJC8kpM7gCGG8DptA2nTPuQG02MOx7AsEE99EN8ltD_dA0l0MgG7CDsaQC5IPMHcRs1wyvZMBGA8fvZdURiVv9YSnCddndXjBJuetf5KdES-1EmrSLzo5hobQbkc7dkHMS5dmLm5YtK-aLYXZi31nRIGkA1UfZhf2TtfRxP6uKlRT106EtDX1rT3RgsLqg06y_xoS4SFQ6u-8wHqgbIHBmKdsWVtBkC4SGUlYDPgrJe2V9CaPFAcoSDFK1D_IPvU2U".to_vec(),
            p: Some(b"zhyauK0ISMg9Wk7iZK2ifW2cj5KSr-_k_Em0nfUrtsaKp0iXOsCKxOH__zcAVj7oLxaEP2l8i2Pdi7CzhVRiqrjgVwA1JuLPgxtryuVqwRCYbO_Y_2Xutk404iKmDX6_LQ7BeIzUI8GD6rQCeLq1HBd3Yvok9bPvbbMZjFtUmBf_Kfb0cYP8tewMmV_USGpqwJXdB_4aHF6qBrZBtd1KLoO1E7MNkAPk7pbiA1-KO2Xa6oY6fy2pztNe1MO7tz_QywqlDdymfhnpk41arY3A6US-ZFXOinqXKdh9uEfxiyZwzaLMNWVKEaWxRxbqSUOLV3uZS05N6B2ZqvOp2h9Csw".to_vec()),
            q: Some(b"tdHmYcbJpZ0U27d_j0YvUeb6sdcuFLg2vmDgKwUamC5_vvV41LSm8LIkLuY2DAN5MKg6-HTWetKWQhgbCIbubLtX5164MFrES1YVZI-aggrYohhH8MRn_hwMZZQndv9H07WUVgQ1GZ2ZDvhO7XxPDIXyBNQ46x6V1AikHtyTmqARjgrkgs-1XN55S9rhcffixOlJ-egIDPVei_Z6YNdSpLlhtiqHOp_lX37mrPSYGxjgIZVxevpPgBhVFlnAMqC2iRd87XupmWgiluSos8I7i1VESBzwlFZGk5hRb8och4zwmDBDwx65XWngg6LneSXTWcKjKKGM2NnX7wHrZBuyRQ".to_vec()),
            dp: Some(b"Gfo49fW5CZNTSEKQ_id0R2K9TMsoecw-jB2uCgqQi-TSLOtVRC5oTxA896my_SvIj8bCvEtLSzY3AhgvSCqulN3gSJbaHCCSDvAx0czAe7zfuTsxml76izeoKqg7TZAgAEnP0KXPRwJo4ff2J8lAcl3yyiLE7cLT9nuQSMRqERFVM7DQdk4wV618mQge9VGUStmYlh1MpS65N0dZWNafNuWauPTkTLZw8DFMIyizf3EC-nQYg1b6A_tYBHD3A82jPzQEQY8B3PrfGZ3DRASNv9jONk8qTQHOc5O5pLRMmUErDn_qRQCTKU483bzhooJE2a3WUEt6Pjsc1xMG4Vr3SQ".to_vec()),
            dq: Some(b"cCVai36Yi-06m1cwd8fbkhH9GUpXIvKI2Z5ZRk-smqc7piY0dEZFHftS9BaMyZYu3wM09GDklfdkNLo3mmfXkftv-cbjpvelUa50HYWx0HouKrT9UpVia0sTnmfme7BztjKunuuTcQxTBvfDfxoIi_nmUHIx9Vv1IEaALITzChGnIky3q7O_8ttKR65nFevG1JvsRBeJN6z0tzG9RBQr5mxtx3Wt2Uwcp21XjOCFHVmXjT9nMmpINQNNIC8VrGSSkjaJmNWIw5WGmDnLkKzCG2vpZO1suqIIgCsYN_Ka7ETTdZt3gFdoECUpFSiay4-4MAospvgWLv8XAFXXwfSPXQ".to_vec()),
            qi: Some(b"n-R81MpbwfWfqRSVgD8nDk7D8zlJ-tpMaojfTwNNqDt34Cr-BpMjxaQyEfMnzOd2dY4OV0rKhd29DIuwFEb2UERHdVWF3gM8f2byYGj4357CRkiwq6I050bUxd1ODgAXjVGNpOK_fmaNHDWfe5v3wVIcCmwH0mJxEu9kuz7fr9TJNxGJBGUphpGS6NQZDCbDXg9-FPafMeNV-Jdo0NQaKMwm8uZyW7YGSNpUXYnksrWt4Fa-B9H2KoC4PPSWESPxNooXdxK7Y0J1KbzNyrUmOl4dT6p_oFKcU-1unuDCZ11e6EmMKyUGjpDzTIAZ2XxmyWUJ06yzEw7oLo8noiCE_Q".to_vec()),
        };

        read_private_jwk(wallet)?;
        Ok(())
    }
}
