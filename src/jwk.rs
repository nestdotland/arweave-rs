use crate::b64::decode_url;
use rsa::{BigUint, RSAPrivateKey, RSAPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::from_str;

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
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub dp: Vec<u8>,
    pub dq: Vec<u8>,
    pub qi: Vec<u8>,
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
    let p = BigUint::from_bytes_be(&decode_url(&components.p)?);
    let q = BigUint::from_bytes_be(&decode_url(&components.q)?);
    let dp = BigUint::from_bytes_be(&decode_url(&components.dp)?);
    let dq = BigUint::from_bytes_be(&decode_url(&components.dq)?);
    let qi = BigUint::from_bytes_be(&decode_url(&components.qi)?);

    let mut primes = Vec::<BigUint>::new();

    primes.push(p);
    primes.push(q);
    primes.push(dp);
    primes.push(dq);
    primes.push(qi);

    let private_key = RSAPrivateKey::from_components(n, e, d, primes);

    Ok(private_key)
}
