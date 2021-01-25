use serde::{Serialize, Deserialize};
use serde_json::{from_str};
use rsa::{BigUint, RSAPrivateKey, RSAPublicKey};

#[derive(Serialize, Deserialize)]
struct JwkPublic {
  kty: String,
  n: Vec<u8>,
  e: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct JwkPrivate {
  kty: String,
  n: Vec<u8>,
  e: Vec<u8>,
  d: Vec<u8>,
  p: Vec<u8>,
  q: Vec<u8>,
  dp: Vec<u8>,
  dq: Vec<u8>,
  qi: Vec<u8>,
}

pub fn read_public_jwk (data: &str) -> Result<RSAPublicKey, Box<dyn std::error::Error>> {
  let components: JwkPublic = from_str(&data)?;

  if (components.kty != "RSA") return Err("invalid key type");

  let e = BigUint::from_bytes_be(components.e);
  let n = BigUint::from_bytes_be(components.n);

  let public_key = RSAPublicKey::new(e, n)?;

  Ok(public_key)
}

pub fn read_private_jwk (data: &str) -> Result<RSAPrivateKey, Box<dyn std::error::Error>> {
  let components: JwkPrivate = from_str(&data)?;

  if (components.kty != "RSA") return Err("invalid key type");

  let n = BigUint::from_bytes_be(components.n);
  let e = BigUint::from_bytes_be(components.e);
  let d = BigUint::from_bytes_be(components.d);
  let p = BigUint::from_bytes_be(components.p);
  let q = BigUint::from_bytes_be(components.q);
  let dp = BigUint::from_bytes_be(components.dp);
  let dq = BigUint::from_bytes_be(components.dq);
  let qi = BigUint::from_bytes_be(components.qi);

  let mut primes = Vec::<BigUint>new();

  primes.push(p);
  primes.push(q);
  primes.push(dp);
  primes.push(dq);
  primes.push(qi);

  let private_key = RSAPrivateKey::from_components(n, e, d, primes)?;

  Ok(private_key)
}