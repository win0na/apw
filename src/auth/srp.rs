//! SRP-6a client for Apple's GSA login.
//!
//! Apple uses the RFC 5054 2048-bit group with g = 2 and SHA-256. The password
//! is not hashed the RFC 5054 way: it is SHA-256 first, then PBKDF2-HMAC-SHA256
//! with the server's salt and iteration count. The username is not part of x.

use num_bigint::BigUint;
use num_traits::Zero;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

const N_HEX: &str = "\
AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050\
A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50\
E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8\
55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B\
CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748\
544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6\
AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6\
94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";

const G: u32 = 2;
const N_BYTES: usize = 256;

pub struct SrpClient {
    secret: BigUint,
    public: Vec<u8>,
}

pub struct Proof {
    /// H(S), the SRP session key.
    pub key: Vec<u8>,
    /// M1, sent to the server.
    pub m1: Vec<u8>,
    /// M2, compared against the server's reply.
    pub m2: Vec<u8>,
}

impl std::fmt::Debug for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proof")
            .field("m1", &data_encoding::HEXLOWER.encode(&self.m1))
            .field("m2", &data_encoding::HEXLOWER.encode(&self.m2))
            .finish_non_exhaustive()
    }
}

impl SrpClient {
    pub fn new() -> Self {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let secret = BigUint::from_bytes_be(&secret);
        let public = pad(&BigUint::from(G).modpow(&secret, &modulus()));
        Self { secret, public }
    }

    pub fn public(&self) -> &[u8] {
        &self.public
    }

    pub fn prove(
        &self,
        username: &str,
        password: &str,
        salt: &[u8],
        iterations: u32,
        server_public: &[u8],
    ) -> Result<Proof> {
        let n = modulus();
        let g = BigUint::from(G);
        let server_b = BigUint::from_bytes_be(server_public);
        if server_b.is_zero() || server_b >= n {
            return Err(Error::Message(
                "server sent an invalid SRP public key".into(),
            ));
        }

        let x = password_x(password, salt, iterations);
        let gx = g.modpow(&x, &n);
        let k = multiplier();
        let kgx = (k * gx) % &n;

        // B - k*g^x mod N, without underflow.
        let base = (server_b.clone() + &n - kgx) % &n;
        let server_bytes = pad(&server_b);

        let u = scrambling(&self.public, &server_bytes);
        let exponent = &self.secret + &u * &x;
        let shared = base.modpow(&exponent, &n);

        let key = sha256(&[&shared.to_bytes_be()]);
        let m1 = sha256(&[
            &hash_n_xor_g(),
            &sha256(&[username.as_bytes()]),
            salt,
            &self.public,
            &server_bytes,
            &key,
        ]);
        let m2 = sha256(&[&self.public, &m1, &key]);

        Ok(Proof { key, m1, m2 })
    }
}

impl Default for SrpClient {
    fn default() -> Self {
        Self::new()
    }
}

pub fn modulus() -> BigUint {
    BigUint::parse_bytes(N_HEX.as_bytes(), 16).expect("valid group")
}

fn multiplier() -> BigUint {
    let n = modulus();
    BigUint::from_bytes_be(&sha256(&[&pad(&n), &pad(&BigUint::from(G))]))
}

fn hash_n_xor_g() -> Vec<u8> {
    let n = sha256(&[&pad(&modulus())]);
    let g = sha256(&[&pad(&BigUint::from(G))]);
    n.iter().zip(g.iter()).map(|(a, b)| a ^ b).collect()
}

fn scrambling(public: &[u8], server_public: &[u8]) -> BigUint {
    BigUint::from_bytes_be(&sha256(&[public, server_public]))
}

fn password_x(password: &str, salt: &[u8], iterations: u32) -> BigUint {
    let inner = sha256(&[password.as_bytes()]);
    let mut stretched = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(&inner, salt, iterations.max(1), &mut stretched);
    let outer = sha256(&[salt, &sha256(&[b":", &stretched])]);
    BigUint::from_bytes_be(&outer)
}

fn pad(value: &BigUint) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    if bytes.len() >= N_BYTES {
        return bytes;
    }
    let mut out = vec![0u8; N_BYTES - bytes.len()];
    out.extend_from_slice(&bytes);
    out
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(salt: &[u8], iterations: u32, password: &str, public: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let n = modulus();
        let g = BigUint::from(G);
        let x = password_x(password, salt, iterations);
        let v = g.modpow(&x, &n);

        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let b = BigUint::from_bytes_be(&secret);
        let server_public = ((multiplier() * &v) + g.modpow(&b, &n)) % &n;

        let client_public = BigUint::from_bytes_be(public);
        let u = scrambling(public, &pad(&server_public));
        let shared = (client_public * v.modpow(&u, &n)).modpow(&b, &n);
        let key = sha256(&[&shared.to_bytes_be()]);

        (pad(&server_public), key)
    }

    #[test]
    fn round_trip_matches() {
        let client = SrpClient::new();
        let salt = b"0123456789abcdef";
        let (server_public, server_key) = server(salt, 1000, "correct horse", client.public());

        let proof = client
            .prove(
                "user@example.com",
                "correct horse",
                salt,
                1000,
                &server_public,
            )
            .unwrap();

        assert_eq!(proof.key, server_key);
        assert_eq!(proof.m1.len(), 32);
        assert_eq!(proof.m2.len(), 32);
    }

    #[test]
    fn wrong_password_does_not_match() {
        let client = SrpClient::new();
        let salt = b"0123456789abcdef";
        let (server_public, server_key) = server(salt, 1000, "right", client.public());

        let proof = client
            .prove("user@example.com", "wrong", salt, 1000, &server_public)
            .unwrap();

        assert_ne!(proof.key, server_key);
    }

    #[test]
    fn pbkdf2_matches_rfc_vector() {
        let mut out = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(b"password", b"salt", 1, &mut out);
        assert_eq!(
            data_encoding::HEXLOWER.encode(&out),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }

    #[test]
    fn rejects_zero_server_public() {
        let client = SrpClient::new();
        let error = client
            .prove("user@example.com", "pw", b"salt", 1, &[0u8; 256])
            .unwrap_err();
        assert!(error.to_string().contains("invalid SRP public key"));
    }
}
