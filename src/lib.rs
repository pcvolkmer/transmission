use aead::Generate;
use base64::Engine;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{RngExt, rng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::oneshot;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRequest {
    pub uuid: String,
    pub destination: String,
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl StoredRequest {
    pub fn hmac(&self, key: &str) -> String {
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key.as_bytes()) else {
            return String::new();
        };
        mac.update(serde_json::to_string(self).unwrap_or_default().as_bytes());

        hex::encode(mac.finalize().into_bytes())
    }

    pub fn encrypt_with(&self, key: [u8; 32]) -> String {
        encrypt_with(&serde_json::to_string(self).unwrap_or_default(), key)
    }

    pub fn decrypt_with(encrypted: &str, key: [u8; 32]) -> Result<Self, ()> {
        let json = decrypt_with(encrypted, key)?;
        serde_json::from_str(&json).map_err(|_| ())
    }
}

#[derive(Debug)]
pub struct PendingRequest {
    pub request: StoredRequest,
    pub timestamp: u64,
    pub response_tx: Option<oneshot::Sender<AgentResponse>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl AgentResponse {
    pub fn encrypt_with(&self, key: [u8; 32]) -> String {
        encrypt_with(&serde_json::to_string(self).unwrap_or_default(), key)
    }

    pub fn decrypt_with(encrypted: &str, key: [u8; 32]) -> Result<Self, ()> {
        let json = decrypt_with(encrypted, key)?;
        serde_json::from_str(&json).map_err(|_| ())
    }
}

pub fn create_shared_secret(secret: &str, others_public: &str, salt: &str) -> Result<[u8; 32], ()> {
    let secret: StaticSecret = decode_key(secret)?.into();
    let others_public: PublicKey = decode_key(others_public)?.into();

    let shared_secret = secret.diffie_hellman(&others_public);
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), shared_secret.as_bytes());

    let mut key = [0u8; 32];
    hk.expand(b"chacha20-key", &mut key).map_err(|_| ())?;

    Ok(key)
}

pub fn create_key_pair() -> (String, String) {
    let secret = StaticSecret::from(rng().random::<[u8; 32]>());
    let public = PublicKey::from(&secret);

    (encode_key(secret.as_bytes()), encode_key(public.as_bytes()))
}

fn encode_key(key: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(key)
}

fn decode_key(key: &str) -> Result<[u8; 32], ()> {
    let decoded = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(key)
        .map_err(|_| ())?;

    Ok(decoded.try_into().map_err(|_| ())?)
}

fn encrypt_with(value: &str, key: [u8; 32]) -> String {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::generate();

    let Ok(ciphertext) = cipher.encrypt(
        &nonce,
        serde_json::to_string(value).unwrap_or_default().as_bytes(),
    ) else {
        return String::new();
    };

    format!(
        "{}.{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(ciphertext),
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(nonce),
    )
}

pub fn decrypt_with(encrypted: &str, key: [u8; 32]) -> Result<String, ()> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    let Some((ciphertext, nonce)) = encrypted.split_once('.') else {
        return Err(());
    };

    let json = cipher
        .decrypt(
            Nonce::from_slice(
                base64::engine::general_purpose::STANDARD_NO_PAD
                    .decode(nonce.as_bytes())
                    .map_err(|_| ())?
                    .as_slice(),
            ),
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(ciphertext.as_bytes())
                .map_err(|_| ())?
                .as_slice(),
        )
        .map_err(|_| ())?;
    serde_json::from_slice(&json).map_err(|_| ())
}
