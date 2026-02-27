use anyhow::{Result, anyhow};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub const SESSION_KEY_LEN: usize = 32;

pub fn random_nonce_24() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

pub fn compute_hello_proof(
    identity_secret_hex: &str,
    identity_id: &str,
    device_pk: &str,
    client_key_b64: &str,
    ts: u64,
) -> Result<String> {
    let key = parse_hex_exact(identity_secret_hex, 32)?;
    let mut mac: Hmac<Sha256> =
        <Hmac<Sha256> as Mac>::new_from_slice(&key).map_err(|_| anyhow!("hmac key"))?;
    let material = format!("{}|{}|{}|{}", identity_id, device_pk, client_key_b64, ts);
    mac.update(material.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

pub fn verify_hello_proof(
    identity_secret_hex: &str,
    identity_id: &str,
    device_pk: &str,
    client_key_b64: &str,
    ts: u64,
    proof_hex: &str,
) -> Result<bool> {
    let expected = compute_hello_proof(
        identity_secret_hex,
        identity_id,
        device_pk,
        client_key_b64,
        ts,
    )?;
    Ok(expected.eq_ignore_ascii_case(proof_hex))
}

pub fn derive_session_key(
    server_secret_hex: &str,
    identity_secret_hex: &str,
    client_key_b64: &str,
    context: &str,
) -> Result<(Vec<u8>, String)> {
    let server_secret_bytes = parse_hex_exact(server_secret_hex, 32)?;
    let identity_secret = parse_hex_exact(identity_secret_hex, 32)?;
    let client_key = decode_b64_exact(client_key_b64, 32)?;

    let mut ss = [0u8; 32];
    ss.copy_from_slice(&server_secret_bytes);
    let server_secret = StaticSecret::from(ss);
    let server_pub = PublicKey::from(&server_secret);

    let mut cp = [0u8; 32];
    cp.copy_from_slice(&client_key);
    let client_pub = PublicKey::from(cp);

    let shared = server_secret.diffie_hellman(&client_pub);
    let hk = Hkdf::<Sha256>::new(Some(&identity_secret), shared.as_bytes());

    let mut out = [0u8; SESSION_KEY_LEN];
    hk.expand(context.as_bytes(), &mut out)
        .map_err(|_| anyhow!("hkdf expand failed"))?;

    let server_pub_b64 = base64::engine::general_purpose::STANDARD.encode(server_pub.as_bytes());
    Ok((out.to_vec(), server_pub_b64))
}

pub fn encrypt_payload(session_key: &[u8], nonce: &[u8; 24], plaintext: &[u8]) -> Result<Vec<u8>> {
    if session_key.len() != SESSION_KEY_LEN {
        return Err(anyhow!("invalid session key length"));
    }
    let key = Key::from_slice(session_key);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(nonce);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow!("encrypt failed"))
}

pub fn decrypt_payload(session_key: &[u8], nonce: &[u8; 24], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if session_key.len() != SESSION_KEY_LEN {
        return Err(anyhow!("invalid session key length"));
    }
    let key = Key::from_slice(session_key);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XNonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("decrypt failed"))
}

pub fn parse_hex_exact(hex_in: &str, expected_len: usize) -> Result<Vec<u8>> {
    let bytes = hex::decode(hex_in.trim()).map_err(|_| anyhow!("invalid hex"))?;
    if bytes.len() != expected_len {
        return Err(anyhow!(
            "expected {} bytes, got {}",
            expected_len,
            bytes.len()
        ));
    }
    Ok(bytes)
}

pub fn decode_b64_exact(b64: &str, expected_len: usize) -> Result<Vec<u8>> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| anyhow!("invalid base64"))?;
    if bytes.len() != expected_len {
        return Err(anyhow!(
            "expected {} bytes, got {}",
            expected_len,
            bytes.len()
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_roundtrip() {
        let identity_secret = "11".repeat(32);
        let p = compute_hello_proof(&identity_secret, "id", "dev", "abcd", 10).unwrap();
        assert!(verify_hello_proof(&identity_secret, "id", "dev", "abcd", 10, &p).unwrap());
    }

    #[test]
    fn encrypt_roundtrip() {
        let key = vec![7u8; 32];
        let nonce = random_nonce_24();
        let input = b"hello world";
        let enc = encrypt_payload(&key, &nonce, input).unwrap();
        let dec = decrypt_payload(&key, &nonce, &enc).unwrap();
        assert_eq!(input.to_vec(), dec);
    }
}
