use serde_json::Value;
use sha2::{Digest, Sha256};
pub fn sha256_hex(b: &[u8]) -> String { hex::encode(Sha256::digest(b)) }
pub fn canonical_stringify(v: &Value) -> String { serde_json::to_string(v).unwrap() }
pub fn canonical_hash(v: &Value) -> String { sha256_hex(canonical_stringify(v).as_bytes()) }
pub fn b64url(b: &[u8]) -> String { base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, b) }
pub fn b64url_decode(s: &str) -> Result<Vec<u8>, String> { base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, s).map_err(|e| e.to_string()) }
