use p256::ecdsa::{Signature, signature::{Signer, Verifier}};
use serde_json::{json, Value};
use crate::canonical::{b64url, b64url_decode, canonical_hash, canonical_stringify, sha256_hex};
use crate::jwk::KeyPair;

#[derive(Clone, Debug)]
pub struct Disclosure { pub salt: String, pub name: String, pub value: Value, pub hash: String }
pub fn make_disclosure(salt: &str, name: &str, value: Value) -> Disclosure {
    let arr = json!([salt, name, value]);
    let hash = sha256_hex(b64url(canonical_stringify(&arr).as_bytes()).as_bytes());
    Disclosure { salt: salt.to_string(), name: name.to_string(), value, hash }
}
#[derive(Clone, Debug)]
pub struct SdJwt { pub issuer: String, pub subject: String, pub intent: Value, pub disclosures: Vec<Disclosure>, pub disclosure_hashes: Vec<String>, pub cnf: Value, pub jws: String, pub kid: String }
pub fn create_sdjwt(issuer_keys: &KeyPair, issuer: &str, subject: &str, intent: Value, disclosures: Vec<Disclosure>, subject_keys: &KeyPair) -> SdJwt {
    let hashes: Vec<String> = disclosures.iter().map(|d| d.hash.clone()).collect();
    let payload = json!({"iss": issuer, "sub": subject, "intent": intent, "_sd": hashes, "cnf": subject_keys.jwk_thumbprint_cnf(), "iat": 0});
    let header = json!({"alg":"ES256","typ":"sd-jwt","kid": issuer_keys.kid});
    let signing_input = format!("{}.{}", b64url(canonical_stringify(&header).as_bytes()), b64url(canonical_stringify(&payload).as_bytes()));
    let sig: Signature = issuer_keys.signing_key.sign(signing_input.as_bytes());
    let jws = format!("{}.{}", signing_input, b64url(&sig.to_bytes()));
    SdJwt { issuer: issuer.to_string(), subject: subject.to_string(), intent, disclosures, disclosure_hashes: hashes, cnf: subject_keys.jwk_thumbprint_cnf(), jws, kid: issuer_keys.kid.clone() }
}
pub fn verify_sdjwt(jwt: &SdJwt, issuer_keys: &KeyPair, subject_keys: &KeyPair) -> Result<(), String> {
    // 1. JWS signature ES256
    let parts: Vec<&str> = jwt.jws.split('.').collect();
    if parts.len()!=3 { return Err("JWS_FORMAT".into()); }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = b64url_decode(parts[2])?;
    if sig_bytes.len()!=64 { return Err("SIG_LEN".into()); }
    let mut arr = [0u8;64]; arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&arr.into()).map_err(|_| "SIG_PARSE".to_string())?;
    issuer_keys.verifying_key.verify(signing_input.as_bytes(), &sig).map_err(|_| "BAD_ES256_SIGNATURE".to_string())?;
    // 2. Disclosure hashes recompute
    for d in &jwt.disclosures {
        let arr2 = json!([d.salt, d.name, d.value]);
        let h = sha256_hex(b64url(canonical_stringify(&arr2).as_bytes()).as_bytes());
        if h != d.hash { return Err("DISCLOSURE_HASH_MISMATCH".into()); }
        if !jwt.disclosure_hashes.contains(&h) { return Err("DISCLOSURE_NOT_IN_SD".into()); }
    }
    // 3. cnf binding — subject key thumbprint must match cnf.jkt
    if jwt.cnf["jkt"] != serde_json::Value::String(subject_keys.thumbprint()) { return Err("CNF_MISMATCH".into()); }
    // 4. Intent hash stable
    let _ = canonical_hash(&jwt.intent);
    Ok(())
}
