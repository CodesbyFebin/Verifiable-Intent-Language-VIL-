use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use crate::canonical::{b64url, canonical_hash};
#[derive(Clone)]
pub struct KeyPair { pub signing_key: SigningKey, pub verifying_key: VerifyingKey, pub kid: String }
impl KeyPair {
    pub fn generate(kid: &str) -> Self {
        let sk = SigningKey::random(&mut OsRng);
        let vk = VerifyingKey::from(&sk);
        Self { signing_key: sk, verifying_key: vk, kid: kid.to_string() }
    }
    pub fn jwk(&self) -> Value {
        let pt = self.verifying_key.to_encoded_point(false);
        json!({"kty":"EC","crv":"P-256","x": b64url(pt.x().unwrap()), "y": b64url(pt.y().unwrap()), "kid": self.kid, "alg":"ES256","use":"sig"})
    }
    pub fn thumbprint(&self) -> String {
        let j = json!({"crv":"P-256","kty":"EC","x": self.jwk()["x"], "y": self.jwk()["y"]});
        canonical_hash(&j)
    }
    pub fn jwk_thumbprint_cnf(&self) -> Value { json!({"jkt": self.thumbprint()}) }
}
