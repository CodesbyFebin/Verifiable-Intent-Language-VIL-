# VIL Hygiene
- ES256 only. No Ed25519 claimed as ES256. No mock signature.
- SD-JWT: disclosure hash = sha256(b64url([salt,name,value])). Tamper breaks hash.
- cnf binding: jkt = JWK thumbprint of subject key. Mismatch = no verify.
- Delegation no-widening: amount and expiry can only narrow, never widen.
- No simulated zk, no simulated TEE. If you need TEE/zkVM, supply real proof via Rust-C.
