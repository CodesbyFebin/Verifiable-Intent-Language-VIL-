use vil::{KeyPair, make_disclosure, create_sdjwt, verify_sdjwt, create_delegation, verify_delegation_chain};
use serde_json::json;
#[test]
fn es256_sign_verify() {
    let issuer = KeyPair::generate("iss-1");
    let user = KeyPair::generate("user-1");
    let intent = json!({"action":"purchase","item":"book","maxAmountCents":2500});
    let jwt = create_sdjwt(&issuer, "did:web:issuer.com", "did:web:user.com", intent, vec![], &user);
    assert!(verify_sdjwt(&jwt, &issuer, &user).is_ok());
}
#[test]
fn disclosure_hash() {
    let issuer = KeyPair::generate("iss-1");
    let user = KeyPair::generate("user-1");
    let d = make_disclosure("salt-1","item", json!("book"));
    let jwt = create_sdjwt(&issuer, "did:web:issuer.com", "did:web:user.com", json!({"action":"purchase"}), vec![d.clone()], &user);
    assert!(jwt.disclosure_hashes.contains(&d.hash));
    assert!(verify_sdjwt(&jwt, &issuer, &user).is_ok());
    let mut tampered = jwt.clone(); tampered.disclosures[0].value = json!("car");
    assert!(verify_sdjwt(&tampered, &issuer, &user).is_err());
}
#[test]
fn cnf_binding() {
    let issuer = KeyPair::generate("iss-1");
    let user = KeyPair::generate("user-1");
    let attacker = KeyPair::generate("attacker-1");
    let jwt = create_sdjwt(&issuer, "did:web:issuer.com", "did:web:user.com", json!({}), vec![], &user);
    assert!(verify_sdjwt(&jwt, &issuer, &attacker).is_err());
}
#[test]
fn delegation_no_widening() {
    let intent = json!({"action":"purchase"});
    let d1 = create_delegation("did:web:user.com","did:web:agent.com", intent.clone(), 2500, 100);
    let d2_ok = create_delegation("did:web:agent.com","did:web:sub.com", intent.clone(), 1000, 100);
    assert!(verify_delegation_chain(&[d1.clone(), d2_ok]).is_ok());
    let d2_bad = create_delegation("did:web:agent.com","did:web:sub.com", intent.clone(), 9999, 100);
    assert!(verify_delegation_chain(&[d1.clone(), d2_bad]).is_err());
    let d2_bad2 = create_delegation("did:web:agent.com","did:web:sub.com", intent, 1000, 999);
    assert!(verify_delegation_chain(&[d1, d2_bad2]).is_err());
}
#[test]
fn jwk_thumbprint_deterministic() {
    let k = KeyPair::generate("k1");
    assert_eq!(k.thumbprint(), k.thumbprint());
    assert!(k.jwk()["x"].as_str().unwrap().len()>10);
}
#[test]
fn tampered_jws_fails() {
    let issuer = KeyPair::generate("iss-1");
    let user = KeyPair::generate("user-1");
    let mut jwt = create_sdjwt(&issuer, "did:web:issuer.com", "did:web:user.com", json!({"action":"purchase"}), vec![], &user);
    jwt.jws = format!("{}x", jwt.jws);
    assert!(verify_sdjwt(&jwt, &issuer, &user).is_err());
}
