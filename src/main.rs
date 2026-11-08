use vil::{KeyPair, make_disclosure, create_sdjwt, verify_sdjwt, create_delegation, verify_delegation_chain};
use serde_json::json;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len()<2 { eprintln!("Usage: vil <demo>"); std::process::exit(2); }
    if args[1]=="demo" {
        let issuer = KeyPair::generate("issuer-1");
        let user = KeyPair::generate("user-1");
        let agent = KeyPair::generate("agent-1");
        let intent = json!({"action":"purchase","item":"book","maxAmountCents":2500,"merchant":"did:web:acme.com"});
        let disc = make_disclosure("salt-1","item", json!("book"));
        let jwt = create_sdjwt(&issuer, "did:web:issuer.com", &user.thumbprint(), intent.clone(), vec![disc], &user);
        println!("sd-jwt verified: {:?}", verify_sdjwt(&jwt, &issuer, &user).is_ok());
        println!("jwk thumbprint user: {}", user.thumbprint());
        let d1 = create_delegation("did:web:user.com","did:web:agent.com", intent.clone(), 2500, 9999999999);
        let d2 = create_delegation("did:web:agent.com","did:web:subagent.com", intent, 1000, 9999999999);
        println!("delegation chain: {:?}", verify_delegation_chain(&[d1,d2]).is_ok());
        println!("agent cnf jkt: {}", agent.thumbprint());
    }
}
