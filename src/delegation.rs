use serde_json::{json, Value};
use crate::canonical::canonical_hash;
#[derive(Clone, Debug)]
pub struct Delegation { pub delegator: String, pub delegate: String, pub intent: Value, pub max_amount_cents: u64, pub expiry: u64, pub hash: String }
pub fn create_delegation(delegator: &str, delegate: &str, intent: Value, max_amount_cents: u64, expiry: u64) -> Delegation {
    let v = json!({"delegator": delegator, "delegate": delegate, "intent": intent, "maxAmountCents": max_amount_cents, "expiry": expiry});
    Delegation { delegator: delegator.to_string(), delegate: delegate.to_string(), intent, max_amount_cents, expiry, hash: canonical_hash(&v) }
}
pub fn verify_delegation_chain(chain: &[Delegation]) -> Result<(), String> {
    if chain.is_empty() { return Err("CHAIN_EMPTY".into()); }
    for (i, d) in chain.iter().enumerate() {
        let v = json!({"delegator": d.delegator, "delegate": d.delegate, "intent": d.intent, "maxAmountCents": d.max_amount_cents, "expiry": d.expiry});
        if canonical_hash(&v) != d.hash { return Err("DELEGATION_HASH_MISMATCH".into()); }
        if i>0 {
            let prev = &chain[i-1];
            if d.delegator != prev.delegate { return Err("CHAIN_LINK_MISMATCH".into()); }
            // No-widening: delegate cannot increase amount or extend expiry
            if d.max_amount_cents > prev.max_amount_cents { return Err("AMOUNT_WIDENED".into()); }
            if d.expiry > prev.expiry { return Err("EXPIRY_WIDENED".into()); }
        }
    }
    Ok(())
}
