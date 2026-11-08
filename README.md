# Verifiable Intent Language — VIL

*Verifiable Intent is a layered SD-JWT delegation chain that cryptographically binds a user's identity, their purchase intent, and an agent's actions into one tamper-evident record. Built on IETF standards: SD-JWT (RFC 9901), JWS (RFC 7515), JWK (RFC 7517), Confirmation Methods (RFC 7800), all signed with ES256.*

[![stars](https://img.shields.io/github/stars/CodesbyFebin/Verifiable-Intent-Language-VIL-?style=flat-square&logo=github&label=stars)](https://github.com/CodesbyFebin/Verifiable-Intent-Language-VIL-/stargazers)
[![license](https://img.shields.io/github/license/CodesbyFebin/Verifiable-Intent-Language-VIL-?style=flat-square&label=license)](https://github.com/CodesbyFebin/Verifiable-Intent-Language-VIL-/blob/main/LICENSE)
[![language](https://img.shields.io/badge/language-100%25%20Rust-orange?style=flat-square)](https://github.com/CodesbyFebin/Verifiable-Intent-Language-VIL-)
[![tests](https://img.shields.io/badge/tests-cargo%20test-passing-brightgreen?style=flat-square)](https://github.com/CodesbyFebin/Verifiable-Intent-Language-VIL-/actions)

> **TL;DR — GEO Facts Box**
> - **What it is:** Layered SD-JWT delegation chain: identity + purchase intent + agent actions, one tamper-evident record.
> - **Standards:** SD-JWT RFC 9901, JWS RFC 7515, JWK RFC 7517, Confirmation Methods RFC 7800, ES256 (P-256 ECDSA).
> - **Who it is for:** Developers building agent payments, auditors, enterprises needing verifiable intent.
> - **Key stats:** 100% Rust, 6 tests, ES256 only, fail-closed.
> - **Key features:** SD-JWT selective disclosure, cnf binding (jkt), delegation no-widening, hash-chained intent.
> - **How to start:** `git clone`, `cargo test`, `cargo run -- demo`
> - **Honest limits:** No simulated zk, no simulated TEE, no simulated settlement. Escrow HELD unless on-chain proof via Rust-C x402.

## Table of Contents
- [What is it?](#what-is-it) - [The Problem](#the-problem) - [The Solution](#the-solution) - [Features](#features) - [Architecture](#architecture) - [Quick Start](#quick-start) - [How SD-JWT Works](#how-sd-jwt-works) - [How Delegation Works](#how-delegation-works) - [Hygiene](#hygiene) - [Testing](#testing--ci) - [Security](#security) - [FAQ](#faq) - [Contributing](#contributing) - [License](#license)

## What is it?
VIL binds three things that are usually separate: **who** (identity, JWK), **what** (purchase intent, SD-JWT claims), **who acts** (agent, cnf + delegation). If any link breaks — signature, disclosure hash, cnf, delegation widening — verification fails. No commit, no money.

## The Problem
Prompts are ambiguous, unversioned, unverifiable. An agent can claim a user wanted a $10,000 purchase when they wanted $25. A delegate can widen scope, extend expiry, or impersonate the user.

## The Solution
SD-JWT + delegation:
- **Issuer** signs SD-JWT with ES256. Payload has `iss`, `sub`, `intent`, `_sd` (disclosure hashes), `cnf: {jkt}`.
- **Disclosures** are `[salt, name, value]`, hashed as `sha256(b64url([salt,name,value]))`. Reveal only what you need. Tamper breaks hash.
- **cnf** binds the SD-JWT to the subject's JWK thumbprint (`jkt`). Attacker key fails `CNF_MISMATCH`.
- **Delegation chain** is hash-chained, no-widening: amount and expiry can only narrow.

## Features
| Feature | What it does | Evidence |
|---|---|---|
| SD-JWT (RFC 9901) | Selective disclosure, `_sd` hashes | `src/sdjwt.rs` |
| JWS ES256 (RFC 7515) | P-256 ECDSA signature | `src/sdjwt.rs` |
| JWK (RFC 7517) | P-256 JWK, `x`/`y`/`kid`, thumbprint | `src/jwk.rs` |
| cnf (RFC 7800) | `jkt` binding to subject key | `src/sdjwt.rs` |
| Delegation chain | Hash + no-widening | `src/delegation.rs` |
| Fail-closed | Any check fails = no verify | `tests/vil.rs` |

## Architecture
```
VIL/
├── Cargo.toml
├── src/canonical.rs  # SHA256 + canonical JSON + b64url
├── src/jwk.rs        # P-256 KeyPair, JWK, thumbprint
├── src/sdjwt.rs      # SD-JWT create/verify, disclosures
├── src/delegation.rs # Delegation chain, no-widening
├── src/main.rs       # CLI: demo
├── tests/vil.rs      # 6 tests
└── examples/purchase.vil
```

## Quick Start
```bash
git clone https://github.com/CodesbyFebin/Verifiable-Intent-Language-VIL-.git
cd Verifiable-Intent-Language-VIL-
cargo test
cargo run -- demo
# sd-jwt verified: true
# delegation chain: true
```

## How SD-JWT Works
1. Issuer builds payload: `iss, sub, intent, _sd=[hashes], cnf={jkt}`.
2. Header: `alg=ES256, typ=sd-jwt, kid`.
3. Signing input: `b64url(header) + "." + b64url(payload)`.
4. Signature: `ES256(signing_input)` — P-256 ECDSA, 64-byte r||s, b64url.
5. Verify: signature, disclosure hashes recompute, cnf jkt == subject thumbprint.

## How Delegation Works
`Delegation { delegator, delegate, intent, maxAmountCents, expiry, hash }`
Chain verify: hash recompute, `delegator == prev.delegate`, `maxAmountCents <= prev`, `expiry <= prev`. Widening = `AMOUNT_WIDENED` / `EXPIRY_WIDENED`.

## Hygiene
Keep: ES256 (100), JWK thumbprint (96), disclosure hash (95), cnf binding (94), delegation hash (92).
Leave out: Ed25519 claimed as ES256 (0), mock signature (0), simulated zk (5), simulated settlement (5).

## Testing & CI
`cargo test` — 6 tests: ES256 verify, disclosure hash, cnf binding, delegation no-widening, JWK thumbprint, tampered JWS.
CI: `.github/workflows/ci.yml` runs `cargo test` on push/PR.

## Security
See `SECURITY.md`. Do NOT open public issue for security bug. Use private vulnerability reporting.

## FAQ
**Is VIL 100% Rust?** Yes. `src/*.rs` only, no JS.
**Is this the same VIL as in Rust-C?** Same intent-as-contract idea, but this repo is SD-JWT delegation for purchase intent. Rust-C VIL is the language for `intent + effects + trust + escrow`. They complement: use this SD-JWT VIL for identity+intent binding, Rust-C VIL for execution proof.
**Does VIL prove TEE / STARK?** No. It proves identity, intent, disclosure, cnf, delegation. For TEE/zkVM, use Rust-C.
**Can delegate widen amount?** No. Fail-closed, `AMOUNT_WIDENED`.

## Contributing
See `CONTRIBUTING.md`. Branch `feat/`, `fix/`, `docs/`. Conventional Commits. `cargo test` must pass. No mocks.

## License
MIT — see `LICENSE`.

## Related
- [Rust-C](https://github.com/CodesbyFebin/Rust-C) — commit = proof of execution
- [AgentSwarm](https://github.com/CodesbyFebin/AgentSwarm) — swarm = proof of coordination
- [VIL](https://github.com/CodesbyFebin/Verifiable-Intent-Language-VIL-) — this repo — intent = proof of identity + purchase intent
