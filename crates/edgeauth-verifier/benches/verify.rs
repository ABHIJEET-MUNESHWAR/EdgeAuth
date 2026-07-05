//! Cold-start and steady-state verification benchmarks.
//!
//! The headline metric for an edge verifier is latency: how quickly can a cold
//! worker (JWKS arriving as JSON) accept or reject a token, and how cheap is the
//! steady-state hot path once the key set is parsed. We measure both, plus the
//! `did:key` credential path which needs no key set at all.

use std::collections::BTreeMap;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ed25519_dalek::SigningKey;
use edgeauth_types::{
    credential::CredentialSubject, encode_jwt, Audience, Did, Jwk, Jwks, JwtClaims, JwtHeader,
    TrustPolicy, VerifiableCredential, JWT_ALG,
};
use edgeauth_verifier::{verify_credential, verify_jwt};

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn sample_token(sk: &SigningKey, kid: &str) -> String {
    let header = JwtHeader {
        alg: JWT_ALG.to_string(),
        typ: Some("JWT".to_string()),
        kid: Some(kid.to_string()),
    };
    let claims = JwtClaims {
        iss: Some("https://issuer.example".to_string()),
        sub: Some("user-1".to_string()),
        aud: Some(Audience::Single("edge-api".to_string())),
        exp: Some(4_000_000_000),
        nbf: Some(1_000),
        iat: Some(1_000),
        jti: Some("tok-1".to_string()),
        scope: Some("openid documents:read".to_string()),
        roles: vec!["editor".to_string()],
    };
    encode_jwt(&header, &claims, sk).unwrap()
}

fn sample_credential() -> VerifiableCredential {
    let issuer_sk = signing_key(1);
    let issuer = Did::from_verifying_key(&issuer_sk.verifying_key());
    let subject = Did::from_verifying_key(&signing_key(2).verifying_key());
    let mut claims = BTreeMap::new();
    claims.insert("kyc".to_string(), "verified".to_string());
    let mut vc = VerifiableCredential {
        id: "cred-1".to_string(),
        credential_type: "KycVerified".to_string(),
        issuer,
        subject: CredentialSubject {
            id: subject,
            claims,
        },
        issued_at: 1_000,
        expires_at: Some(4_000_000_000),
        proof: None,
    };
    vc.sign_with(&issuer_sk, 1_000).unwrap();
    vc
}

fn bench_verify(c: &mut Criterion) {
    let sk = signing_key(1);
    let token = sample_token(&sk, "k1");
    let jwks = Jwks::from_keys([Jwk::from_verifying_key(&sk.verifying_key(), "k1")]);
    let jwks_json = serde_json::to_string(&jwks).unwrap();
    let policy = TrustPolicy::permissive()
        .with_trusted_issuer("https://issuer.example")
        .with_audience("edge-api")
        .requiring_scope("openid")
        .with_leeway(30);
    let now = 2_000_000_000;

    // Steady-state hot path: JWKS already parsed and indexed.
    c.bench_function("jwt_verify_hot", |b| {
        b.iter(|| {
            let out = verify_jwt(
                std::hint::black_box(&token),
                std::hint::black_box(&jwks),
                std::hint::black_box(&policy),
                now,
            );
            debug_assert!(out.valid);
        });
    });

    // Cold path: JWKS arrives as JSON (as in a fresh serverless invocation).
    c.bench_function("jwt_verify_cold", |b| {
        b.iter(|| {
            let jwks = Jwks::from_json(std::hint::black_box(&jwks_json)).unwrap();
            let out = verify_jwt(std::hint::black_box(&token), &jwks, &policy, now);
            debug_assert!(out.valid);
        });
    });

    // did:key credential path — self-contained, no key set to resolve.
    let vc = sample_credential();
    let vc_policy = TrustPolicy::permissive().with_trusted_issuer(vc.issuer.as_str());
    c.bench_function("credential_verify", |b| {
        b.iter(|| {
            let out = verify_credential(std::hint::black_box(&vc), &vc_policy, now);
            debug_assert!(out.valid);
        });
    });

    // Verification cost as the trusted key set grows (kid lookup scaling).
    let mut group = c.benchmark_group("jwt_verify_by_jwks_size");
    for size in [1_usize, 8, 64] {
        let keys: Vec<Jwk> = (0..size)
            .map(|i| {
                let k = signing_key((i as u8).wrapping_add(10));
                Jwk::from_verifying_key(&k.verifying_key(), format!("k{i}"))
            })
            .chain(std::iter::once(Jwk::from_verifying_key(
                &sk.verifying_key(),
                "k1",
            )))
            .collect();
        let big_jwks = Jwks::from_keys(keys);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let out = verify_jwt(std::hint::black_box(&token), &big_jwks, &policy, now);
                debug_assert!(out.valid);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
