//! A self-contained demonstration: mint sample artifacts with local keys and
//! verify them through the real [`EdgeVerifier`], showing both acceptance and
//! the distinct rejection reasons.

use std::collections::BTreeMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;

use edgeauth_infra::{EdgeVerifier, NoopAuditSink, StaticJwksProvider, SystemClock};
use edgeauth_types::{
    encode_jwt, Audience, CredentialSubject, Did, JwtClaims, JwtHeader, TrustPolicy,
    VerifiableCredential, VerificationOutcome, JWT_ALG,
};

use crate::config::CommonArgs;
use crate::startup::{local_jwks, local_signer, LOCAL_KID};

/// Runs the demonstration, printing a short report to stdout.
///
/// # Errors
/// Fails only if minting a sample artifact cannot be serialized.
pub fn run(common: &CommonArgs) -> anyhow::Result<()> {
    let seed = common.signer_seed;
    let signer = local_signer(seed);

    // A separate key acts as the credential issuer; the node trusts its DID.
    let vc_key = local_signer(seed.wrapping_add(1));
    let vc_issuer = Did::from_verifying_key(&vc_key.verifying_key());
    let subject = Did::from_verifying_key(&local_signer(seed.wrapping_add(2)).verifying_key());

    let policy = TrustPolicy::permissive()
        .with_trusted_issuer(&common.issuer)
        .with_trusted_issuer(vc_issuer.as_str())
        .with_audience("edge-api")
        .with_leeway(60);

    let verifier = EdgeVerifier::new(
        Arc::new(StaticJwksProvider::new(local_jwks(seed))),
        Arc::new(SystemClock),
        Arc::new(NoopAuditSink),
        policy,
    );
    let now = verifier.now_unix();

    println!("EdgeAuth demo — verifying with local key `{LOCAL_KID}`\n");

    // 1. A well-formed, in-date, correctly-addressed JWT.
    let valid = mint_jwt(&signer, &common.issuer, "edge-api", now - 60, now + 3600)?;
    print_outcome("valid JWT", &verifier.verify_jwt(&valid, None));

    // 2. An expired JWT.
    let expired = mint_jwt(&signer, &common.issuer, "edge-api", now - 7200, now - 3600)?;
    print_outcome("expired JWT", &verifier.verify_jwt(&expired, None));

    // 3. A JWT from an untrusted issuer.
    let untrusted = mint_jwt(
        &signer,
        "https://evil.example",
        "edge-api",
        now - 60,
        now + 3600,
    )?;
    print_outcome(
        "untrusted-issuer JWT",
        &verifier.verify_jwt(&untrusted, None),
    );

    // 4. A JWT for the wrong audience.
    let wrong_aud = mint_jwt(&signer, &common.issuer, "other-api", now - 60, now + 3600)?;
    print_outcome("wrong-audience JWT", &verifier.verify_jwt(&wrong_aud, None));

    // 5. A properly signed Verifiable Credential.
    let mut vc = build_credential(&vc_issuer, &subject, now);
    vc.sign_with(&vc_key, now)
        .map_err(|e| anyhow::anyhow!("signing credential: {e}"))?;
    let vc_json = serde_json::to_string(&vc)?;
    let outcome = verifier
        .verify_credential_json(&vc_json, None)
        .map_err(|e| anyhow::anyhow!("verifying credential: {e}"))?;
    print_outcome("signed credential", &outcome);

    // 6. A tampered credential (claim mutated after signing).
    let mut tampered = vc.clone();
    tampered
        .subject
        .claims
        .insert("kyc_level".to_string(), "platinum".to_string());
    let tampered_json = serde_json::to_string(&tampered)?;
    let outcome = verifier
        .verify_credential_json(&tampered_json, None)
        .map_err(|e| anyhow::anyhow!("verifying tampered credential: {e}"))?;
    print_outcome("tampered credential", &outcome);

    let stats = verifier.stats();
    println!(
        "\nstats: jwt accepted={} rejected={} | vc accepted={} rejected={}",
        stats.jwt_accepted, stats.jwt_rejected, stats.vc_accepted, stats.vc_rejected
    );
    Ok(())
}

fn mint_jwt(
    signer: &SigningKey,
    issuer: &str,
    audience: &str,
    nbf: i64,
    exp: i64,
) -> anyhow::Result<String> {
    let header = JwtHeader {
        alg: JWT_ALG.to_string(),
        typ: Some("JWT".to_string()),
        kid: Some(LOCAL_KID.to_string()),
    };
    let claims = JwtClaims {
        iss: Some(issuer.to_string()),
        sub: Some("user-demo".to_string()),
        aud: Some(Audience::Single(audience.to_string())),
        exp: Some(exp),
        nbf: Some(nbf),
        iat: Some(nbf),
        jti: Some(format!("jti-{nbf}")),
        scope: Some("openid profile".to_string()),
        roles: vec!["reader".to_string()],
    };
    encode_jwt(&header, &claims, signer).map_err(|e| anyhow::anyhow!("encoding JWT: {e}"))
}

fn build_credential(issuer: &Did, subject: &Did, now: i64) -> VerifiableCredential {
    let mut claims = BTreeMap::new();
    claims.insert("kyc_level".to_string(), "gold".to_string());
    VerifiableCredential {
        id: "urn:cred:demo-1".to_string(),
        credential_type: "KycVerified".to_string(),
        issuer: issuer.clone(),
        subject: CredentialSubject {
            id: subject.clone(),
            claims,
        },
        issued_at: now - 3600,
        expires_at: Some(now + 86_400),
        proof: None,
    }
}

fn print_outcome(label: &str, outcome: &VerificationOutcome) {
    let verdict = if outcome.valid { "ACCEPT" } else { "REJECT" };
    let reason = outcome.reason.as_deref().unwrap_or("-");
    let subject = outcome.subject.as_deref().unwrap_or("-");
    println!("  [{verdict}] {label:<22} subject={subject} reason={reason}");
}
