//! Generates ready-to-use demonstration fixtures (a JWT, a signed Verifiable
//! Credential and the credential issuer's DID) signed by the node's
//! deterministic local key, and prints them as JSON.
//!
//! These artifacts are intentionally **not** committed to the repository:
//! embedding a JWT-shaped literal in source or a Postman collection trips
//! secret scanners and is poor hygiene. Instead, run
//! `cargo run -p edgeauth-node -- mint` and paste the output into the Postman
//! collection variables (`jwt`, `credential`, `vcIssuerDid`).

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;

use edgeauth_types::{
    encode_jwt, Audience, CredentialSubject, Did, JwtClaims, JwtHeader, VerifiableCredential,
    JWT_ALG,
};

use crate::config::CommonArgs;
use crate::startup::{local_signer, LOCAL_KID};

/// A fixed "issued at" timestamp (Unix epoch) for reproducible fixtures.
const FIXTURE_IAT: i64 = 0;
/// A fixed "expires at" timestamp: 2100-01-01, so fixtures stay valid.
const FIXTURE_EXP: i64 = 4_102_444_800;

/// Mints and prints the demonstration fixtures as a JSON object whose keys
/// mirror the Postman collection variables.
///
/// # Errors
/// Fails only if an artifact cannot be signed or serialized.
pub fn run(common: &CommonArgs) -> anyhow::Result<()> {
    let seed = common.signer_seed;
    let signer = local_signer(seed);

    // A separate key issues the credential; the node trusts its DID via
    // `EA_TRUSTED_ISSUERS`.
    let vc_key = local_signer(seed.wrapping_add(1));
    let vc_issuer = Did::from_verifying_key(&vc_key.verifying_key());
    let subject = Did::from_verifying_key(&local_signer(seed.wrapping_add(2)).verifying_key());

    let jwt = mint_jwt(&signer, &common.issuer, "edge-api")?;
    let credential = mint_credential(&vc_key, &vc_issuer, &subject)?;

    let fixtures = serde_json::json!({
        "jwt": jwt,
        "vcIssuerDid": vc_issuer.as_str(),
        "credential": credential,
    });
    println!("{}", serde_json::to_string_pretty(&fixtures)?);
    Ok(())
}

fn mint_jwt(signer: &SigningKey, issuer: &str, audience: &str) -> anyhow::Result<String> {
    let header = JwtHeader {
        alg: JWT_ALG.to_string(),
        typ: Some("JWT".to_string()),
        kid: Some(LOCAL_KID.to_string()),
    };
    let claims = JwtClaims {
        iss: Some(issuer.to_string()),
        sub: Some("user-alice".to_string()),
        aud: Some(Audience::Single(audience.to_string())),
        exp: Some(FIXTURE_EXP),
        nbf: Some(FIXTURE_IAT),
        iat: Some(FIXTURE_IAT),
        jti: Some("postman-1".to_string()),
        scope: Some("openid profile".to_string()),
        roles: vec!["reader".to_string()],
    };
    encode_jwt(&header, &claims, signer).map_err(|e| anyhow::anyhow!("encoding JWT: {e}"))
}

fn mint_credential(vc_key: &SigningKey, issuer: &Did, subject: &Did) -> anyhow::Result<String> {
    let mut claims = BTreeMap::new();
    claims.insert("kyc_level".to_string(), "gold".to_string());
    let mut vc = VerifiableCredential {
        id: "urn:cred:postman-1".to_string(),
        credential_type: "KycVerified".to_string(),
        issuer: issuer.clone(),
        subject: CredentialSubject {
            id: subject.clone(),
            claims,
        },
        issued_at: FIXTURE_IAT,
        expires_at: Some(FIXTURE_EXP),
        proof: None,
    };
    vc.sign_with(vc_key, FIXTURE_IAT)
        .map_err(|e| anyhow::anyhow!("signing credential: {e}"))?;
    serde_json::to_string(&vc).map_err(Into::into)
}
