//! # `edgeauth-verifier`
//!
//! The stateless verification engine at the heart of EdgeAuth. Given a trusted
//! [`Jwks`] / issuer set and a [`TrustPolicy`], it decides whether an EdDSA
//! [`SignedJwt`] or a [`VerifiableCredential`] is acceptable — reporting every
//! individual check so callers get the full picture, not just the first error.
//!
//! Everything here is **synchronous, allocation-light and side-effect free**:
//! the caller supplies the current time (`now`, Unix seconds), so the engine
//! holds no clock and performs no I/O. That is what lets the same code run in a
//! Cloudflare Worker (`wasm32`) and in the native `axum` server unchanged.
//!
//! ```
//! use edgeauth_types::{Jwks, TrustPolicy};
//! use edgeauth_verifier::verify_jwt;
//!
//! # fn demo(token: &str, jwks: &Jwks) {
//! let policy = TrustPolicy::permissive()
//!     .with_trusted_issuer("https://issuer.example")
//!     .with_audience("edge-api")
//!     .with_leeway(30);
//! let outcome = verify_jwt(token, jwks, &policy, 1_700_000_000);
//! if outcome.valid {
//!     println!("subject = {:?}", outcome.subject);
//! }
//! # }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use edgeauth_types::{
    Jwks, SignedJwt, TokenKind, TrustPolicy, VerifiableCredential, VerificationChecks,
    VerificationOutcome, VerifyError,
};

/// Returns a human-readable reason for the first failing check, if any.
fn first_failure(checks: &VerificationChecks) -> Option<&'static str> {
    if !checks.signature {
        Some("signature verification failed")
    } else if !checks.issuer_trusted {
        Some("issuer is not trusted")
    } else if !checks.not_before {
        Some("artifact is not yet valid (nbf)")
    } else if !checks.not_expired {
        Some("artifact has expired (exp)")
    } else if !checks.audience {
        Some("audience mismatch (aud)")
    } else if !checks.scopes {
        Some("required scope missing")
    } else if !checks.not_revoked {
        Some("artifact has been revoked")
    } else {
        None
    }
}

/// Verifies a compact EdDSA JWT against a trusted key set and policy.
///
/// The signature is checked first; if it fails (bad signature, unknown `kid`,
/// non-`EdDSA` algorithm or malformed token) the token is rejected outright and
/// no claim is trusted. Otherwise every policy check is evaluated and reported.
///
/// `now` is the current time in Unix seconds, supplied by the caller.
#[must_use]
pub fn verify_jwt(token: &str, jwks: &Jwks, policy: &TrustPolicy, now: i64) -> VerificationOutcome {
    let signed = match SignedJwt::parse(token) {
        Ok(s) => s,
        Err(e) => return VerificationOutcome::rejected(TokenKind::Jwt, e.to_string()),
    };
    if let Err(e) = signed.verify_with(jwks) {
        return VerificationOutcome::rejected(TokenKind::Jwt, e.to_string());
    }

    let claims = &signed.claims;
    let leeway = policy.leeway_secs;
    let scopes = claims.scopes();

    let checks = VerificationChecks {
        signature: true,
        not_expired: claims.exp.is_none_or(|exp| now - leeway < exp),
        not_before: claims.nbf.is_none_or(|nbf| now + leeway >= nbf),
        issuer_trusted: policy.issuer_trusted(claims.iss.as_deref()),
        audience: match &policy.expected_audience {
            None => true,
            Some(expected) => claims.aud.as_ref().is_some_and(|a| a.contains(expected)),
        },
        scopes: policy.required_scopes.is_subset(&scopes),
        not_revoked: claims
            .jti
            .as_ref()
            .is_none_or(|jti| !policy.revoked_jti.contains(jti)),
    };

    VerificationOutcome {
        valid: checks.all(),
        kind: TokenKind::Jwt,
        subject: claims.sub.clone(),
        issuer: claims.iss.clone(),
        scopes: scopes.into_iter().collect(),
        roles: claims.roles.clone(),
        reason: first_failure(&checks).map(str::to_owned),
        checks,
    }
}

/// Verifies a `did:key` Verifiable Credential against a trust policy.
///
/// The issuer's key is recovered directly from its `did:key`, so no network
/// resolution occurs. Audience and scope checks do not apply to credentials and
/// are reported as vacuously satisfied; revocation is checked against the
/// credential id.
///
/// `now` is the current time in Unix seconds, supplied by the caller.
#[must_use]
pub fn verify_credential(
    vc: &VerifiableCredential,
    policy: &TrustPolicy,
    now: i64,
) -> VerificationOutcome {
    if let Err(e) = vc.verify_signature() {
        return VerificationOutcome::rejected(TokenKind::VerifiableCredential, e.to_string());
    }

    let (not_before, not_expired) = vc.validity_at(now, policy.leeway_secs);
    let checks = VerificationChecks {
        signature: true,
        not_expired,
        not_before,
        issuer_trusted: policy.issuer_trusted(Some(vc.issuer.as_str())),
        audience: true,
        scopes: true,
        not_revoked: !policy.revoked_jti.contains(&vc.id),
    };

    VerificationOutcome {
        valid: checks.all(),
        kind: TokenKind::VerifiableCredential,
        subject: Some(vc.subject.id.to_string()),
        issuer: Some(vc.issuer.to_string()),
        scopes: Vec::new(),
        roles: Vec::new(),
        reason: first_failure(&checks).map(str::to_owned),
        checks,
    }
}

/// Parses a JSON-encoded Verifiable Credential and verifies it.
///
/// A convenience for the WASM and GraphQL adapters, which receive credentials
/// as JSON strings.
///
/// # Errors
/// Returns [`VerifyError::Json`] if the document is not a valid credential. A
/// *cryptographic* failure is reported as an invalid [`VerificationOutcome`],
/// not an error.
pub fn verify_credential_json(
    json: &str,
    policy: &TrustPolicy,
    now: i64,
) -> Result<VerificationOutcome, VerifyError> {
    let vc: VerifiableCredential =
        serde_json::from_str(json).map_err(|e| VerifyError::Json(e.to_string()))?;
    Ok(verify_credential(&vc, policy, now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use edgeauth_types::{
        credential::CredentialSubject, encode_jwt, Audience, Did, Jwk, JwtClaims, JwtHeader,
        JWT_ALG,
    };
    use std::collections::BTreeMap;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn jwks_for(sk: &SigningKey, kid: &str) -> Jwks {
        Jwks::from_keys([Jwk::from_verifying_key(&sk.verifying_key(), kid)])
    }

    fn base_claims() -> JwtClaims {
        JwtClaims {
            iss: Some("https://issuer.example".to_string()),
            sub: Some("user-1".to_string()),
            aud: Some(Audience::Single("edge-api".to_string())),
            exp: Some(2_000),
            nbf: Some(1_000),
            iat: Some(1_000),
            jti: Some("tok-1".to_string()),
            scope: Some("openid documents:read".to_string()),
            roles: vec!["editor".to_string()],
        }
    }

    fn mint(sk: &SigningKey, kid: &str, claims: &JwtClaims) -> String {
        let header = JwtHeader {
            alg: JWT_ALG.to_string(),
            typ: Some("JWT".to_string()),
            kid: Some(kid.to_string()),
        };
        encode_jwt(&header, claims, sk).unwrap()
    }

    #[test]
    fn valid_jwt_passes_all_checks() {
        let sk = signing_key(1);
        let token = mint(&sk, "k1", &base_claims());
        let jwks = jwks_for(&sk, "k1");
        let policy = TrustPolicy::permissive()
            .with_trusted_issuer("https://issuer.example")
            .with_audience("edge-api")
            .requiring_scope("openid")
            .with_leeway(30);

        let out = verify_jwt(&token, &jwks, &policy, 1_500);
        assert!(out.valid, "reason: {:?}", out.reason);
        assert_eq!(out.subject.as_deref(), Some("user-1"));
        assert_eq!(out.issuer.as_deref(), Some("https://issuer.example"));
        assert!(out.scopes.contains(&"openid".to_string()));
        assert!(out.checks.all());
        assert!(out.reason.is_none());
    }

    #[test]
    fn expired_jwt_is_rejected_with_reason() {
        let sk = signing_key(1);
        let token = mint(&sk, "k1", &base_claims());
        let jwks = jwks_for(&sk, "k1");
        let out = verify_jwt(&token, &jwks, &TrustPolicy::permissive(), 5_000);
        assert!(!out.valid);
        assert!(out.checks.signature);
        assert!(!out.checks.not_expired);
        assert_eq!(out.reason.as_deref(), Some("artifact has expired (exp)"));
    }

    #[test]
    fn not_yet_valid_jwt_is_rejected() {
        let sk = signing_key(1);
        let token = mint(&sk, "k1", &base_claims());
        let jwks = jwks_for(&sk, "k1");
        let out = verify_jwt(&token, &jwks, &TrustPolicy::permissive(), 500);
        assert!(!out.valid);
        assert!(!out.checks.not_before);
    }

    #[test]
    fn leeway_admits_small_clock_skew() {
        let sk = signing_key(1);
        let token = mint(&sk, "k1", &base_claims());
        let jwks = jwks_for(&sk, "k1");
        let policy = TrustPolicy::permissive().with_leeway(60);
        // 40s before nbf, but within 60s leeway.
        let out = verify_jwt(&token, &jwks, &policy, 960);
        assert!(out.valid, "reason: {:?}", out.reason);
    }

    #[test]
    fn untrusted_issuer_is_rejected() {
        let sk = signing_key(1);
        let token = mint(&sk, "k1", &base_claims());
        let jwks = jwks_for(&sk, "k1");
        let policy = TrustPolicy::permissive().with_trusted_issuer("https://other.example");
        let out = verify_jwt(&token, &jwks, &policy, 1_500);
        assert!(!out.valid);
        assert!(!out.checks.issuer_trusted);
    }

    #[test]
    fn audience_mismatch_is_rejected() {
        let sk = signing_key(1);
        let token = mint(&sk, "k1", &base_claims());
        let jwks = jwks_for(&sk, "k1");
        let policy = TrustPolicy::permissive().with_audience("different-api");
        let out = verify_jwt(&token, &jwks, &policy, 1_500);
        assert!(!out.valid);
        assert!(!out.checks.audience);
    }

    #[test]
    fn missing_required_scope_is_rejected() {
        let sk = signing_key(1);
        let token = mint(&sk, "k1", &base_claims());
        let jwks = jwks_for(&sk, "k1");
        let policy = TrustPolicy::permissive().requiring_scope("admin:write");
        let out = verify_jwt(&token, &jwks, &policy, 1_500);
        assert!(!out.valid);
        assert!(!out.checks.scopes);
    }

    #[test]
    fn revoked_jti_is_rejected() {
        let sk = signing_key(1);
        let token = mint(&sk, "k1", &base_claims());
        let jwks = jwks_for(&sk, "k1");
        let policy = TrustPolicy::permissive().revoking("tok-1");
        let out = verify_jwt(&token, &jwks, &policy, 1_500);
        assert!(!out.valid);
        assert!(!out.checks.not_revoked);
    }

    #[test]
    fn unknown_kid_is_a_hard_failure() {
        let sk = signing_key(1);
        let token = mint(&sk, "k1", &base_claims());
        let jwks = jwks_for(&sk, "different-kid");
        let out = verify_jwt(&token, &jwks, &TrustPolicy::permissive(), 1_500);
        assert!(!out.valid);
        assert!(!out.checks.signature);
        assert!(out.reason.unwrap().contains("unknown key id"));
    }

    fn signed_credential(issuer_seed: u8, subject_seed: u8) -> VerifiableCredential {
        let issuer_sk = signing_key(issuer_seed);
        let issuer = Did::from_verifying_key(&issuer_sk.verifying_key());
        let subject = Did::from_verifying_key(&signing_key(subject_seed).verifying_key());
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
            expires_at: Some(2_000),
            proof: None,
        };
        vc.sign_with(&issuer_sk, 1_000).unwrap();
        vc
    }

    #[test]
    fn valid_credential_passes() {
        let vc = signed_credential(1, 2);
        let policy = TrustPolicy::permissive().with_trusted_issuer(vc.issuer.as_str());
        let out = verify_credential(&vc, &policy, 1_500);
        assert!(out.valid, "reason: {:?}", out.reason);
        assert_eq!(out.kind, TokenKind::VerifiableCredential);
        assert_eq!(out.subject, Some(vc.subject.id.to_string()));
    }

    #[test]
    fn untrusted_credential_issuer_is_rejected() {
        let vc = signed_credential(1, 2);
        let policy = TrustPolicy::permissive().with_trusted_issuer("did:key:zSomeOtherIssuer");
        let out = verify_credential(&vc, &policy, 1_500);
        assert!(!out.valid);
        assert!(out.checks.signature);
        assert!(!out.checks.issuer_trusted);
    }

    #[test]
    fn expired_credential_is_rejected() {
        let vc = signed_credential(1, 2);
        let policy = TrustPolicy::permissive();
        let out = verify_credential(&vc, &policy, 9_000);
        assert!(!out.valid);
        assert!(!out.checks.not_expired);
    }

    #[test]
    fn revoked_credential_is_rejected() {
        let vc = signed_credential(1, 2);
        let policy = TrustPolicy::permissive().revoking("cred-1");
        let out = verify_credential(&vc, &policy, 1_500);
        assert!(!out.valid);
        assert!(!out.checks.not_revoked);
    }

    #[test]
    fn tampered_credential_is_a_hard_failure() {
        let mut vc = signed_credential(1, 2);
        vc.subject
            .claims
            .insert("kyc".to_string(), "forged".to_string());
        let out = verify_credential(&vc, &TrustPolicy::permissive(), 1_500);
        assert!(!out.valid);
        assert!(!out.checks.signature);
    }

    #[test]
    fn verify_credential_json_round_trips() {
        let vc = signed_credential(1, 2);
        let json = serde_json::to_string(&vc).unwrap();
        let policy = TrustPolicy::permissive();
        let out = verify_credential_json(&json, &policy, 1_500).unwrap();
        assert!(out.valid, "reason: {:?}", out.reason);
        assert!(verify_credential_json("not json", &policy, 1_500).is_err());
    }

    proptest::proptest! {
        #[test]
        fn garbage_never_verifies_and_never_panics(s in ".{0,256}") {
            let sk = signing_key(1);
            let jwks = jwks_for(&sk, "k1");
            let out = verify_jwt(&s, &jwks, &TrustPolicy::permissive(), 1_500);
            proptest::prop_assert!(!out.valid);
        }
    }
}
