//! # `edgeauth-wasm`
//!
//! Thin WebAssembly bindings over [`edgeauth_verifier`], designed for edge
//! runtimes (Cloudflare Workers, Fastly, `wasm32-wasi` hosts). The verification
//! core is already synchronous, allocation-light and free of I/O, so the edge
//! adapter is deliberately tiny: parse the caller-supplied inputs, run the
//! verifier, and hand back the outcome as a JSON string.
//!
//! The JWKS and trust policy are passed **in** by the host on every call — the
//! module keeps no state, so a fresh (cold) instance is immediately usable and
//! there is no key material embedded in the artifact.
//!
//! ## JavaScript usage
//!
//! ```js
//! import init, { verify_jwt, verify_credential } from "./edgeauth_wasm.js";
//! await init();
//! const outcome = JSON.parse(verify_jwt(token, jwksJson, policyJson, Date.now() / 1000));
//! if (outcome.valid) { /* admit request */ }
//! ```

#![forbid(unsafe_code)]

use edgeauth_types::{Jwks, TokenKind, TrustPolicy, VerificationOutcome};
use edgeauth_verifier::{verify_credential_json, verify_jwt as core_verify_jwt};
use wasm_bindgen::prelude::wasm_bindgen;

/// Installs a panic hook that forwards Rust panics to the host console.
///
/// Invoked automatically when the module is instantiated.
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// Serializes an outcome to JSON, falling back to a hand-written rejection if
/// serialization itself ever fails (it cannot, in practice).
fn to_json(outcome: &VerificationOutcome) -> String {
    serde_json::to_string(outcome).unwrap_or_else(|_| {
        r#"{"valid":false,"reason":"internal serialization error"}"#.to_string()
    })
}

/// Parses the trust policy, tolerating an empty string as the permissive policy.
fn parse_policy(policy_json: &str) -> Result<TrustPolicy, String> {
    if policy_json.trim().is_empty() {
        return Ok(TrustPolicy::permissive());
    }
    serde_json::from_str(policy_json).map_err(|e| format!("invalid trust policy JSON: {e}"))
}

/// Verifies a compact EdDSA JWT at the edge.
///
/// * `token` — the compact JWS.
/// * `jwks_json` — the trusted JSON Web Key Set, as JSON.
/// * `policy_json` — the [`TrustPolicy`] as JSON (empty string = permissive).
/// * `now_secs` — the current time in Unix seconds (e.g. `Date.now() / 1000`).
///
/// Returns a JSON-encoded [`VerificationOutcome`]; malformed inputs yield an
/// invalid outcome rather than throwing.
#[wasm_bindgen]
pub fn verify_jwt(token: &str, jwks_json: &str, policy_json: &str, now_secs: f64) -> String {
    let policy = match parse_policy(policy_json) {
        Ok(p) => p,
        Err(e) => return to_json(&VerificationOutcome::rejected(TokenKind::Jwt, e)),
    };
    let jwks = match Jwks::from_json(jwks_json) {
        Ok(j) => j,
        Err(e) => {
            return to_json(&VerificationOutcome::rejected(
                TokenKind::Jwt,
                format!("invalid JWKS JSON: {e}"),
            ))
        }
    };
    let outcome = core_verify_jwt(token, &jwks, &policy, now_secs as i64);
    to_json(&outcome)
}

/// Verifies a `did:key` Verifiable Credential at the edge.
///
/// * `credential_json` — the credential document as JSON.
/// * `policy_json` — the [`TrustPolicy`] as JSON (empty string = permissive).
/// * `now_secs` — the current time in Unix seconds.
///
/// Returns a JSON-encoded [`VerificationOutcome`].
#[wasm_bindgen]
pub fn verify_credential(credential_json: &str, policy_json: &str, now_secs: f64) -> String {
    let policy = match parse_policy(policy_json) {
        Ok(p) => p,
        Err(e) => {
            return to_json(&VerificationOutcome::rejected(
                TokenKind::VerifiableCredential,
                e,
            ))
        }
    };
    match verify_credential_json(credential_json, &policy, now_secs as i64) {
        Ok(outcome) => to_json(&outcome),
        Err(e) => to_json(&VerificationOutcome::rejected(
            TokenKind::VerifiableCredential,
            e.to_string(),
        )),
    }
}

/// The semantic version of the edge module, for host-side compatibility checks.
#[wasm_bindgen]
#[must_use]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use edgeauth_types::{encode_jwt, Audience, Jwk, JwtClaims, JwtHeader, JWT_ALG};

    fn token_and_jwks() -> (String, String) {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let header = JwtHeader {
            alg: JWT_ALG.to_string(),
            typ: Some("JWT".to_string()),
            kid: Some("k1".to_string()),
        };
        let claims = JwtClaims {
            iss: Some("https://issuer.example".to_string()),
            sub: Some("user-1".to_string()),
            aud: Some(Audience::Single("edge-api".to_string())),
            exp: Some(4_000_000_000),
            nbf: Some(1_000),
            iat: Some(1_000),
            jti: Some("tok-1".to_string()),
            scope: Some("openid".to_string()),
            roles: vec![],
        };
        let token = encode_jwt(&header, &claims, &sk).unwrap();
        let jwks = Jwks::from_keys([Jwk::from_verifying_key(&sk.verifying_key(), "k1")]);
        (token, serde_json::to_string(&jwks).unwrap())
    }

    #[test]
    fn verify_jwt_returns_valid_outcome_json() {
        let (token, jwks) = token_and_jwks();
        let out = verify_jwt(&token, &jwks, "", 2_000_000_000.0);
        let parsed: VerificationOutcome = serde_json::from_str(&out).unwrap();
        assert!(parsed.valid);
        assert_eq!(parsed.subject.as_deref(), Some("user-1"));
    }

    #[test]
    fn verify_jwt_with_policy_enforces_audience() {
        let (token, jwks) = token_and_jwks();
        let policy = r#"{"expected_audience":"different"}"#;
        let out = verify_jwt(&token, &jwks, policy, 2_000_000_000.0);
        let parsed: VerificationOutcome = serde_json::from_str(&out).unwrap();
        assert!(!parsed.valid);
        assert!(!parsed.checks.audience);
    }

    #[test]
    fn invalid_jwks_json_yields_rejection_not_panic() {
        let (token, _) = token_and_jwks();
        let out = verify_jwt(&token, "{not-json", "", 2_000_000_000.0);
        let parsed: VerificationOutcome = serde_json::from_str(&out).unwrap();
        assert!(!parsed.valid);
        assert!(parsed.reason.unwrap().contains("invalid JWKS"));
    }

    #[test]
    fn invalid_policy_json_yields_rejection() {
        let (token, jwks) = token_and_jwks();
        let out = verify_jwt(&token, &jwks, "{bad", 2_000_000_000.0);
        let parsed: VerificationOutcome = serde_json::from_str(&out).unwrap();
        assert!(!parsed.valid);
        assert!(parsed.reason.unwrap().contains("invalid trust policy"));
    }

    #[test]
    fn version_is_reported() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
    }
}
