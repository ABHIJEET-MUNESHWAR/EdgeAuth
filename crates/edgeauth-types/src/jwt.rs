//! Compact EdDSA JSON Web Tokens and JSON Web Key Sets (RFC 7515/7517/8037).
//!
//! EdgeAuth only *verifies*: it parses a compact JWS, checks the JOSE header
//! pins `alg = EdDSA`, resolves the signing key from a trusted [`Jwks`] by
//! `kid`, and validates the Ed25519 signature over the exact signing input.
//! No key generation and no randomness are involved, so this module compiles
//! unchanged to `wasm32-unknown-unknown`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::error::{VerifyError, PUBLIC_KEY_LEN, SIGNATURE_LEN};

/// The only JWS algorithm EdgeAuth accepts (Ed25519, RFC 8037).
pub const JWT_ALG: &str = "EdDSA";
/// JWK key type for an Ed25519 public key (Octet Key Pair).
pub const JWK_KTY: &str = "OKP";
/// JWK curve identifier for Ed25519.
pub const JWK_CRV: &str = "Ed25519";
/// JWK `use` value for a signature-verification key.
pub const JWK_USE_SIG: &str = "sig";

/// Decodes a `base64url` (no padding) segment into raw bytes.
///
/// # Errors
/// Returns [`VerifyError::Base64`] if the input is not valid `base64url`.
pub fn b64url_decode(segment: &str) -> Result<Vec<u8>, VerifyError> {
    URL_SAFE_NO_PAD
        .decode(segment.as_bytes())
        .map_err(|e| VerifyError::Base64(e.to_string()))
}

/// Encodes raw bytes as `base64url` without padding.
#[must_use]
pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The JOSE header of a compact JWS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtHeader {
    /// Signature algorithm; EdgeAuth requires `"EdDSA"`.
    pub alg: String,
    /// Token type, conventionally `"JWT"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// Key identifier selecting the verifying key from the JWKS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// A JWT `aud` claim, which may be a single string or an array (RFC 7519).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    /// A single audience value.
    Single(String),
    /// A list of audience values.
    Multiple(Vec<String>),
}

impl Audience {
    /// Returns `true` if `candidate` is among the audience values.
    #[must_use]
    pub fn contains(&self, candidate: &str) -> bool {
        match self {
            Self::Single(a) => a == candidate,
            Self::Multiple(list) => list.iter().any(|a| a == candidate),
        }
    }

    /// Returns the first audience value, if any.
    #[must_use]
    pub fn primary(&self) -> Option<&str> {
        match self {
            Self::Single(a) => Some(a.as_str()),
            Self::Multiple(list) => list.first().map(String::as_str),
        }
    }
}

/// The registered and EdgeAuth-relevant claims of a JWT.
///
/// Unknown claims are ignored. Every field is optional so tokens minted by
/// heterogeneous issuers still parse; policy decides which claims are required.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Issuer (`iss`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Subject (`sub`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Audience (`aud`) — a string or array of strings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<Audience>,
    /// Expiry, seconds since the Unix epoch (`exp`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Not-before, seconds since the Unix epoch (`nbf`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Issued-at, seconds since the Unix epoch (`iat`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// JWT ID (`jti`), used for revocation checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// OAuth space-delimited scopes (`scope`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Application roles (`roles`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
}

impl JwtClaims {
    /// Parses the space-delimited `scope` claim into a set.
    #[must_use]
    pub fn scopes(&self) -> BTreeSet<String> {
        self.scope
            .as_deref()
            .map(|s| s.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default()
    }
}

/// A single Ed25519 JSON Web Key (RFC 8037, an `OKP`/`Ed25519` key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type; always `"OKP"` for Ed25519.
    pub kty: String,
    /// Curve; always `"Ed25519"`.
    pub crv: String,
    /// The `base64url` public key coordinate.
    pub x: String,
    /// Key identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Intended use, conventionally `"sig"`.
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    /// Algorithm, conventionally `"EdDSA"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

impl Jwk {
    /// Builds a JWK from an Ed25519 verifying key and key id.
    #[must_use]
    pub fn from_verifying_key(key: &VerifyingKey, kid: impl Into<String>) -> Self {
        Self {
            kty: JWK_KTY.to_string(),
            crv: JWK_CRV.to_string(),
            x: b64url_encode(key.as_bytes()),
            kid: Some(kid.into()),
            use_: Some(JWK_USE_SIG.to_string()),
            alg: Some(JWT_ALG.to_string()),
        }
    }

    /// Recovers the Ed25519 verifying key encoded in this JWK.
    ///
    /// # Errors
    /// Returns [`VerifyError::InvalidKey`] if the key type/curve is wrong or the
    /// coordinate is not a valid 32-byte Ed25519 point.
    pub fn verifying_key(&self) -> Result<VerifyingKey, VerifyError> {
        if self.kty != JWK_KTY {
            return Err(VerifyError::InvalidKey(format!("kty={}", self.kty)));
        }
        if self.crv != JWK_CRV {
            return Err(VerifyError::InvalidKey(format!("crv={}", self.crv)));
        }
        let raw = b64url_decode(&self.x)?;
        let arr: [u8; PUBLIC_KEY_LEN] =
            raw.as_slice()
                .try_into()
                .map_err(|_| VerifyError::InvalidKeyLength {
                    expected: PUBLIC_KEY_LEN,
                    got: raw.len(),
                })?;
        VerifyingKey::from_bytes(&arr).map_err(|e| VerifyError::InvalidKey(e.to_string()))
    }
}

/// A set of trusted JSON Web Keys.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwks {
    /// The keys in the set.
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Builds a JWKS from an iterator of keys.
    pub fn from_keys(keys: impl IntoIterator<Item = Jwk>) -> Self {
        Self {
            keys: keys.into_iter().collect(),
        }
    }

    /// Finds a key by `kid`. When `kid` is `None`, returns the sole key iff the
    /// set contains exactly one (a common single-key convenience).
    #[must_use]
    pub fn find(&self, kid: Option<&str>) -> Option<&Jwk> {
        match kid {
            Some(id) => self.keys.iter().find(|k| k.kid.as_deref() == Some(id)),
            None if self.keys.len() == 1 => self.keys.first(),
            None => None,
        }
    }

    /// Parses a JWKS from its JSON representation.
    ///
    /// # Errors
    /// Returns [`VerifyError::Json`] if the document is not a valid JWKS.
    pub fn from_json(json: &str) -> Result<Self, VerifyError> {
        serde_json::from_str(json).map_err(|e| VerifyError::Json(e.to_string()))
    }
}

/// A parsed compact JWS, retaining the exact signing input for verification.
#[derive(Debug, Clone)]
pub struct SignedJwt {
    /// The decoded JOSE header.
    pub header: JwtHeader,
    /// The decoded claim set.
    pub claims: JwtClaims,
    /// The ASCII bytes that were signed: `base64url(header) + "." + base64url(payload)`.
    signing_input: String,
    /// The raw 64-byte Ed25519 signature.
    signature: [u8; SIGNATURE_LEN],
}

impl SignedJwt {
    /// Parses a compact JWS string into its header, claims and signature.
    ///
    /// This does **not** verify the signature; call [`Self::verify_with`].
    ///
    /// # Errors
    /// Returns [`VerifyError::MalformedJwt`], [`VerifyError::Base64`] or
    /// [`VerifyError::Json`] if the token is not a well-formed compact JWS.
    pub fn parse(token: &str) -> Result<Self, VerifyError> {
        let mut parts = token.split('.');
        let (Some(h), Some(p), Some(s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(VerifyError::MalformedJwt(
                "expected exactly three dot-separated segments".to_string(),
            ));
        };

        let header: JwtHeader = serde_json::from_slice(&b64url_decode(h)?)
            .map_err(|e| VerifyError::Json(e.to_string()))?;
        let claims: JwtClaims = serde_json::from_slice(&b64url_decode(p)?)
            .map_err(|e| VerifyError::Json(e.to_string()))?;

        let sig_bytes = b64url_decode(s)?;
        let signature: [u8; SIGNATURE_LEN] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::InvalidSignatureLength(sig_bytes.len()))?;

        Ok(Self {
            header,
            claims,
            signing_input: format!("{h}.{p}"),
            signature,
        })
    }

    /// Verifies the token's Ed25519 signature against a trusted key set.
    /// Pins `alg = EdDSA`, resolves the key by `kid`, and checks the signature
    /// over the original signing input.
    ///
    /// # Errors
    /// Returns [`VerifyError::UnsupportedAlgorithm`], [`VerifyError::UnknownKeyId`],
    /// [`VerifyError::InvalidKey`] or [`VerifyError::SignatureInvalid`].
    pub fn verify_with(&self, jwks: &Jwks) -> Result<(), VerifyError> {
        if self.header.alg != JWT_ALG {
            return Err(VerifyError::UnsupportedAlgorithm(self.header.alg.clone()));
        }
        let jwk = jwks.find(self.header.kid.as_deref()).ok_or_else(|| {
            VerifyError::UnknownKeyId(self.header.kid.clone().unwrap_or_default())
        })?;
        let key = jwk.verifying_key()?;
        let sig = Signature::from_bytes(&self.signature);
        key.verify(self.signing_input.as_bytes(), &sig)
            .map_err(|_| VerifyError::SignatureInvalid)
    }
}

/// Encodes and signs a compact EdDSA JWT.
///
/// EdgeAuth is a verifier; this helper exists for tests, benchmarks and the
/// local demo that need to mint sample tokens. It is pure and `wasm`-safe.
///
/// # Errors
/// Returns [`VerifyError::Json`] if the header or claims cannot be serialized.
pub fn encode_jwt(
    header: &JwtHeader,
    claims: &JwtClaims,
    signing_key: &SigningKey,
) -> Result<String, VerifyError> {
    let h =
        b64url_encode(&serde_json::to_vec(header).map_err(|e| VerifyError::Json(e.to_string()))?);
    let p =
        b64url_encode(&serde_json::to_vec(claims).map_err(|e| VerifyError::Json(e.to_string()))?);
    let signing_input = format!("{h}.{p}");
    let signature = signing_key.sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        b64url_encode(&signature.to_bytes())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn sample_claims() -> JwtClaims {
        JwtClaims {
            iss: Some("https://issuer.example".to_string()),
            sub: Some("user-42".to_string()),
            aud: Some(Audience::Single("edge-api".to_string())),
            exp: Some(2_000),
            nbf: Some(1_000),
            iat: Some(1_000),
            jti: Some("tok-1".to_string()),
            scope: Some("openid documents:read".to_string()),
            roles: vec!["editor".to_string()],
        }
    }

    #[test]
    fn encode_then_parse_and_verify_round_trip() {
        let sk = signing_key(5);
        let header = JwtHeader {
            alg: JWT_ALG.to_string(),
            typ: Some("JWT".to_string()),
            kid: Some("key-1".to_string()),
        };
        let token = encode_jwt(&header, &sample_claims(), &sk).unwrap();
        let jwks = Jwks::from_keys([Jwk::from_verifying_key(&sk.verifying_key(), "key-1")]);

        let parsed = SignedJwt::parse(&token).unwrap();
        assert_eq!(parsed.claims.sub.as_deref(), Some("user-42"));
        assert!(parsed.verify_with(&jwks).is_ok());
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let sk = signing_key(5);
        let header = JwtHeader {
            alg: JWT_ALG.to_string(),
            typ: None,
            kid: Some("key-1".to_string()),
        };
        let token = encode_jwt(&header, &sample_claims(), &sk).unwrap();
        let jwks = Jwks::from_keys([Jwk::from_verifying_key(&sk.verifying_key(), "key-1")]);

        // Flip a character in the payload segment.
        let mut parts: Vec<&str> = token.split('.').collect();
        let mutated = format!("{}x", parts[1]);
        parts[1] = &mutated;
        let bad = parts.join(".");
        // Either parse fails (bad base64/json) or the signature check fails.
        let rejected = match SignedJwt::parse(&bad) {
            Ok(j) => j.verify_with(&jwks).is_err(),
            Err(_) => true,
        };
        assert!(rejected);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let sk = signing_key(5);
        let header = JwtHeader {
            alg: JWT_ALG.to_string(),
            typ: None,
            kid: Some("key-1".to_string()),
        };
        let token = encode_jwt(&header, &sample_claims(), &sk).unwrap();
        let other = Jwks::from_keys([Jwk::from_verifying_key(
            &signing_key(6).verifying_key(),
            "key-1",
        )]);
        let parsed = SignedJwt::parse(&token).unwrap();
        assert_eq!(
            parsed.verify_with(&other),
            Err(VerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn non_eddsa_algorithm_is_rejected() {
        let sk = signing_key(5);
        let header = JwtHeader {
            alg: "HS256".to_string(),
            typ: None,
            kid: Some("key-1".to_string()),
        };
        let token = encode_jwt(&header, &sample_claims(), &sk).unwrap();
        let jwks = Jwks::from_keys([Jwk::from_verifying_key(&sk.verifying_key(), "key-1")]);
        let parsed = SignedJwt::parse(&token).unwrap();
        assert!(matches!(
            parsed.verify_with(&jwks),
            Err(VerifyError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn malformed_token_shapes_are_rejected() {
        assert!(SignedJwt::parse("only.two").is_err());
        assert!(SignedJwt::parse("a.b.c.d").is_err());
        assert!(SignedJwt::parse("!!!.@@@.###").is_err());
    }

    #[test]
    fn audience_matching_handles_single_and_multiple() {
        let single = Audience::Single("a".to_string());
        assert!(single.contains("a"));
        assert!(!single.contains("b"));
        let multi = Audience::Multiple(vec!["a".to_string(), "b".to_string()]);
        assert!(multi.contains("b"));
        assert_eq!(multi.primary(), Some("a"));
    }

    #[test]
    fn scopes_parse_from_space_delimited_claim() {
        let claims = sample_claims();
        let scopes = claims.scopes();
        assert!(scopes.contains("openid"));
        assert!(scopes.contains("documents:read"));
        assert_eq!(scopes.len(), 2);
    }
}
