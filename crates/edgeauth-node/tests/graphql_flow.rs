//! End-to-end GraphQL tests driving the real schema and service wiring.
//!
//! These execute operations directly against the `async-graphql` schema (no
//! socket needed), exercising the full path: resolver -> `EdgeVerifier` ->
//! pure verifier -> outcome projection.

use async_graphql::{Request, Variables};
use serde_json::{json, Value};

use edgeauth_node::config::CommonArgs;
use edgeauth_node::startup::{build_state, local_signer, LOCAL_KID};
use edgeauth_types::{encode_jwt, Audience, JwtClaims, JwtHeader, JWT_ALG};

const SEED: u8 = 7;
const ISSUER: &str = "https://issuer.local";
const AUDIENCE: &str = "edge-api";

fn common() -> CommonArgs {
    CommonArgs {
        signer_seed: SEED,
        issuer: ISSUER.to_string(),
        trusted_issuers: Vec::new(),
        audience: Some(AUDIENCE.to_string()),
        leeway_secs: 60,
        jwks_url: None,
        jwks_refresh_secs: 300,
    }
}

fn now() -> i64 {
    #[allow(clippy::cast_possible_wrap)]
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn mint(issuer: &str, audience: &str, nbf: i64, exp: i64) -> String {
    let header = JwtHeader {
        alg: JWT_ALG.to_string(),
        typ: Some("JWT".to_string()),
        kid: Some(LOCAL_KID.to_string()),
    };
    let claims = JwtClaims {
        iss: Some(issuer.to_string()),
        sub: Some("user-1".to_string()),
        aud: Some(Audience::Single(audience.to_string())),
        exp: Some(exp),
        nbf: Some(nbf),
        iat: Some(nbf),
        jti: Some("jti-1".to_string()),
        scope: Some("openid".to_string()),
        roles: vec!["reader".to_string()],
    };
    encode_jwt(&header, &claims, &local_signer(SEED)).expect("mint jwt")
}

async fn data_of(schema: &edgeauth_api::EdgeAuthSchema, query: &str, vars: Value) -> Value {
    let req = Request::new(query).variables(Variables::from_json(vars));
    let resp = schema.execute(req).await;
    assert!(resp.errors.is_empty(), "graphql errors: {:?}", resp.errors);
    serde_json::to_value(&resp.data).expect("serialize data")
}

#[tokio::test]
async fn verifies_a_valid_jwt_and_updates_stats() {
    let state = build_state(&common(), 1000).expect("state");
    let schema = edgeauth_api::build_schema(state);
    let n = now();
    let token = mint(ISSUER, AUDIENCE, n - 60, n + 3600);

    let data = data_of(
        &schema,
        r"mutation($t: String!) {
            verifyJwt(token: $t) {
                valid kind subject issuer
                checks { signature notExpired issuerTrusted audience notRevoked }
            }
        }",
        json!({ "t": token }),
    )
    .await;

    let v = &data["verifyJwt"];
    assert_eq!(v["valid"], json!(true));
    assert_eq!(v["kind"], json!("JWT"));
    assert_eq!(v["subject"], json!("user-1"));
    assert_eq!(v["issuer"], json!(ISSUER));
    assert_eq!(v["checks"]["signature"], json!(true));
    assert_eq!(v["checks"]["notExpired"], json!(true));
    assert_eq!(v["checks"]["issuerTrusted"], json!(true));
    assert_eq!(v["checks"]["audience"], json!(true));

    let stats = data_of(&schema, r"{ stats { jwtAccepted jwtRejected } }", json!({})).await;
    assert_eq!(stats["stats"]["jwtAccepted"], json!(1));
    assert_eq!(stats["stats"]["jwtRejected"], json!(0));
}

#[tokio::test]
async fn rejects_an_expired_jwt_with_a_reason() {
    let state = build_state(&common(), 1000).expect("state");
    let schema = edgeauth_api::build_schema(state);
    let n = now();
    let token = mint(ISSUER, AUDIENCE, n - 7200, n - 3600);

    let data = data_of(
        &schema,
        r"mutation($t: String!) {
            verifyJwt(token: $t) { valid reason checks { notExpired } }
        }",
        json!({ "t": token }),
    )
    .await;

    let v = &data["verifyJwt"];
    assert_eq!(v["valid"], json!(false));
    assert_eq!(v["checks"]["notExpired"], json!(false));
    assert!(v["reason"].as_str().unwrap_or_default().contains("exp"));
}

#[tokio::test]
async fn rejects_an_untrusted_issuer() {
    let state = build_state(&common(), 1000).expect("state");
    let schema = edgeauth_api::build_schema(state);
    let n = now();
    let token = mint("https://evil.example", AUDIENCE, n - 60, n + 3600);

    let data = data_of(
        &schema,
        r"mutation($t: String!) {
            verifyJwt(token: $t) { valid checks { issuerTrusted signature } }
        }",
        json!({ "t": token }),
    )
    .await;

    let v = &data["verifyJwt"];
    assert_eq!(v["valid"], json!(false));
    assert_eq!(v["checks"]["signature"], json!(true));
    assert_eq!(v["checks"]["issuerTrusted"], json!(false));
}

#[tokio::test]
async fn health_and_version_queries_resolve() {
    let state = build_state(&common(), 1000).expect("state");
    let schema = edgeauth_api::build_schema(state);

    let data = data_of(
        &schema,
        r"{ health apiVersion trustPolicy { trustedIssuers expectedAudience leewaySecs } jwks { keys { kty crv kid } } }",
        json!({}),
    )
    .await;

    assert_eq!(data["health"], json!(true));
    assert_eq!(data["apiVersion"], json!(env!("CARGO_PKG_VERSION")));
    assert_eq!(data["trustPolicy"]["expectedAudience"], json!(AUDIENCE));
    assert_eq!(data["trustPolicy"]["leewaySecs"], json!(60));
    assert_eq!(data["trustPolicy"]["trustedIssuers"], json!([ISSUER]));
    assert_eq!(data["jwks"]["keys"][0]["kty"], json!("OKP"));
    assert_eq!(data["jwks"]["keys"][0]["crv"], json!("Ed25519"));
    assert_eq!(data["jwks"]["keys"][0]["kid"], json!(LOCAL_KID));
}
