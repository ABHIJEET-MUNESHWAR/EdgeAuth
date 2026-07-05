//! GraphQL API surface for the EdgeAuth verification service.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod schema;
pub mod state;

pub use schema::{build_schema, EdgeAuthSchema};
pub use state::ServiceState;

use async_graphql::http::{playground_source, GraphQLPlaygroundConfig};
use async_graphql_axum::{GraphQL, GraphQLSubscription};
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Router;

async fn playground() -> impl IntoResponse {
    Html(playground_source(
        GraphQLPlaygroundConfig::new("/graphql").subscription_endpoint("/graphql/ws"),
    ))
}

/// Builds the axum router exposing the GraphQL endpoint, an interactive
/// playground and a websocket subscription endpoint.
pub fn router(schema: EdgeAuthSchema) -> Router {
    Router::new()
        .route(
            "/graphql",
            get(playground).post_service(GraphQL::new(schema.clone())),
        )
        .route_service("/graphql/ws", GraphQLSubscription::new(schema))
}
