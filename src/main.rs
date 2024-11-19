use std::{collections::HashMap, sync::Arc, time::Duration};

use axum::{
    extract::{Path, State},
    middleware,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use axum_auth_provider::{auth_middleware, cached_jwk_set::CachedJwkSet, AuthProvider, Token};
use clap::Parser;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(clap::Parser)]
pub struct Cli {
    #[clap(long, default_value = "0.0.0.0")]
    host: String,
    #[clap(long, default_value = "3000")]
    post: u16,
    #[clap(long)]
    audience: String,
    #[clap(long)]
    issuer_base_url: String,
    #[clap(long, default_value = "86400")]
    jwk_set_cache_duration: u64,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct InputApiKey {
    pub name: String,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct ApiKey {
    pub id: Uuid,
    pub name: String,
    pub secret: String,
}

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct ProtectedApiKey {
    pub id: Uuid,
    pub name: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct LookupSecret {
    pub secret: String,
}

#[derive(Clone, Default)]
struct AppState {
    keys: Arc<Mutex<HashMap<String, Vec<ApiKey>>>>,
}

async fn create_key(
    State(app_state): State<AppState>,
    token_data: Token,
    Json(key): Json<InputApiKey>,
) -> impl IntoResponse {
    let mut keys = app_state.keys.lock().await;

    let api_key = ApiKey {
        id: Uuid::new_v4(),
        name: key.name.clone(),
        secret: Uuid::new_v4().to_string(),
    };

    keys.entry(token_data.claims.sub.clone())
        .or_insert_with(Vec::new)
        .push(api_key.clone());

    Json(api_key).into_response()
}

async fn list_keys(State(app_state): State<AppState>, token_data: Token) -> impl IntoResponse {
    let mut keys = app_state.keys.lock().await;

    let user_keys = keys
        .entry(token_data.claims.sub.clone())
        .or_insert(Vec::new());

    Json(
        user_keys
            .iter()
            .map(|key| ProtectedApiKey {
                id: key.id.clone(),
                name: key.name.clone(),
            })
            .collect::<Vec<ProtectedApiKey>>(),
    )
    .into_response()
}

async fn delete_key(
    State(app_state): State<AppState>,
    token_data: Token,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let mut keys = app_state.keys.lock().await;

    if let Some(user_keys) = keys.get_mut(&token_data.claims.sub) {
        let key_index = user_keys.iter().position(|key| key.id == id);

        if let Some(index) = key_index {
            let _ = user_keys.remove(index);
            axum::http::StatusCode::NO_CONTENT.into_response()
        } else {
            axum::http::StatusCode::NOT_FOUND.into_response()
        }
    } else {
        axum::http::StatusCode::NOT_FOUND.into_response()
    }
}

async fn regenerate_key(
    State(app_state): State<AppState>,
    token_data: Token,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let mut keys = app_state.keys.lock().await;

    if let Some(user_keys) = keys.get_mut(&token_data.claims.sub) {
        if let Some(key) = user_keys.iter_mut().find(|key| key.id == id) {
            key.secret = Uuid::new_v4().to_string();
            Json(key.clone()).into_response()
        } else {
            axum::http::StatusCode::NOT_FOUND.into_response()
        }
    } else {
        axum::http::StatusCode::NOT_FOUND.into_response()
    }
}

async fn lookup_key(
    State(app_state): State<AppState>,
    token_data: Token,
    Json(lookup): Json<LookupSecret>,
) -> impl IntoResponse {
    let keys = app_state.keys.lock().await;

    if let Some(user_keys) = keys.get(&token_data.claims.sub) {
        if let Some(key) = user_keys.iter().find(|key| key.secret == lookup.secret) {
            Json(ProtectedApiKey {
                id: key.id,
                name: key.name.clone(),
            })
            .into_response()
        } else {
            axum::http::StatusCode::NOT_FOUND.into_response()
        }
    } else {
        axum::http::StatusCode::NOT_FOUND.into_response()
    }
}

async fn healthz() -> impl IntoResponse {
    axum::http::StatusCode::OK
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let listener = tokio::net::TcpListener::bind((cli.host, cli.post)).await?;

    let auth_provider = Arc::new(
        CachedJwkSet::builder()
            .issuer(cli.issuer_base_url)
            .duration(Duration::from_secs(cli.jwk_set_cache_duration))
            .validator(Arc::new(move |mut validation| {
                validation.set_audience(&[&cli.audience]);
                validation.to_owned()
            }))
            .build()?,
    );

    axum::serve(listener, app(auth_provider)).await?;

    Ok(())
}

fn app(auth_provider: Arc<dyn AuthProvider + Send + Sync>) -> Router {
    let app_state = AppState::default();

    Router::new()
        .route("/keys", post(create_key))
        .route("/keys", get(list_keys))
        .route("/keys/:id", delete(delete_key))
        .route("/keys/:id", post(regenerate_key))
        .route("/lookup", post(lookup_key))
        .with_state(app_state)
        .layer(middleware::from_fn_with_state(
            auth_provider,
            auth_middleware,
        ))
        .route("/healthz", get(healthz))
}

#[cfg(test)]
mod tests {
    use axum::async_trait;
    use axum_auth_provider::{AuthError, Claims};
    use axum_test::{TestResponse, TestServer};
    use jsonwebtoken::{jwk::JwkSet, TokenData};

    use super::*;

    struct TestAuthProvider;

    impl TestAuthProvider {
        fn new() -> Arc<Self> {
            Arc::new(Self)
        }
    }

    #[async_trait]
    impl AuthProvider for TestAuthProvider {
        async fn jwk_set(&self) -> Result<JwkSet, AuthError> {
            todo!()
        }

        async fn verify(&self, token: &str) -> Result<TokenData<Claims>, AuthError> {
            Ok(TokenData {
                header: Default::default(),
                claims: Claims {
                    sub: token.to_string(),
                    exp: 0,
                },
            })
        }
    }

    struct TestClient {
        server: TestServer,
    }

    impl TestClient {
        fn new() -> Self {
            Self {
                server: TestServer::new(app(TestAuthProvider::new())).unwrap(),
            }
        }

        async fn create_key(&self, key: InputApiKey, token: &str) -> TestResponse {
            self.server
                .post("/keys")
                .json(&serde_json::to_value(key).unwrap())
                .add_header("Authorization", &format!("Bearer {}", token))
                .await
        }

        async fn list_keys(&self, token: &str) -> TestResponse {
            self.server
                .get("/keys")
                .add_header("Authorization", &format!("Bearer {}", token))
                .await
        }

        async fn delete_key(&self, id: Uuid, token: &str) -> TestResponse {
            self.server
                .delete(&format!("/keys/{}", id))
                .add_header("Authorization", &format!("Bearer {}", token))
                .await
        }

        async fn regenerate_key(&self, id: Uuid, token: &str) -> TestResponse {
            self.server
                .post(&format!("/keys/{}", id))
                .add_header("Authorization", &format!("Bearer {}", token))
                .await
        }

        async fn lookup_key(&self, secret: String, token: &str) -> TestResponse {
            self.server
                .post("/lookup")
                .json(&LookupSecret { secret })
                .add_header("Authorization", &format!("Bearer {}", token))
                .await
        }

        async fn healthz(&self) -> TestResponse {
            self.server.get("/healthz").await
        }
    }

    #[tokio::test]
    async fn test_create_key() {
        let api_key_name = String::from("my api key");
        let client = TestClient::new();
        let response = client
            .create_key(
                InputApiKey {
                    name: api_key_name.clone(),
                },
                "test_token",
            )
            .await;

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.json::<ApiKey>().id.to_string().is_empty(), false);
        assert_eq!(response.json::<ApiKey>().name, api_key_name.clone());
        assert_eq!(response.json::<ApiKey>().secret.is_empty(), false);
    }

    #[tokio::test]
    async fn test_list_keys() {
        let client = TestClient::new();

        let api_key_name = String::from("my api key 1");
        client
            .create_key(
                InputApiKey {
                    name: api_key_name.clone(),
                },
                "test_token",
            )
            .await;

        let api_key_name = String::from("my api key 2");
        client
            .create_key(
                InputApiKey {
                    name: api_key_name.clone(),
                },
                "test_token",
            )
            .await;

        let response = client.list_keys("test_token").await;

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.json::<Vec<ProtectedApiKey>>().len(), 2);
    }

    #[tokio::test]
    async fn test_delete_key() {
        let client = TestClient::new();

        let api_key_name = String::from("my api key");
        let response = client
            .create_key(
                InputApiKey {
                    name: api_key_name.clone(),
                },
                "test_token",
            )
            .await;
        let id = response.json::<ApiKey>().id;

        let delete_response = client.delete_key(id, "test_token").await;
        assert_eq!(delete_response.status_code(), 204);

        let list_response = client.list_keys("test_token").await;
        assert_eq!(list_response.json::<Vec<ProtectedApiKey>>().len(), 0);
    }

    #[tokio::test]
    async fn test_regenerate_key() {
        let client = TestClient::new();

        let api_key_name = String::from("my api key");
        let create_response = client
            .create_key(
                InputApiKey {
                    name: api_key_name.clone(),
                },
                "test_token",
            )
            .await;
        let original_key = create_response.json::<ApiKey>();

        let regenerate_response = client.regenerate_key(original_key.id, "test_token").await;
        assert_eq!(regenerate_response.status_code(), 200);

        let regenerated_key = regenerate_response.json::<ApiKey>();
        assert_eq!(regenerated_key.id, original_key.id);
        assert_eq!(regenerated_key.name, original_key.name);
        assert_ne!(regenerated_key.secret, original_key.secret);
    }

    #[tokio::test]
    async fn test_successful_lookup_key() {
        let client = TestClient::new();

        let api_key_name = String::from("my api key");
        let create_response = client
            .create_key(
                InputApiKey {
                    name: api_key_name.clone(),
                },
                "test_token",
            )
            .await;
        let created_key = create_response.json::<ApiKey>();

        let lookup_response = client.lookup_key(created_key.secret, "test_token").await;
        assert_eq!(lookup_response.status_code(), 200);

        let looked_up_key = lookup_response.json::<ProtectedApiKey>();
        assert_eq!(looked_up_key.id, created_key.id);
        assert_eq!(looked_up_key.name, created_key.name);
    }

    #[tokio::test]
    async fn test_invalid_lookup_key() {
        let client = TestClient::new();

        let invalid_lookup_response = client
            .lookup_key("invalid_secret".to_string(), "test_token")
            .await;
        assert_eq!(invalid_lookup_response.status_code(), 404);
    }

    #[tokio::test]
    async fn test_healthz() {
        let client = TestClient::new();
        let response = client.healthz().await;
        assert_eq!(response.status_code(), 200);
    }

    #[tokio::test]
    async fn test_different_tokens_access_different_keys() {
        let client = TestClient::new();

        let user1_key = client
            .create_key(
                InputApiKey {
                    name: "user1_key".to_string(),
                },
                "user1_token",
            )
            .await
            .json::<ApiKey>();

        let user2_key = client
            .create_key(
                InputApiKey {
                    name: "user2_key".to_string(),
                },
                "user2_token",
            )
            .await
            .json::<ApiKey>();

        let user1_keys = client
            .list_keys("user1_token")
            .await
            .json::<Vec<ProtectedApiKey>>();
        assert_eq!(user1_keys.len(), 1);
        assert_eq!(user1_keys[0].id, user1_key.id);

        let user2_keys = client
            .list_keys("user2_token")
            .await
            .json::<Vec<ProtectedApiKey>>();
        assert_eq!(user2_keys.len(), 1);
        assert_eq!(user2_keys[0].id, user2_key.id);

        let delete_response = client.delete_key(user2_key.id, "user1_token").await;
        assert_eq!(delete_response.status_code(), 404);

        let regenerate_response = client.regenerate_key(user1_key.id, "user2_token").await;
        assert_eq!(regenerate_response.status_code(), 404);

        let lookup_response = client.lookup_key(user2_key.secret, "user1_token").await;
        assert_eq!(lookup_response.status_code(), 404);
    }
}
