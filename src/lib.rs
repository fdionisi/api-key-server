use std::sync::Arc;

use axum::{
    async_trait,
    extract::{Path, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use axum_auth_provider::{auth_middleware, AuthProvider, Token};
use uuid::Uuid;

pub struct ApiKeyServer {
    auth_provider: Arc<dyn AuthProvider>,
    storage_adapter: Arc<dyn StorageAdapter>,
    secret_generator: Arc<dyn SecretGenerator>,
}

pub struct ApiKeyServerBuilder {
    auth_provider: Option<Arc<dyn AuthProvider>>,
    storage_adapter: Option<Arc<dyn StorageAdapter>>,
    secret_generator: Option<Arc<dyn SecretGenerator>>,
}

impl ApiKeyServer {
    pub fn builder() -> ApiKeyServerBuilder {
        ApiKeyServerBuilder {
            auth_provider: None,
            storage_adapter: None,
            secret_generator: None,
        }
    }

    pub fn router(self) -> Router {
        let app_state = AppState {
            storage_adapter: self.storage_adapter,
            secret_generator: self.secret_generator,
        };

        Router::new()
            .route("/keys", post(create_key))
            .route("/keys", get(list_keys))
            .route("/keys/:id", delete(delete_key))
            .route("/keys/:id", post(regenerate_key))
            .route("/lookup", post(lookup_key))
            .with_state(app_state)
            .layer(middleware::from_fn_with_state(
                self.auth_provider,
                auth_middleware,
            ))
            .route("/healthz", get(healthz))
    }
}

impl ApiKeyServerBuilder {
    pub fn with_auth_provider(mut self, auth_provider: Arc<dyn AuthProvider>) -> Self {
        self.auth_provider = Some(auth_provider);
        self
    }

    pub fn with_storage_adapter(mut self, storage_adapter: Arc<dyn StorageAdapter>) -> Self {
        self.storage_adapter = Some(storage_adapter);
        self
    }

    pub fn with_secret_generator(mut self, secret_generator: Arc<dyn SecretGenerator>) -> Self {
        self.secret_generator = Some(secret_generator);
        self
    }

    pub fn build(self) -> Result<ApiKeyServer, Box<dyn std::error::Error>> {
        Ok(ApiKeyServer {
            auth_provider: self
                .auth_provider
                .ok_or_else(|| "Auth provider not provided".to_string())?,
            storage_adapter: self
                .storage_adapter
                .ok_or_else(|| "Storage not provided".to_string())?,
            secret_generator: self
                .secret_generator
                .ok_or_else(|| "Secret generator not provided".to_string())?,
        })
    }
}

#[async_trait]
pub trait StorageAdapter: Send + Sync {
    async fn create_key(&self, user_id: &str, key: ApiKey) -> Result<(), StorageError>;
    async fn list_keys(&self, user_id: &str) -> Result<Vec<ApiKey>, StorageError>;
    async fn delete_key(&self, user_id: &str, key_id: Uuid) -> Result<(), StorageError>;
    async fn update_key(&self, user_id: &str, key: ApiKey) -> Result<(), StorageError>;
    async fn lookup_key(&self, user_id: &str, secret: &str)
        -> Result<Option<ApiKey>, StorageError>;
}

#[derive(Debug)]
pub enum StorageError {
    NotFound,
    InternalError(String),
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

#[async_trait]
pub trait SecretGenerator: Send + Sync {
    async fn generate(&self) -> String;
}

#[derive(Clone)]
struct AppState {
    storage_adapter: Arc<dyn StorageAdapter>,
    secret_generator: Arc<dyn SecretGenerator>,
}

async fn create_key(
    State(app_state): State<AppState>,
    token_data: Token,
    Json(key): Json<InputApiKey>,
) -> impl IntoResponse {
    let api_key = ApiKey {
        id: Uuid::new_v4(),
        name: key.name.clone(),
        secret: app_state.secret_generator.generate().await,
    };

    match app_state
        .storage_adapter
        .create_key(&token_data.claims.sub, api_key.clone())
        .await
    {
        Ok(_) => Json(api_key).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create key: {:?}", e),
        )
            .into_response(),
    }
}

async fn list_keys(State(app_state): State<AppState>, token_data: Token) -> impl IntoResponse {
    match app_state
        .storage_adapter
        .list_keys(&token_data.claims.sub)
        .await
    {
        Ok(user_keys) => Json(
            user_keys
                .iter()
                .map(|key| ProtectedApiKey {
                    id: key.id,
                    name: key.name.clone(),
                })
                .collect::<Vec<ProtectedApiKey>>(),
        )
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to list keys: {:?}", e),
        )
            .into_response(),
    }
}

async fn delete_key(
    State(app_state): State<AppState>,
    token_data: Token,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match app_state
        .storage_adapter
        .delete_key(&token_data.claims.sub, id)
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(StorageError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to delete key: {:?}", e),
        )
            .into_response(),
    }
}

async fn regenerate_key(
    State(app_state): State<AppState>,
    token_data: Token,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match app_state
        .storage_adapter
        .list_keys(&token_data.claims.sub)
        .await
    {
        Ok(mut user_keys) => {
            if let Some(key) = user_keys.iter_mut().find(|key| key.id == id) {
                let mut updated_key = key.clone();
                updated_key.secret = app_state.secret_generator.generate().await;
                match app_state
                    .storage_adapter
                    .update_key(&token_data.claims.sub, updated_key.clone())
                    .await
                {
                    Ok(_) => Json(updated_key).into_response(),
                    Err(e) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to update key: {:?}", e),
                    )
                        .into_response(),
                }
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }
        Err(StorageError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to regenerate key: {:?}", e),
        )
            .into_response(),
    }
}

async fn lookup_key(
    State(app_state): State<AppState>,
    token_data: Token,
    Json(lookup): Json<LookupSecret>,
) -> impl IntoResponse {
    match app_state
        .storage_adapter
        .lookup_key(&token_data.claims.sub, &lookup.secret)
        .await
    {
        Ok(Some(key)) => Json(ProtectedApiKey {
            id: key.id,
            name: key.name,
        })
        .into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to lookup key: {:?}", e),
        )
            .into_response(),
    }
}

async fn healthz() -> impl IntoResponse {
    axum::http::StatusCode::OK
}

pub fn router(
    auth_provider: Arc<dyn AuthProvider>,
    storage_adapter: Arc<dyn StorageAdapter>,
    secret_generator: Arc<dyn SecretGenerator>,
) -> Router {
    let app_state = AppState {
        storage_adapter,
        secret_generator,
    };

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

pub mod uuid_secret_generator {
    use std::sync::Arc;

    use axum::async_trait;
    use uuid::Uuid;

    use crate::SecretGenerator;

    pub struct UuidSecretGenerator;

    impl UuidSecretGenerator {
        pub fn new() -> Arc<Self> {
            Arc::new(Self)
        }
    }

    #[async_trait]
    impl SecretGenerator for UuidSecretGenerator {
        async fn generate(&self) -> String {
            Uuid::new_v4().to_string()
        }
    }
}

pub mod in_memory_storage {
    use std::{collections::HashMap, sync::Arc};

    use axum::async_trait;
    use tokio::sync::Mutex;
    use uuid::Uuid;

    use crate::{ApiKey, StorageAdapter, StorageError};

    pub struct InMemoryStorage {
        keys: Arc<Mutex<HashMap<String, Vec<ApiKey>>>>,
    }

    impl InMemoryStorage {
        pub fn new() -> Arc<Self> {
            Arc::new(InMemoryStorage {
                keys: Arc::new(Mutex::new(HashMap::new())),
            })
        }
    }

    #[async_trait]
    impl StorageAdapter for InMemoryStorage {
        async fn create_key(&self, user_id: &str, key: ApiKey) -> Result<(), StorageError> {
            let mut keys = self.keys.lock().await;
            keys.entry(user_id.to_string())
                .or_insert_with(Vec::new)
                .push(key);
            Ok(())
        }

        async fn list_keys(&self, user_id: &str) -> Result<Vec<ApiKey>, StorageError> {
            let keys = self.keys.lock().await;
            Ok(keys.get(user_id).cloned().unwrap_or_default())
        }

        async fn delete_key(&self, user_id: &str, key_id: Uuid) -> Result<(), StorageError> {
            let mut keys = self.keys.lock().await;
            if let Some(user_keys) = keys.get_mut(user_id) {
                if let Some(index) = user_keys.iter().position(|key| key.id == key_id) {
                    user_keys.remove(index);
                    Ok(())
                } else {
                    Err(StorageError::NotFound)
                }
            } else {
                Err(StorageError::NotFound)
            }
        }

        async fn update_key(&self, user_id: &str, key: ApiKey) -> Result<(), StorageError> {
            let mut keys = self.keys.lock().await;
            if let Some(user_keys) = keys.get_mut(user_id) {
                if let Some(existing_key) = user_keys.iter_mut().find(|k| k.id == key.id) {
                    *existing_key = key;
                    Ok(())
                } else {
                    Err(StorageError::NotFound)
                }
            } else {
                Err(StorageError::NotFound)
            }
        }

        async fn lookup_key(
            &self,
            user_id: &str,
            secret: &str,
        ) -> Result<Option<ApiKey>, StorageError> {
            let keys = self.keys.lock().await;
            Ok(keys
                .get(user_id)
                .and_then(|user_keys| user_keys.iter().find(|key| key.secret == secret))
                .cloned())
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::async_trait;
    use axum_auth_provider::{AuthError, Claims};
    use axum_test::{TestResponse, TestServer};
    use in_memory_storage::InMemoryStorage;
    use jsonwebtoken::{jwk::JwkSet, TokenData};
    use uuid_secret_generator::UuidSecretGenerator;

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
                server: TestServer::new(router(
                    TestAuthProvider::new(),
                    InMemoryStorage::new(),
                    UuidSecretGenerator::new(),
                ))
                .unwrap(),
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
