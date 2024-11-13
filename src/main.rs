use std::sync::Arc;

use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use tokio::sync::Mutex;
use uuid::Uuid;

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

#[derive(Clone, Default)]
struct AppState {
    keys: Arc<Mutex<Vec<ApiKey>>>,
}

async fn create_key(
    State(app_state): State<AppState>,
    Json(key): Json<InputApiKey>,
) -> impl IntoResponse {
    let mut keys = app_state.keys.lock().await;

    let api_key = ApiKey {
        id: Uuid::new_v4(),
        name: key.name.clone(),
        secret: Uuid::new_v4().to_string(),
    };

    keys.push(api_key.clone());

    Json(api_key).into_response()
}

async fn list_keys(State(app_state): State<AppState>) -> impl IntoResponse {
    let keys = app_state.keys.lock().await;

    Json(
        keys.iter()
            .map(|key| ProtectedApiKey {
                id: key.id.clone(),
                name: key.name.clone(),
            })
            .collect::<Vec<ProtectedApiKey>>(),
    )
    .into_response()
}

async fn delete_key(State(app_state): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    let mut keys = app_state.keys.lock().await;

    let key_index = keys.iter().position(|key| key.id == id);

    if let Some(index) = key_index {
        let _ = keys.remove(index);
        axum::http::StatusCode::NO_CONTENT.into_response()
    } else {
        axum::http::StatusCode::NOT_FOUND.into_response()
    }
}

#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app()).await.unwrap();
}

fn app() -> Router {
    let app_state = AppState::default();

    Router::new()
        .route("/keys", post(create_key))
        .route("/keys", get(list_keys))
        .route("/keys/:id", delete(delete_key))
        .with_state(app_state)
}

#[cfg(test)]
mod tests {
    use axum_test::{TestResponse, TestServer};

    use super::*;

    struct TestClient {
        server: TestServer,
    }

    impl TestClient {
        fn new() -> Self {
            Self {
                server: TestServer::new(app()).unwrap(),
            }
        }

        async fn create_key(&self, key: InputApiKey) -> TestResponse {
            self.server
                .post("/keys")
                .json(&serde_json::to_value(key).unwrap())
                .await
        }

        async fn list_keys(&self) -> TestResponse {
            self.server.get("/keys").await
        }

        async fn delete_key(&self, id: Uuid) -> TestResponse {
            self.server.delete(&format!("/keys/{}", id)).await
        }
    }

    #[tokio::test]
    async fn test_create_key() {
        let api_key_name = String::from("my api key");
        let client = TestClient::new();
        let response = client
            .create_key(InputApiKey {
                name: api_key_name.clone(),
            })
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
            .create_key(InputApiKey {
                name: api_key_name.clone(),
            })
            .await;

        let api_key_name = String::from("my api key 2");
        client
            .create_key(InputApiKey {
                name: api_key_name.clone(),
            })
            .await;

        let response = client.list_keys().await;

        assert_eq!(response.status_code(), 200);
        assert_eq!(response.json::<Vec<ProtectedApiKey>>().len(), 2);
    }

    #[tokio::test]
    async fn test_delete_key() {
        let client = TestClient::new();

        let api_key_name = String::from("my api key");
        let response = client
            .create_key(InputApiKey {
                name: api_key_name.clone(),
            })
            .await;
        let id = response.json::<ApiKey>().id;

        let delete_response = client.delete_key(id).await;
        assert_eq!(delete_response.status_code(), 204);

        let list_response = client.list_keys().await;
        assert_eq!(list_response.json::<Vec<ProtectedApiKey>>().len(), 0);
    }
}
