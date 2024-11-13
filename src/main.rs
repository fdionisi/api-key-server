use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::post, Json, Router};
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

#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app()).await.unwrap();
}

fn app() -> Router {
    let app_state = AppState::default();

    Router::new()
        .route("/keys", post(create_key))
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
}
