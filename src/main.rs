use std::{sync::Arc, time::Duration};

use api_key_server::{
    in_memory_storage::InMemoryStorage, uuid_secret_generator::UuidSecretGenerator, ApiKeyServer,
};
use axum_auth_provider::cached_jwk_set::CachedJwkSet;
use clap::Parser;

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

    let storage_adapter = InMemoryStorage::new();
    let secret_generator = UuidSecretGenerator::new();

    let api_key_server = ApiKeyServer::builder()
        .with_auth_provider(auth_provider)
        .with_secret_generator(secret_generator)
        .with_storage_adapter(storage_adapter)
        .build()?;

    axum::serve(listener, api_key_server.router()).await?;

    Ok(())
}
