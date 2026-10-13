//! S3/MinIO object storage for gate snapshot captures.
use aws_config::BehaviorVersion;
use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;

use crate::core::{AppError, AppResult};

#[derive(Clone)]
pub struct SnapshotStore {
    client: Client,
    bucket: String,
}

impl SnapshotStore {
    /// Connect from env (`S3_ENDPOINT` etc., dev defaults for compose MinIO)
    /// and create the bucket idempotently.
    pub async fn from_env() -> AppResult<Self> {
        let endpoint = std::env::var("S3_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:9000".into());
        let bucket = std::env::var("S3_BUCKET").unwrap_or_else(|_| "nigrani-snapshots".into());
        let config = aws_config::defaults(BehaviorVersion::latest())
            .endpoint_url(&endpoint)
            .load()
            .await;
        let client = Client::new(&config);
        // Idempotent: ignore AlreadyOwned errors so restarts are clean.
        match client.create_bucket().bucket(&bucket).send().await {
            Ok(_) => tracing::info!(%bucket, "snapshot bucket created"),
            Err(e) => tracing::debug!(%bucket, error = %e, "snapshot bucket exists (or unreachable)"),
        }
        Ok(Self { client, bucket })
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub async fn put_jpeg(&self, key: &str, bytes: Vec<u8>) -> AppResult<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_type("image/jpeg")
            .body(ByteStream::from(bytes))
            .send()
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("snapshot upload failed: {e}")))?;
        Ok(())
    }

    pub async fn get(&self, key: &str) -> AppResult<Vec<u8>> {
        let out = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| AppError::NotFound(format!("snapshot not found: {e}")))?;
        out.body
            .collect()
            .await
            .map(|data| data.to_vec())
            .map_err(|e| AppError::Internal(anyhow::anyhow!("snapshot read failed: {e}")))
    }
}
