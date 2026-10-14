//! S3 object storage for gate snapshot captures.
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
    /// Connect from env (`S3_ENDPOINT` etc., dev defaults for compose LocalStack S3)
    /// and create the bucket idempotently.
    pub async fn from_env() -> AppResult<Self> {
        let endpoint =
            std::env::var("S3_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:4566".into());
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

    /// Presigned GET URL (15 min) so browsers fetch snapshots direct from S3.
    pub async fn share_url(&self, key: &str) -> AppResult<String> {
        use std::time::Duration;
        let cfg = aws_sdk_s3::presigning::PresigningConfig::builder()
            .expires_in(Duration::from_secs(15 * 60))
            .build()
            .map_err(|e| AppError::Internal(anyhow::anyhow!("presign config failed: {e}")))?;
        let req = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .presigned(cfg)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("presign failed: {e}")))?;
        Ok(req.uri().to_owned())
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

    /// Every key in the bucket (paginated ListObjectsV2, 1000/page).
    /// Used by orphan collection; buckets stay small (gate captures only).
    pub async fn list_keys(&self) -> AppResult<Vec<String>> {
        let mut keys = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut req = self.client.list_objects_v2().bucket(&self.bucket).max_keys(1000);
            if let Some(t) = token {
                req = req.continuation_token(t);
            }
            let out = req
                .send()
                .await
                .map_err(|e| AppError::Internal(anyhow::anyhow!("snapshot list failed: {e}")))?;
            for obj in out.contents() {
                if let Some(k) = obj.key() {
                    keys.push(k.to_owned());
                }
            }
            if out.is_truncated().unwrap_or(false) {
                token = out.next_continuation_token().map(str::to_owned);
            } else {
                break;
            }
        }
        Ok(keys)
    }

    /// Batch-delete (DeleteObjects, ≤1000/batch). Missing keys are skipped
    /// by S3; returns the count actually deleted.
    pub async fn delete_keys(&self, keys: &[String]) -> AppResult<i64> {
        use aws_sdk_s3::types::{Delete, ObjectIdentifier};
        let mut deleted = 0i64;
        for chunk in keys.chunks(1000) {
            let mut del = Delete::builder();
            for k in chunk {
                del = del.objects(ObjectIdentifier::builder().key(k).build().map_err(|e| {
                    AppError::Internal(anyhow::anyhow!("snapshot delete ident failed: {e}"))
                })?);
            }
            let out = self
                .client
                .delete_objects()
                .bucket(&self.bucket)
                .delete(del.build().map_err(|e| {
                    AppError::Internal(anyhow::anyhow!("snapshot delete build failed: {e}"))
                })?)
                .send()
                .await
                .map_err(|e| AppError::Internal(anyhow::anyhow!("snapshot delete failed: {e}")))?;
            deleted += out.deleted().len() as i64;
        }
        Ok(deleted)
    }
}
