.PHONY: dev backend frontend install

dev:
	$(MAKE) -j2 backend frontend

backend: check-compose
	docker compose up -d db s3
	DATABASE_URL=postgres://nigrani:nigrani@localhost:5432/nigrani \
	JWT_SECRET=dev-secret-change-me-change-me!! \
	BIND_ADDR=127.0.0.1:8080 \
	S3_ENDPOINT=http://localhost:4566 \
	S3_BUCKET=nigrani-snapshots \
	AWS_REGION=us-east-1 \
	AWS_ACCESS_KEY_ID=nigrani \
	AWS_SECRET_ACCESS_KEY=nigrani-secret-key \
	cargo run --manifest-path backend/Cargo.toml

check-compose:
	@command -v docker >/dev/null || { echo "docker not installed"; exit 1; }

frontend:
	npm --prefix frontend run dev

install:
	cargo fetch --manifest-path backend/Cargo.toml
	npm --prefix frontend install
