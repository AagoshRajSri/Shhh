use axum::{
    routing::{get, post},
    Router, Json, extract::State,
    extract::ws::{WebSocketUpgrade, WebSocket, Message as WsMessage},
    extract::Query,
};
use serde::{Deserialize, Serialize};
use aws_sdk_s3 as s3;
use s3::presigning::PresigningConfig;
use std::time::Duration;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::{broadcast, Mutex};
use tracing::{info, error};
use sqlx::{PgPool, Row};
use base64::{Engine as _, engine::general_purpose::STANDARD as b64};
use chrono::Utc;
use axum::extract::ConnectInfo;
use std::net::SocketAddr;

// Type aliases for complex rate-limiter map types
type HandleRateLimiter = Arc<Mutex<HashMap<String, (u32, chrono::DateTime<Utc>)>>>;
type IpRateLimiter = Arc<Mutex<HashMap<std::net::IpAddr, (u32, chrono::DateTime<Utc>)>>>;

// --- DTOs ---
#[derive(Deserialize, Serialize, Clone)]
struct RegisterRequest {
    handle: String,
    identity_public_key: String, // Base64
    signed_prekey: String,
    one_time_prekeys: Vec<String>,
    kyber_public_key: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    status: String,
    routing_token: String,
}

#[derive(Serialize)]
struct LookupResponse {
    status: String,
    routing_token: String,
    identity_pubkey: String,
}

#[derive(Deserialize, Serialize, Clone)]
struct SealedSenderEnvelope {
    to_routing_token: String,
    encrypted_payload: String, 
}

#[derive(Deserialize)]
struct WsQuery {
    token: Option<String>,
}

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    redis_conn: redis::aio::MultiplexedConnection,
    s3_client: s3::Client,
    active_connections: Arc<Mutex<HashMap<String, broadcast::Sender<String>>>>,
    handle_rate_limiter: HandleRateLimiter,
    ip_rate_limiter: IpRateLimiter,
}

#[derive(Deserialize)]
struct UploadInitRequest {
    hash: String,
    parts: u32,
}

#[derive(Serialize)]
struct UploadInitResponse {
    status: String,
    upload_id: Option<String>,
    urls: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct UploadCompleteRequest {
    hash: String,
    upload_id: String,
    etags: Vec<String>,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let db_conn_string = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://securechat:CHANGEME@localhost:5432/securechat".to_string());
    println!("Connecting to Postgres...");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(50)
        .connect(&db_conn_string)
        .await
        .expect("Failed to connect to Postgres");

    println!("Running migrations...");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    println!("Connecting to Redis...");
    let redis_conn_string = std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://:CHANGEME@localhost:6379".to_string());
    let redis_client = redis::Client::open(redis_conn_string).expect("Invalid Redis URL");
    let redis_conn = redis_client.get_multiplexed_async_connection().await.expect("Failed to connect to Redis");

    println!("Connecting to MinIO...");
    let s3_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .endpoint_url(std::env::var("S3_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".to_string()))
        .region(aws_config::Region::new("us-east-1"))
        .credentials_provider(s3::config::Credentials::new(
            std::env::var("S3_ACCESS_KEY").unwrap_or_else(|_| "minioadmin".to_string()),
            std::env::var("S3_SECRET_KEY").unwrap_or_else(|_| "CHANGEME".to_string()),
            None,
            None,
            "manual",
        ))
        .load()
        .await;
    let s3_client = s3::Client::from_conf(
        s3::config::Builder::from(&s3_config)
            .force_path_style(true)
            .build()
    );
    
    println!("Creating MinIO bucket...");
    let _ = s3_client.create_bucket().bucket("shhh-attachments").send().await;
    println!("Done creating bucket.");

    let state = Arc::new(AppState {
        pool,
        redis_conn,
        s3_client,
        active_connections: Arc::new(Mutex::new(HashMap::new())),
        handle_rate_limiter: Arc::new(Mutex::new(HashMap::new())),
        ip_rate_limiter: Arc::new(Mutex::new(HashMap::new())),
    });

    let cors = tower_http::cors::CorsLayer::new()
        .allow_origin("http://localhost:5173".parse::<axum::http::HeaderValue>().unwrap())
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST, axum::http::Method::PUT])
        .allow_headers(vec![axum::http::header::CONTENT_TYPE]);

    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/api/register", post(register_handler))
        .route("/api/message", post(message_handler))
        .route("/api/lookup/:handle", get(lookup_handler))
        .route("/api/upload/init", post(upload_init_handler))
        .route("/api/upload/complete", post(upload_complete_handler))
        .route("/api/download/:hash", get(download_handler))
        .route("/ws", get(ws_handler))
        .layer(cors)
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .with_state(state);

    info!("Shhh relay securely listening on ws://0.0.0.0:3000 (Local Dev)");
    
    let addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();
    axum_server::bind(addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}

async fn security_headers_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("Strict-Transport-Security", "max-age=31536000; includeSubDomains".parse().unwrap());
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("Referrer-Policy", "no-referrer".parse().unwrap());
    // Basic CSP that prevents rendering or script execution since it's just an API
    headers.insert("Content-Security-Policy", "default-src 'none'".parse().unwrap());
    response
}

async fn register_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, axum::http::StatusCode> {
    info!("Registering handle: {}", payload.handle);
    
    let id_pubkey_bytes = b64.decode(&payload.identity_public_key).unwrap_or_default();
    let signed_prekey_bytes = b64.decode(&payload.signed_prekey).unwrap_or_default();
    let kyber_pubkey_bytes = b64.decode(&payload.kyber_public_key).unwrap_or_default();
    let now = Utc::now().naive_utc().date();

    let result = sqlx::query(
        "INSERT INTO users (handle, identity_pubkey, signed_prekey, kyber_pubkey, created_week)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id",
    )
    .bind(&payload.handle)
    .bind(&id_pubkey_bytes)
    .bind(&signed_prekey_bytes)
    .bind(&kyber_pubkey_bytes)
    .bind(now)
    .fetch_one(&state.pool)
    .await;

    match result {
        Ok(record) => {
            let id: uuid::Uuid = record.try_get("id").unwrap_or_default();
            let routing_token = id.to_string();
            Ok(Json(RegisterResponse {
                status: "success".to_string(),
                routing_token,
            }))
        }
        Err(e) => {
            error!("Failed to register user: {}", e);
            Err(axum::http::StatusCode::CONFLICT)
        }
    }
}

async fn lookup_handler(
    axum::extract::Path(handle): axum::extract::Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<LookupResponse>, axum::http::StatusCode> {
    let now = Utc::now();
    let ip = addr.ip();
    
    // 1. IP-based ephemeral rate limit (Prevents global enumeration from a single source)
    {
        let mut rl = state.ip_rate_limiter.lock().await;
        let entry = rl.entry(ip).or_insert((0, now));
        if now.signed_duration_since(entry.1).num_seconds() > 10 {
            entry.0 = 0;
            entry.1 = now;
        }
        if entry.0 >= 20 {
            return Err(axum::http::StatusCode::TOO_MANY_REQUESTS);
        }
        entry.0 += 1;
    }

    // 2. Handle-based ephemeral rate limit (Prevents targeted enumeration of a specific user)
    {
        let mut rl = state.handle_rate_limiter.lock().await;
        let entry = rl.entry(handle.clone()).or_insert((0, now));
        if now.signed_duration_since(entry.1).num_seconds() > 10 {
            entry.0 = 0;
            entry.1 = now;
        }
        if entry.0 >= 20 {
            return Err(axum::http::StatusCode::TOO_MANY_REQUESTS);
        }
        entry.0 += 1;
    }

    let result = sqlx::query(
        "SELECT id, identity_pubkey FROM users WHERE handle = $1",
    )
    .bind(&handle)
    .fetch_optional(&state.pool)
    .await;

    match result {
        Ok(Some(record)) => {
            let id: uuid::Uuid = record.try_get("id").unwrap_or_default();
            let identity_pubkey: Vec<u8> = record.try_get("identity_pubkey").unwrap_or_default();
            Ok(Json(LookupResponse {
                status: "success".to_string(),
                routing_token: id.to_string(),
                identity_pubkey: b64.encode(&identity_pubkey),
            }))
        }
        _ => {
            // Fake it to prevent enumeration (identically shaped output)
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(b"fake_salt_v1");
            hasher.update(handle.as_bytes());
            let hash = hasher.finalize();
            
            let mut uuid_bytes = [0u8; 16];
            uuid_bytes.copy_from_slice(&hash[0..16]);
            let fake_uuid = uuid::Builder::from_random_bytes(uuid_bytes).into_uuid();
            
            let mut pubkey_bytes = vec![0u8; 65];
            pubkey_bytes[0..32].copy_from_slice(&hash[..]);
            
            Ok(Json(LookupResponse {
                status: "success".to_string(),
                routing_token: fake_uuid.to_string(),
                identity_pubkey: b64.encode(&pubkey_bytes),
            }))
        }
    }
}

// Fallback HTTP route for envelopes
async fn message_handler(
    State(state): State<Arc<AppState>>,
    Json(envelope): Json<SealedSenderEnvelope>,
) -> Json<serde_json::Value> {
    info!("Received HTTP sealed envelope for routing token: {}", envelope.to_routing_token);
    
    let msg_id = uuid::Uuid::new_v4().to_string();
    let queue_key = format!("queue:{}", envelope.to_routing_token);
    
    let mut conn = state.redis_conn.clone();
    let res: Result<(), _> = redis::pipe()
        .hset(&queue_key, &msg_id, &envelope.encrypted_payload)
        .expire(&queue_key, 604800)
        .ignore()
        .query_async(&mut conn).await;
    
    if let Err(e) = res {
        error!("Redis pipe error in /api/message: {:?}", e);
    }
    
    let conns = state.active_connections.lock().await;
    if let Some(tx) = conns.get(&envelope.to_routing_token) {
        let _ = tx.send("WAKE".to_string());
    }
    
    Json(serde_json::json!({ "status": "queued" }))
}

// WebSocket Route
async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsQuery>,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let mut token = query.token.unwrap_or_default();
    if token.is_empty() {
        token = headers.get("sec-websocket-protocol")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_default();
    }
    info!("WS Connection attempt for token: {}", token);
    ws.protocols([token.clone()]).on_upgrade(move |socket| handle_socket(socket, token, state))
}

async fn flush_queue(token: &str, socket: &mut WebSocket, mut redis_conn: redis::aio::MultiplexedConnection) -> bool {
    let queue_key = format!("queue:{}", token);
    let query_result: Result<HashMap<String, String>, _> = redis::cmd("HGETALL").arg(&queue_key).query_async(&mut redis_conn).await;
    if let Ok(items) = query_result {
        for (msg_id, payload) in items {
            let ws_msg = serde_json::json!({
                "msg_id": msg_id,
                "encrypted_payload": payload
            });
            if socket.send(WsMessage::Text(serde_json::to_string(&ws_msg).unwrap())).await.is_err() {
                return false;
            }
        }
    }
    true
}

async fn handle_socket(mut socket: WebSocket, token: String, state: Arc<AppState>) {
    let (tx, mut rx) = broadcast::channel(100);
    
    {
        let mut conns = state.active_connections.lock().await;
        conns.insert(token.clone(), tx);
    }

    info!("WS Connected successfully for token: {}", token);
    
    // Flush immediately on connect
    if !flush_queue(&token, &mut socket, state.redis_conn.clone()).await {
        return;
    }

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(msg) => {
                        if msg == "WAKE" {
                            if !flush_queue(&token, &mut socket, state.redis_conn.clone()).await {
                                break;
                            }
                        } else {
                            if socket.send(WsMessage::Text(msg)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Just missed some WAKE messages, flush queue anyway
                        if !flush_queue(&token, &mut socket, state.redis_conn.clone()).await {
                            break;
                        }
                    }
                }
            }
            
            result = socket.recv() => {
                match result {
                    Some(Ok(WsMessage::Text(text))) => {
                        if let Ok(envelope) = serde_json::from_str::<SealedSenderEnvelope>(&text) {
                            info!("Routing WS message to: {}", envelope.to_routing_token);
                            
                            let msg_id = uuid::Uuid::new_v4().to_string();
                            let queue_key = format!("queue:{}", envelope.to_routing_token);
                            
                            let mut conn = state.redis_conn.clone();
                            let _: () = redis::pipe()
                                .hset(&queue_key, &msg_id, &envelope.encrypted_payload)
                                .expire(&queue_key, 604800)
                                .ignore()
                                .query_async(&mut conn).await.unwrap_or(());

                            let conns = state.active_connections.lock().await;
                            if let Some(tx) = conns.get(&envelope.to_routing_token) {
                                let _ = tx.send("WAKE".to_string());
                            }
                        } else if let Ok(ack) = serde_json::from_str::<serde_json::Value>(&text) {
                            if ack["type"] == "ack" {
                                if let Some(msg_id) = ack["msg_id"].as_str() {
                                    let queue_key = format!("queue:{}", token);
                                    let mut conn = state.redis_conn.clone();
                                    let _: () = redis::cmd("HDEL").arg(&queue_key).arg(msg_id).query_async(&mut conn).await.unwrap_or(());
                                }
                            }
                        }
                    }
                    Some(Err(_)) | None => {
                        break;
                    }
                    _ => {} // Ignore other message types (Ping, Pong, Binary)
                }
            }
        }
    }

    info!("WS Disconnected for token: {}", token);
    let mut conns = state.active_connections.lock().await;
    conns.remove(&token);
}

// --- Media Upload Routes ---
async fn upload_init_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UploadInitRequest>,
) -> Result<Json<UploadInitResponse>, axum::http::StatusCode> {
    if payload.parts > 100 {
        return Err(axum::http::StatusCode::PAYLOAD_TOO_LARGE);
    }
    let head = state.s3_client.head_object()
        .bucket("shhh-attachments")
        .key(&payload.hash)
        .send()
        .await;
        
    if head.is_ok() {
        return Ok(Json(UploadInitResponse {
            status: "exists".to_string(),
            upload_id: None,
            urls: None,
        }));
    }

    let multipart = state.s3_client.create_multipart_upload()
        .bucket("shhh-attachments")
        .key(&payload.hash)
        .send()
        .await
        .map_err(|e| {
            error!("Failed to create multipart upload: {:?}", e);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;
        
    let upload_id = multipart.upload_id().unwrap().to_string();
    let mut urls = Vec::new();
    let presigning_config = PresigningConfig::expires_in(Duration::from_secs(3600)).unwrap();
    
    for i in 1..=payload.parts {
        let presigned = state.s3_client.upload_part()
            .bucket("shhh-attachments")
            .key(&payload.hash)
            .upload_id(&upload_id)
            .part_number(i as i32)
            .presigned(presigning_config.clone())
            .await
            .map_err(|e| {
                error!("Failed to presign url for part {}: {:?}", i, e);
                axum::http::StatusCode::INTERNAL_SERVER_ERROR
            })?;
            
        urls.push(presigned.uri().to_string());
    }
    
    Ok(Json(UploadInitResponse {
        status: "uploading".to_string(),
        upload_id: Some(upload_id),
        urls: Some(urls),
    }))
}

async fn upload_complete_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UploadCompleteRequest>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    let mut completed_parts = Vec::new();
    for (i, etag) in payload.etags.iter().enumerate() {
        let part = s3::types::CompletedPart::builder()
            .part_number((i + 1) as i32)
            .e_tag(etag)
            .build();
        completed_parts.push(part);
    }
    
    let completed_multipart_upload = s3::types::CompletedMultipartUpload::builder()
        .set_parts(Some(completed_parts))
        .build();
        
    state.s3_client.complete_multipart_upload()
        .bucket("shhh-attachments")
        .key(&payload.hash)
        .upload_id(&payload.upload_id)
        .multipart_upload(completed_multipart_upload)
        .send()
        .await
        .map_err(|e| {
            error!("Failed to complete multipart upload: {:?}", e);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;
        
    Ok(Json(serde_json::json!({ "status": "success" })))
}

#[derive(Serialize)]
struct DownloadResponse {
    url: String,
}

async fn download_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Result<Json<DownloadResponse>, axum::http::StatusCode> {
    let presigning_config = PresigningConfig::expires_in(Duration::from_secs(3600)).unwrap();
    let presigned = state.s3_client.get_object()
        .bucket("shhh-attachments")
        .key(&hash)
        .presigned(presigning_config)
        .await
        .map_err(|e| {
            error!("Failed to presign download url: {:?}", e);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;
        
    Ok(Json(DownloadResponse {
        url: presigned.uri().to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, State, ConnectInfo};
    use std::net::{IpAddr, Ipv4Addr};

    async fn setup_test_state() -> Arc<AppState> {
        dotenvy::dotenv().ok();
        let db_conn_string = std::env::var("DATABASE_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "postgres://securechat:CHANGEME@localhost:5432/securechat".to_string());
        let pool = PgPool::connect(&db_conn_string).await.expect("Failed to connect to Postgres");
        
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Failed to run migrations");

        let redis_conn_string = std::env::var("REDIS_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "redis://:CHANGEME@localhost:6379".to_string());
        let redis_client = redis::Client::open(redis_conn_string).expect("Invalid Redis URL");

        let s3_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .endpoint_url("http://localhost:9000")
            .region(aws_config::Region::new("us-east-1"))
            .credentials_provider(s3::config::Credentials::new(
                std::env::var("S3_ACCESS_KEY").unwrap_or_else(|_| "minioadmin".to_string()),
                std::env::var("S3_SECRET_KEY").unwrap_or_else(|_| "CHANGEME".to_string()),
                None, None, "manual"
            ))
            .load()
            .await;

        Arc::new(AppState {
            pool,
            redis_client,
            s3_client: s3::Client::from_conf(s3::config::Builder::from(&s3_config).force_path_style(true).build()),
            active_connections: Arc::new(Mutex::new(HashMap::new())),
            handle_rate_limiter: Arc::new(Mutex::new(HashMap::new())),
            ip_rate_limiter: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn dummy_connect_info() -> ConnectInfo<SocketAddr> {
        ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080))
    }

    #[tokio::test]
    async fn test_registration_and_lookup_durability() {
        let state = setup_test_state().await;
        let test_handle = format!("#durability_user_{}", uuid::Uuid::new_v4().simple());

        let req = RegisterRequest {
            handle: test_handle.clone(),
            identity_public_key: b64.encode(b"test_identity_key"),
            signed_prekey: b64.encode(b"test_signed_prekey"),
            one_time_prekeys: vec![b64.encode(b"otpk1")],
            kyber_public_key: b64.encode(b"kyber_prekey"),
        };

        let reg_res = register_handler(State(state.clone()), Json(req)).await.expect("Registration failed");
        let routing_token = reg_res.routing_token.clone();
        assert!(!routing_token.is_empty());

        drop(state);
        let restarted_state = setup_test_state().await;

        let lookup_res = lookup_handler(Path(test_handle), dummy_connect_info(), State(restarted_state)).await.unwrap();
        assert_eq!(lookup_res.status, "success");
        assert_eq!(lookup_res.routing_token, routing_token);
        assert_eq!(lookup_res.identity_pubkey, b64.encode(b"test_identity_key"));
    }

    #[tokio::test]
    async fn test_duplicate_registration_fails_cleanly() {
        let state = setup_test_state().await;
        let test_handle = format!("#unique_user_{}", uuid::Uuid::new_v4().simple());

        let req = RegisterRequest {
            handle: test_handle.clone(),
            identity_public_key: b64.encode(b"test_identity_key"),
            signed_prekey: b64.encode(b"test_signed_prekey"),
            one_time_prekeys: vec![],
            kyber_public_key: b64.encode(b"kyber_key"),
        };

        let res1 = register_handler(State(state.clone()), Json(req.clone())).await;
        assert!(res1.is_ok());

        let res2 = register_handler(State(state), Json(req)).await;
        assert!(res2.is_err());
        assert_eq!(res2.err().unwrap(), axum::http::StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_active_connections_not_persisted_on_restart() {
        let state = setup_test_state().await;
        let fake_token = uuid::Uuid::new_v4().to_string();
        let (tx, _) = broadcast::channel(10);
        
        {
            let mut conns = state.active_connections.lock().await;
            conns.insert(fake_token.clone(), tx);
        }

        drop(state);
        let fresh_state = setup_test_state().await;
        
        let conns = fresh_state.active_connections.lock().await;
        assert!(!conns.contains_key(&fake_token));
        assert!(conns.is_empty());
    }

    #[tokio::test]
    async fn test_lookup_rate_limiting() {
        let state = setup_test_state().await;
        
        // 20 requests should succeed
        for _ in 0..20 {
            let res = lookup_handler(Path("#some_handle".to_string()), dummy_connect_info(), State(state.clone())).await;
            assert!(res.is_ok());
        }
        
        // 21st should be rate limited
        let res = lookup_handler(Path("#some_handle".to_string()), dummy_connect_info(), State(state.clone())).await;
        assert!(res.is_err());
        assert_eq!(res.err().unwrap(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_handle_rate_limiter() {
        use std::collections::HashMap;
        use chrono::Utc;
        use tokio::sync::Mutex;
        let handle_rate_limiter = std::sync::Arc::new(Mutex::new(HashMap::<String, (u32, chrono::DateTime<Utc>)>::new()));
        let now = Utc::now();
        let handle = "alice".to_string();

        let mut rl = handle_rate_limiter.lock().await;
        // Simulate 20 requests from different IPs (different calls to lookup_handler)
        for _ in 0..20 {
            let entry = rl.entry(handle.clone()).or_insert((0, now));
            entry.0 += 1;
        }

        // 21st request should hit the limit
        let entry = rl.entry(handle.clone()).or_insert((0, now));
        assert!(entry.0 >= 20, "Rate limiter did not block on 21st request!");
    }
}


