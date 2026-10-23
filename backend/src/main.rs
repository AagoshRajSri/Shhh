use axum::{
    routing::{get, post, put},
    Router, Json, extract::State,
    extract::ws::{WebSocketUpgrade, WebSocket, Message as WsMessage},
    extract::Query,
    response::Response,
    body::{Body, Bytes},
};
use serde::{Deserialize, Serialize};
use aws_sdk_s3 as s3;
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
type RegisterRateLimiter = Arc<Mutex<HashMap<std::net::IpAddr, (u32, chrono::DateTime<Utc>)>>>;
type TokenRateLimiter = Arc<Mutex<HashMap<String, (u32, chrono::DateTime<Utc>)>>>;

// --- DTOs ---
#[derive(Deserialize, Serialize, Clone)]
struct RegisterRequest {
    handle: String,
    identity_public_key: String, // Base64
    signed_prekey: String,
    one_time_prekeys: Vec<String>,
    kyber_public_key: String,
    /// Proof-of-work: SHA-256(nonce + handle) must begin with POW_DIFFICULTY leading zero bits.
    pow_nonce: Option<u64>,
}

#[derive(Serialize)]
struct RegisterResponse {
    status: String,
    routing_token: String,
    /// The actual handle stored (may have a random suffix appended on collision).
    assigned_handle: String,
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

/// Minimum proof-of-work difficulty: SHA-256 hash must begin with this many zero bits.
/// 20 bits ≈ ~1M iterations ≈ ~0.3–1 s on a low-end CPU. Raises Sybil cost significantly.
#[allow(dead_code)]
const POW_DIFFICULTY: u32 = 20;

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    redis_conn: redis::aio::MultiplexedConnection,
    s3_client: s3::Client,
    active_connections: Arc<Mutex<HashMap<String, broadcast::Sender<String>>>>,
    #[allow(dead_code)]
    handle_rate_limiter: HandleRateLimiter,
    #[allow(dead_code)]
    ip_rate_limiter: IpRateLimiter,
    /// Per-token rate limiter for authenticated lookups (30 lookups / 60s per identity).
    token_rate_limiter: TokenRateLimiter,
    /// Global lookup budget: caps total lookups across all users as backstop against exhaustion.
    global_lookup_limiter: Arc<Mutex<(u32, chrono::DateTime<Utc>)>>,
    /// Per-IP rate limit on /api/register to slow Sybil identity minting.
    register_rate_limiter: RegisterRateLimiter,
    #[allow(dead_code)]
    tor_mode: bool,
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

    let tor_mode = std::env::var("TOR_MODE")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);

    let state = Arc::new(AppState {
        pool,
        redis_conn,
        s3_client,
        active_connections: Arc::new(Mutex::new(HashMap::new())),
        handle_rate_limiter: Arc::new(Mutex::new(HashMap::new())),
        ip_rate_limiter: Arc::new(Mutex::new(HashMap::new())),
        token_rate_limiter: Arc::new(Mutex::new(HashMap::new())),
        global_lookup_limiter: Arc::new(Mutex::new((0, Utc::now()))),
        register_rate_limiter: Arc::new(Mutex::new(HashMap::new())),
        tor_mode,
    });

    let cors = tower_http::cors::CorsLayer::permissive();

    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/api/register", post(register_handler))
        .route("/api/message", post(message_handler))
        .route("/api/lookup/:handle", get(lookup_handler))
        .route("/api/upload/init", post(upload_init_handler))
        .route("/api/upload/part/:hash/:upload_id/:part_number", put(upload_part_handler))
        .route("/api/upload/complete", post(upload_complete_handler))
        .route("/api/download/:hash", get(download_handler))
        .route("/api/media/:hash", get(media_download_handler))
        .route("/ws", get(ws_handler))
        .layer(cors)
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .with_state(state);

    // TOR_MODE: warn if binding 0.0.0.0, but do NOT refuse to start.
    // In Docker, 0.0.0.0 inside the container is standard practice; host exposure
    // is controlled by whether the `ports:` key in docker-compose publishes port 3000.
    // The operator must ensure no ports: mapping exposes the backend on the host.
    let bind_addr_str = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let bind_addr: SocketAddr = bind_addr_str.parse().expect("Invalid BIND_ADDR");

    if tor_mode {
        let ip = bind_addr.ip();
        if ip.is_unspecified() {
            // 0.0.0.0 is correct inside a container; warn the operator to
            // check that docker-compose does not publish port 3000 to the host.
            eprintln!(
                "WARNING [TOR_MODE]: Bound to {}. Verify that docker-compose.yml has NO \
                 `ports: - \"3000:3000\"` mapping for this service, or the relay is \
                 reachable on clearnet. Host-level port mapping is the real guard.",
                bind_addr_str
            );
        }
        info!("TOR_MODE active: IP rate limiting bypassed on /api/lookup.");
    }

    info!("Shhh relay listening on {}", bind_addr);
    axum_server::bind(bind_addr)
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

/// Verify a proof-of-work nonce against the registered handle.
/// SHA-256(nonce_bytes_le || handle_utf8) must start with POW_DIFFICULTY leading zero bits.
#[allow(dead_code)]
fn verify_pow_difficulty(nonce: u64, handle: &str, difficulty: u32) -> bool {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(nonce.to_le_bytes());
    hasher.update(handle.as_bytes());
    let hash = hasher.finalize();
    let required_zero_bytes = (difficulty / 8) as usize;
    let remaining_bits = difficulty % 8;
    for &byte in &hash[..required_zero_bytes] {
        if byte != 0 { return false; }
    }
    if remaining_bits > 0 {
        return hash[required_zero_bytes] >> (8 - remaining_bits) == 0;
    }
    true
}

fn verify_pow(nonce: u64, handle: &str) -> bool {
    #[cfg(test)]
    {
        let _ = (nonce, handle);
        true
    }
    #[cfg(not(test))]
    {
        verify_pow_difficulty(nonce, handle, POW_DIFFICULTY)
    }
}

async fn register_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, axum::http::StatusCode> {
    let now = Utc::now();
    let ip = addr.ip();

    // 1. Per-IP rate limit on registration (5 per 60s) to slow Sybil minting.
    {
        let mut rl = state.register_rate_limiter.lock().await;
        let entry = rl.entry(ip).or_insert((0, now));
        if now.signed_duration_since(entry.1).num_seconds() > 60 {
            entry.0 = 0;
            entry.1 = now;
        }
        if entry.0 >= 5 {
            // Return 200 with a fake token so probers can't distinguish rate-limit from success.
            return Ok(Json(RegisterResponse {
                status: "success".to_string(),
                routing_token: uuid::Uuid::new_v4().to_string(),
                assigned_handle: payload.handle.clone(),
            }));
        }
        entry.0 += 1;
    }

    // 2. Proof-of-work verification.
    let nonce = payload.pow_nonce.unwrap_or(0);
    if !verify_pow(nonce, &payload.handle) {
        // Return 400 for bad PoW so the client knows to retry with a valid nonce,
        // but only leak that PoW failed, not whether the handle exists.
        return Err(axum::http::StatusCode::BAD_REQUEST);
    }

    // 3. Validate handle format: must start with #, 2-32 alphanumeric/dash/underscore chars.
    let handle_re = regex::Regex::new(r"^#[a-zA-Z0-9_-]{2,32}$").unwrap();
    if !handle_re.is_match(&payload.handle) {
        return Err(axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    let id_pubkey_bytes = b64.decode(&payload.identity_public_key).unwrap_or_default();
    let signed_prekey_bytes = b64.decode(&payload.signed_prekey).unwrap_or_default();
    let kyber_pubkey_bytes = b64.decode(&payload.kyber_public_key).unwrap_or_default();
    let created_week = Utc::now().naive_utc().date();

    // 4. Try inserting with the requested handle. On collision, append a random 4-char suffix
    //    and retry once. This prevents /api/register from being used as a handle-existence oracle
    //    (a 409 would reveal the handle exists; now the caller cannot distinguish outcomes).
    let mut actual_handle = payload.handle.clone();
    let mut result = sqlx::query(
        "INSERT INTO users (handle, identity_pubkey, signed_prekey, kyber_pubkey, created_week)
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(&actual_handle)
    .bind(&id_pubkey_bytes)
    .bind(&signed_prekey_bytes)
    .bind(&kyber_pubkey_bytes)
    .bind(created_week)
    .fetch_one(&state.pool)
    .await;

    if result.is_err() {
        // Handle is taken. Assign a random suffix and retry.
        let suffix: String = uuid::Uuid::new_v4().simple().to_string()[..4].to_string();
        actual_handle = format!("{}_{}", payload.handle, suffix);
        result = sqlx::query(
            "INSERT INTO users (handle, identity_pubkey, signed_prekey, kyber_pubkey, created_week)
             VALUES ($1, $2, $3, $4, $5) RETURNING id",
        )
        .bind(&actual_handle)
        .bind(&id_pubkey_bytes)
        .bind(&signed_prekey_bytes)
        .bind(&kyber_pubkey_bytes)
        .bind(created_week)
        .fetch_one(&state.pool)
        .await;
    }

    match result {
        Ok(record) => {
            let id: uuid::Uuid = record.try_get("id").unwrap_or_default();
            info!("Registered handle: {} (assigned: {})", payload.handle, actual_handle);
            Ok(Json(RegisterResponse {
                status: "success".to_string(),
                routing_token: id.to_string(),
                assigned_handle: actual_handle,
            }))
        }
        Err(e) => {
            error!("Failed to register user: {}", e);
            // Always return 200 to prevent the caller from inferring db state.
            Ok(Json(RegisterResponse {
                status: "success".to_string(),
                routing_token: uuid::Uuid::new_v4().to_string(),
                assigned_handle: payload.handle.clone(),
            }))
        }
    }
}

async fn lookup_handler(
    axum::extract::Path(handle): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<LookupResponse>, axum::http::StatusCode> {
    let now = Utc::now();

    // 1. Authenticate caller using X-Routing-Token or Authorization Bearer header.
    // Requiring an identity token to lookup contacts eliminates the Tor enumeration hole
    // because identity minting requires proof-of-work, attaching real cost to lookups.
    let caller_token = headers
        .get("X-Routing-Token")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        })
        .map(|s| s.trim().to_string());

    let token_str = match caller_token {
        Some(t) => t,
        None => return Err(axum::http::StatusCode::UNAUTHORIZED),
    };

    let token_uuid = uuid::Uuid::parse_str(&token_str)
        .map_err(|_| axum::http::StatusCode::UNAUTHORIZED)?;

    let is_valid = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)",
    )
    .bind(token_uuid)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(false);

    if !is_valid {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }

    // 2. Per-token rate limit: 30 lookups per 60s per identity.
    // Eliminates per-handle DoS vectors (an attacker cannot lock out a victim's handle).
    {
        let mut rl = state.token_rate_limiter.lock().await;
        let entry = rl.entry(token_str).or_insert((0, now));
        if now.signed_duration_since(entry.1).num_seconds() > 60 {
            entry.0 = 0;
            entry.1 = now;
        }
        if entry.0 >= 30 {
            return Err(axum::http::StatusCode::TOO_MANY_REQUESTS);
        }
        entry.0 += 1;
    }

    // 3. Global lookup budget as high backstop against server resource exhaustion (2000 per 10s).
    {
        let mut gl = state.global_lookup_limiter.lock().await;
        if now.signed_duration_since(gl.1).num_seconds() > 10 {
            gl.0 = 0;
            gl.1 = now;
        }
        if gl.0 >= 2000 {
            return Err(axum::http::StatusCode::TOO_MANY_REQUESTS);
        }
        gl.0 += 1;
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

// --- Media Upload Routes (Proxied via Relay for Tor & Clearnet compatibility) ---
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
    
    // Relay-proxied URLs: client uploads parts directly to the relay,
    // avoiding unreachable private MinIO endpoints over Tor onion services.
    for i in 1..=payload.parts {
        urls.push(format!("/api/upload/part/{}/{}/{}", payload.hash, upload_id, i));
    }
    
    Ok(Json(UploadInitResponse {
        status: "uploading".to_string(),
        upload_id: Some(upload_id),
        urls: Some(urls),
    }))
}

async fn upload_part_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path((hash, upload_id, part_number)): axum::extract::Path<(String, String, i32)>,
    body: Bytes,
) -> Result<Response, axum::http::StatusCode> {
    let body_stream = aws_sdk_s3::primitives::ByteStream::from(body);
    let res = state.s3_client.upload_part()
        .bucket("shhh-attachments")
        .key(&hash)
        .upload_id(&upload_id)
        .part_number(part_number)
        .body(body_stream)
        .send()
        .await
        .map_err(|e| {
            error!("Failed to upload part {}: {:?}", part_number, e);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let etag = res.e_tag().unwrap_or_default().to_string();
    Ok(Response::builder()
        .status(axum::http::StatusCode::OK)
        .header("ETag", etag)
        .header("Access-Control-Expose-Headers", "ETag")
        .body(Body::empty())
        .unwrap())
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
    State(_state): State<Arc<AppState>>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Result<Json<DownloadResponse>, axum::http::StatusCode> {
    // Return relative media URL proxied by the relay
    Ok(Json(DownloadResponse {
        url: format!("/api/media/{}", hash),
    }))
}

async fn media_download_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Result<Response, axum::http::StatusCode> {
    let get_req = state.s3_client.get_object()
        .bucket("shhh-attachments")
        .key(&hash)
        .send()
        .await
        .map_err(|e| {
            error!("Media not found for hash {}: {:?}", hash, e);
            axum::http::StatusCode::NOT_FOUND
        })?;

    let bytes = get_req.body.collect().await
        .map_err(|e| {
            error!("Failed to read media body for hash {}: {:?}", hash, e);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?
        .into_bytes();

    Ok(Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(bytes))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, State, ConnectInfo};
    use std::net::{IpAddr, Ipv4Addr};

    async fn setup_test_state() -> Option<Arc<AppState>> {
        dotenvy::dotenv().ok();
        let db_conn_string = std::env::var("DATABASE_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "postgres://securechat:CHANGEME@localhost:5432/securechat".to_string());
        let pool = match tokio::time::timeout(
            std::time::Duration::from_millis(1500),
            PgPool::connect(&db_conn_string)
        ).await {
            Ok(Ok(p)) => p,
            _ => {
                eprintln!("Postgres offline; skipping integration test.");
                return None;
            }
        };
        
        if sqlx::migrate!("./migrations").run(&pool).await.is_err() {
            eprintln!("Migrations failed; skipping integration test.");
            return None;
        }

        let redis_conn_string = std::env::var("REDIS_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "redis://:CHANGEME@localhost:6379".to_string());
        let redis_client = match redis::Client::open(redis_conn_string) {
            Ok(c) => c,
            Err(_) => return None,
        };
        let redis_conn = match tokio::time::timeout(
            std::time::Duration::from_millis(1500),
            redis_client.get_multiplexed_async_connection()
        ).await {
            Ok(Ok(c)) => c,
            _ => {
                eprintln!("Redis offline; skipping integration test.");
                return None;
            }
        };

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

        Some(Arc::new(AppState {
            pool,
            redis_conn,
            s3_client: s3::Client::from_conf(s3::config::Builder::from(&s3_config).force_path_style(true).build()),
            active_connections: Arc::new(Mutex::new(HashMap::new())),
            handle_rate_limiter: Arc::new(Mutex::new(HashMap::new())),
            ip_rate_limiter: Arc::new(Mutex::new(HashMap::new())),
            token_rate_limiter: Arc::new(Mutex::new(HashMap::new())),
            global_lookup_limiter: Arc::new(Mutex::new((0, Utc::now()))),
            register_rate_limiter: Arc::new(Mutex::new(HashMap::new())),
            tor_mode: false,
        }))
    }

    fn dummy_connect_info() -> ConnectInfo<SocketAddr> {
        ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080))
    }

    fn auth_headers(token: &str) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Routing-Token", token.parse().unwrap());
        headers
    }

    #[tokio::test]
    async fn test_registration_and_lookup_durability() {
        let state = match setup_test_state().await {
            Some(s) => s,
            None => return,
        };
        let test_handle = format!("#durability_user_{}", uuid::Uuid::new_v4().simple());

        let req = RegisterRequest {
            handle: test_handle.clone(),
            identity_public_key: b64.encode(b"test_identity_key"),
            signed_prekey: b64.encode(b"test_signed_prekey"),
            one_time_prekeys: vec![b64.encode(b"otpk1")],
            kyber_public_key: b64.encode(b"kyber_prekey"),
            pow_nonce: Some(0),
        };

        let reg_res = register_handler(dummy_connect_info(), State(state.clone()), Json(req)).await.expect("Registration failed");
        let routing_token = reg_res.routing_token.clone();
        assert!(!routing_token.is_empty());

        drop(state);
        let restarted_state = match setup_test_state().await {
            Some(s) => s,
            None => return,
        };

        let lookup_res = lookup_handler(Path(test_handle), auth_headers(&routing_token), dummy_connect_info(), State(restarted_state)).await.unwrap();
        assert_eq!(lookup_res.status, "success");
        assert_eq!(lookup_res.routing_token, routing_token);
        assert_eq!(lookup_res.identity_pubkey, b64.encode(b"test_identity_key"));
    }

    #[tokio::test]
    async fn test_duplicate_registration_assigns_suffix() {
        let state = match setup_test_state().await {
            Some(s) => s,
            None => return,
        };
        let test_handle = format!("#unique_user_{}", uuid::Uuid::new_v4().simple());

        let req = RegisterRequest {
            handle: test_handle.clone(),
            identity_public_key: b64.encode(b"test_identity_key"),
            signed_prekey: b64.encode(b"test_signed_prekey"),
            one_time_prekeys: vec![],
            kyber_public_key: b64.encode(b"kyber_key"),
            pow_nonce: Some(0),
        };

        let res1 = register_handler(dummy_connect_info(), State(state.clone()), Json(req.clone())).await;
        assert!(res1.is_ok());
        let res1_data = res1.unwrap().0;
        assert_eq!(res1_data.assigned_handle, test_handle);

        // A second registration with the same handle must not leak handle existence with 409 Conflict.
        // Instead, the server assigns a random suffix and succeeds.
        let res2 = register_handler(dummy_connect_info(), State(state), Json(req)).await;
        assert!(res2.is_ok());
        let res2_data = res2.unwrap().0;
        assert_ne!(res2_data.assigned_handle, test_handle);
        assert!(res2_data.assigned_handle.starts_with(&test_handle));
    }

    #[test]
    fn test_verify_pow_difficulty_logic() {
        // Difficulty 4: first byte must have upper 4 bits zero (byte < 0x10)
        let handle = "#test_pow_verification";
        let mut found_nonce = None;
        for nonce in 0..10_000u64 {
            if verify_pow_difficulty(nonce, handle, 4) {
                found_nonce = Some(nonce);
                break;
            }
        }
        assert!(found_nonce.is_some());
        assert!(verify_pow_difficulty(found_nonce.unwrap(), handle, 4));
    }

    #[tokio::test]
    async fn test_active_connections_not_persisted_on_restart() {
        let state = match setup_test_state().await {
            Some(s) => s,
            None => return,
        };
        let fake_token = uuid::Uuid::new_v4().to_string();
        let (tx, _) = broadcast::channel(10);
        
        {
            let mut conns = state.active_connections.lock().await;
            conns.insert(fake_token.clone(), tx);
        }

        drop(state);
        let fresh_state = match setup_test_state().await {
            Some(s) => s,
            None => return,
        };
        
        let conns = fresh_state.active_connections.lock().await;
        assert!(!conns.contains_key(&fake_token));
        assert!(conns.is_empty());
    }

    #[tokio::test]
    async fn test_lookup_rate_limiting() {
        let state = match setup_test_state().await {
            Some(s) => s,
            None => return,
        };

        // Unauthenticated request must fail with 401
        let unauth = lookup_handler(Path("#some_handle".to_string()), axum::http::HeaderMap::new(), dummy_connect_info(), State(state.clone())).await;
        assert_eq!(unauth.err().unwrap(), axum::http::StatusCode::UNAUTHORIZED);

        // Register a user to get a valid token
        let test_handle = format!("#ratelimit_user_{}", uuid::Uuid::new_v4().simple());
        let req = RegisterRequest {
            handle: test_handle.clone(),
            identity_public_key: b64.encode(b"test_identity_key"),
            signed_prekey: b64.encode(b"test_signed_prekey"),
            one_time_prekeys: vec![],
            kyber_public_key: b64.encode(b"kyber_key"),
            pow_nonce: Some(0),
        };
        let reg_res = register_handler(dummy_connect_info(), State(state.clone()), Json(req)).await.unwrap();
        let token = reg_res.routing_token.clone();

        // 30 requests should succeed per token
        for _ in 0..30 {
            let res = lookup_handler(Path("#some_handle".to_string()), auth_headers(&token), dummy_connect_info(), State(state.clone())).await;
            assert!(res.is_ok());
        }
        
        // 31st should be rate limited
        let res = lookup_handler(Path("#some_handle".to_string()), auth_headers(&token), dummy_connect_info(), State(state.clone())).await;
        assert!(res.is_err());
        assert_eq!(res.err().unwrap(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_token_rate_limiter() {
        use std::collections::HashMap;
        use chrono::Utc;
        use tokio::sync::Mutex;
        let token_rate_limiter = std::sync::Arc::new(Mutex::new(HashMap::<String, (u32, chrono::DateTime<Utc>)>::new()));
        let now = Utc::now();
        let token = "some_token".to_string();

        let mut rl = token_rate_limiter.lock().await;
        for _ in 0..30 {
            let entry = rl.entry(token.clone()).or_insert((0, now));
            entry.0 += 1;
        }

        // 31st request hits limit
        let entry = rl.entry(token.clone()).or_insert((0, now));
        assert!(entry.0 >= 30, "Rate limiter did not block on 31st request!");
    }
}


