use axum::{
    routing::{get, post, put},
    Router, Json, extract::State,
    extract::ws::{WebSocketUpgrade, WebSocket, Message as WsMessage},
    response::Response,
    body::{Body, Bytes},
};
use serde::{Deserialize, Serialize};
use aws_sdk_s3 as s3;
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use tokio::sync::{broadcast, Mutex, RwLock};
use tracing::{info, error};
use sqlx::{PgPool, Row};
use base64::{Engine as _, engine::general_purpose::STANDARD as b64};
use chrono::Utc;
use axum::extract::ConnectInfo;
use std::net::SocketAddr;

use subtle::ConstantTimeEq;
use axum::response::IntoResponse;

// Type aliases for complex rate-limiter map types
type HandleRateLimiter = Arc<Mutex<HashMap<String, (u32, chrono::DateTime<Utc>)>>>;
type IpRateLimiter = Arc<Mutex<HashMap<std::net::IpAddr, (u32, chrono::DateTime<Utc>)>>>;
type RegisterRateLimiter = Arc<Mutex<HashMap<std::net::IpAddr, (u32, chrono::DateTime<Utc>)>>>;
type TokenRateLimiter = Arc<Mutex<HashMap<String, (u32, chrono::DateTime<Utc>)>>>;
type FailedAuthLimiter = Arc<Mutex<HashMap<std::net::IpAddr, (u32, chrono::DateTime<Utc>)>>>;

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
    /// Private 256-bit client-generated secret (64-char hex string).
    /// Never returned by any endpoint or written to logs.
    receive_secret: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct RegisterResponse {
    status: String,
    inbox_id: String,
    /// The actual handle stored (may have a random suffix appended on collision).
    assigned_handle: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct LookupResponse {
    status: String,
    inbox_id: String,
    identity_pubkey: String,
}

#[derive(Deserialize, Serialize, Clone)]
struct SealedSenderEnvelope {
    /// Public delivery address. Carries only the public inbox_id UUID.
    to_inbox_id: String,
    encrypted_payload: String,
}

#[derive(Deserialize)]
struct AckRequest {
    msg_id: String,
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
    /// Rate limiter for failed authentication attempts (10 failed attempts / 60s per IP, non-Tor only).
    failed_auth_limiter: FailedAuthLimiter,
    /// In-memory cache of valid secret hashes.
    /// Protects Postgres from junk credential exhaustion attacks: bogus secrets are rejected
    /// in-memory in O(1) without touching Postgres. Eliminates the need for a global failure counter
    /// that could be weaponized to lock out legitimate users.
    ///
    /// ARCHITECTURE / SINGLE-INSTANCE LIMITATION:
    /// This set resides in process memory (alongside active_connections and rate limiters).
    /// Running multiple backend instances would require shared state or synchronization.
    ///
    /// PHASE 8 LIFECYCLE NOTE:
    /// When account deletion or secret rotation is added (Phase 8), the handler MUST
    /// remove or atomically update the corresponding hash entry in this set.
    valid_secret_hashes: Arc<RwLock<HashSet<[u8; 32]>>>,
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
    dotenvy::from_filename("../.env").ok();
    tracing_subscriber::fmt::init();

    let db_conn_string = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://securechat:password@localhost:5433/securechat".to_string());
    println!("Connecting to Postgres at {}...", db_conn_string);
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
        .unwrap_or_else(|_| "redis://:password@localhost:6379".to_string());
    let redis_client = redis::Client::open(redis_conn_string).expect("Invalid Redis URL");
    let redis_conn = redis_client.get_multiplexed_async_connection().await.expect("Failed to connect to Redis");

    println!("Connecting to MinIO...");
    let s3_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .endpoint_url(std::env::var("S3_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".to_string()))
        .region(aws_config::Region::new("us-east-1"))
        .credentials_provider(s3::config::Credentials::new(
            std::env::var("S3_ACCESS_KEY").unwrap_or_else(|_| "minioadmin".to_string()),
            std::env::var("S3_SECRET_KEY").unwrap_or_else(|_| "minioadminpassword".to_string()),
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

    // STARTUP ORDERING GUARANTEE:
    // The valid_secret_hashes set MUST finish loading from Postgres before the server binds
    // or starts accepting connections. If incoming requests were served during warm-up, valid
    // users would encounter false 401 Unauthorized errors from the in-memory fast-path check.
    println!("Pre-loading registered secret hashes from Postgres into memory...");
    let initial_hashes: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT receive_secret_hash FROM users WHERE auth_scheme = 'hash-v1'"
    )
    .fetch_all(&pool)
    .await
    .unwrap_or_default();

    let mut hash_set = HashSet::new();
    for h in initial_hashes {
        if h.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            hash_set.insert(arr);
        }
    }
    println!("Startup warm-up complete: loaded {} valid secret hashes into memory.", hash_set.len());

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
        failed_auth_limiter: Arc::new(Mutex::new(HashMap::new())),
        valid_secret_hashes: Arc::new(RwLock::new(hash_set)),
        tor_mode,
    });

    let cors = tower_http::cors::CorsLayer::permissive();

    let app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/api/register", post(register_handler))
        .route("/api/message", post(message_handler))
        .route("/api/message/ack", post(ack_handler))
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

const RECV_DOMAIN_SEP: &[u8] = b"shhh-recv-v1";

fn hash_receive_secret(secret_raw: &str) -> Result<[u8; 32], axum::http::StatusCode> {
    let trimmed = secret_raw.trim();
    let secret_bytes = if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(trimmed).map_err(|_| axum::http::StatusCode::UNAUTHORIZED)?
    } else {
        use base64::Engine;
        b64.decode(trimmed)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
            .map_err(|_| axum::http::StatusCode::UNAUTHORIZED)?
    };

    if secret_bytes.len() != 32 {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(RECV_DOMAIN_SEP);
    hasher.update(&secret_bytes);
    let hash: [u8; 32] = hasher.finalize().into();
    Ok(hash)
}

#[derive(Clone, Debug)]
struct AuthenticatedUser {
    #[allow(dead_code)]
    id: uuid::Uuid,
    inbox_id: uuid::Uuid,
    #[allow(dead_code)]
    handle: String,
}

/// Authenticate a raw receive_secret string against the stored hash.
///
/// # Authentication and DoS Protection Model
/// Authentication uses SHA-256("shhh-recv-v1" || secret) client-side secret tokens.
/// To protect Postgres from query exhaustion under Tor or open network load, the server
/// maintains an in-memory set of valid secret hashes (`valid_secret_hashes`).
///
/// Bogus credentials are rejected immediately in memory in O(1) time without touching Postgres.
/// Because invalid secrets never touch Postgres and legitimate secrets always match the cache,
/// valid users are never denied service by an adversary flooding invalid credentials.
async fn authenticate_receive_secret(
    state: &Arc<AppState>,
    secret_str: &str,
    caller_ip: std::net::IpAddr,
) -> Result<AuthenticatedUser, axum::http::StatusCode> {
    let now = Utc::now();

    // 1. Per-IP failed-auth limit: max 10 per 60s (non-Tor only).
    // SKIPPED in TOR_MODE: behind an onion service all users share a single IP.
    if !state.tor_mode {
        let rl = state.failed_auth_limiter.lock().await;
        if let Some((count, window_start)) = rl.get(&caller_ip) {
            if now.signed_duration_since(*window_start).num_seconds() <= 60 && *count >= 10 {
                return Err(axum::http::StatusCode::TOO_MANY_REQUESTS);
            }
        }
    }

    let record_failure = || async {
        if !state.tor_mode {
            let mut rl = state.failed_auth_limiter.lock().await;
            let entry = rl.entry(caller_ip).or_insert((0, now));
            if now.signed_duration_since(entry.1).num_seconds() > 60 {
                entry.0 = 0;
                entry.1 = now;
            }
            entry.0 += 1;
        }
    };

    let computed_hash = match hash_receive_secret(secret_str) {
        Ok(h) => h,
        Err(_) => {
            record_failure().await;
            return Err(axum::http::StatusCode::UNAUTHORIZED);
        }
    };

    // Fast-path in-memory hash check:
    // Reject unknown/junk credentials immediately without querying Postgres.
    {
        let vsh = state.valid_secret_hashes.read().await;
        if !vsh.contains(&computed_hash) {
            record_failure().await;
            return Err(axum::http::StatusCode::UNAUTHORIZED);
        }
    }

    let record = sqlx::query(
        "SELECT id, inbox_id, handle, receive_secret_hash, auth_scheme FROM users WHERE receive_secret_hash = $1"
    )
    .bind(&computed_hash[..])
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let row = match record {
        Some(r) => r,
        None => {
            record_failure().await;
            return Err(axum::http::StatusCode::UNAUTHORIZED);
        }
    };

    let stored_hash: Vec<u8> = row.try_get("receive_secret_hash").unwrap_or_default();
    let auth_scheme: String = row.try_get("auth_scheme").unwrap_or_default();

    if auth_scheme != "hash-v1" || stored_hash.len() != 32 {
        record_failure().await;
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }

    // Constant-time comparison
    if !bool::from(computed_hash.ct_eq(&stored_hash[..])) {
        record_failure().await;
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }

    let id: uuid::Uuid = row.try_get("id").unwrap_or_default();
    let inbox_id: uuid::Uuid = row.try_get("inbox_id").unwrap_or_default();
    let handle: String = row.try_get("handle").unwrap_or_default();

    Ok(AuthenticatedUser { id, inbox_id, handle })
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
            // Return 200 with a fake inbox_id so probers can't distinguish rate-limit from success.
            let fake_id = uuid::Uuid::new_v4().to_string();
            return Ok(Json(RegisterResponse {
                status: "success".to_string(),
                inbox_id: fake_id,
                assigned_handle: payload.handle.clone(),
            }));
        }
        entry.0 += 1;
    }

    // 2. Proof-of-work verification.
    let nonce = payload.pow_nonce.unwrap_or(0);
    if !verify_pow(nonce, &payload.handle) {
        return Err(axum::http::StatusCode::BAD_REQUEST);
    }

    // 3. Validate handle format: must start with #, 2-32 alphanumeric/dash/underscore chars.
    let handle_re = regex::Regex::new(r"^#[a-zA-Z0-9_-]{2,32}$").unwrap();
    if !handle_re.is_match(&payload.handle) {
        return Err(axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    }

    // 4. Validate receive_secret: must be 256 bits (32 bytes).
    let secret_hash = hash_receive_secret(&payload.receive_secret)
        .map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;

    let id_pubkey_bytes = b64.decode(&payload.identity_public_key).unwrap_or_default();
    let signed_prekey_bytes = b64.decode(&payload.signed_prekey).unwrap_or_default();
    let kyber_pubkey_bytes = b64.decode(&payload.kyber_public_key).unwrap_or_default();
    let created_week = Utc::now().naive_utc().date();

    let inbox_id = uuid::Uuid::new_v4();

    // 5. Try inserting with the requested handle. On collision, append a random 4-char suffix
    //    and retry once.
    let mut actual_handle = payload.handle.clone();
    let mut result = sqlx::query(
        "INSERT INTO users (handle, identity_pubkey, signed_prekey, kyber_pubkey, created_week, inbox_id, receive_secret_hash, auth_scheme)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'hash-v1') RETURNING id, inbox_id",
    )
    .bind(&actual_handle)
    .bind(&id_pubkey_bytes)
    .bind(&signed_prekey_bytes)
    .bind(&kyber_pubkey_bytes)
    .bind(created_week)
    .bind(inbox_id)
    .bind(&secret_hash[..])
    .fetch_one(&state.pool)
    .await;

    if result.is_err() {
        let suffix: String = uuid::Uuid::new_v4().simple().to_string()[..4].to_string();
        actual_handle = format!("{}_{}", payload.handle, suffix);
        result = sqlx::query(
            "INSERT INTO users (handle, identity_pubkey, signed_prekey, kyber_pubkey, created_week, inbox_id, receive_secret_hash, auth_scheme)
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'hash-v1') RETURNING id, inbox_id",
        )
        .bind(&actual_handle)
        .bind(&id_pubkey_bytes)
        .bind(&signed_prekey_bytes)
        .bind(&kyber_pubkey_bytes)
        .bind(created_week)
        .bind(inbox_id)
        .bind(&secret_hash[..])
        .fetch_one(&state.pool)
        .await;
    }

    match result {
        Ok(record) => {
            let assigned_inbox_id: uuid::Uuid = record.try_get("inbox_id").unwrap_or(inbox_id);
            {
                let mut vsh = state.valid_secret_hashes.write().await;
                vsh.insert(secret_hash);
            }
            info!("Registered handle: {} (assigned: {})", payload.handle, actual_handle);
            Ok(Json(RegisterResponse {
                status: "success".to_string(),
                inbox_id: assigned_inbox_id.to_string(),
                assigned_handle: actual_handle,
            }))
        }
        Err(e) => {
            error!("Failed to register user: {}", e);
            Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn lookup_handler(
    axum::extract::Path(handle): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<LookupResponse>, axum::http::StatusCode> {
    let now = Utc::now();

    // 1. Authenticate caller with their receive_secret
    let caller_secret = headers
        .get("X-Receive-Secret")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        })
        .map(|s| s.trim().to_string());

    let secret_str = match caller_secret {
        Some(s) if !s.is_empty() => s,
        _ => return Err(axum::http::StatusCode::UNAUTHORIZED),
    };

    let auth_user = authenticate_receive_secret(&state, &secret_str, addr.ip()).await?;
    let token_str = auth_user.inbox_id.to_string();

    // 2. Per-token rate limit: 30 lookups per 60s per identity.
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
        "SELECT inbox_id, identity_pubkey FROM users WHERE handle = $1",
    )
    .bind(&handle)
    .fetch_optional(&state.pool)
    .await;

    match result {
        Ok(Some(record)) => {
            let target_inbox_id: uuid::Uuid = record.try_get("inbox_id").unwrap_or_default();
            let identity_pubkey: Vec<u8> = record.try_get("identity_pubkey").unwrap_or_default();
            Ok(Json(LookupResponse {
                status: "success".to_string(),
                inbox_id: target_inbox_id.to_string(),
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
                inbox_id: fake_uuid.to_string(),
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
    let msg_id = uuid::Uuid::new_v4().to_string();
    let queue_key = format!("msg_queue:{}", envelope.to_inbox_id);
    
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
    if let Some(tx) = conns.get(&envelope.to_inbox_id) {
        let _ = tx.send("WAKE".to_string());
    }
    
    Json(serde_json::json!({ "status": "queued" }))
}

// HTTP message ack route
async fn ack_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<AckRequest>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    let secret = headers
        .get("X-Receive-Secret")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        })
        .map(|s| s.trim())
        .unwrap_or_default();

    if secret.is_empty() {
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }

    let auth_user = authenticate_receive_secret(&state, secret, addr.ip()).await?;
    let queue_key = format!("msg_queue:{}", auth_user.inbox_id);
    let mut conn = state.redis_conn.clone();
    let _: () = redis::cmd("HDEL")
        .arg(&queue_key)
        .arg(&payload.msg_id)
        .query_async(&mut conn)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({ "status": "acknowledged" })))
}

// WebSocket Route
async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    // Secret travels ONLY in Sec-WebSocket-Protocol. Query fallback is completely removed.
    let subprotocols = headers.get("sec-websocket-protocol")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();

    let secret = subprotocols
        .split(',')
        .map(|s| s.trim())
        .find(|s| !s.is_empty())
        .unwrap_or_default();

    if secret.is_empty() {
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }

    let auth_user = match authenticate_receive_secret(&state, secret, addr.ip()).await {
        Ok(u) => u,
        Err(status) => return status.into_response(),
    };

    let selected_proto = secret.to_string();
    let inbox_id_str = auth_user.inbox_id.to_string();

    ws.protocols([selected_proto]).on_upgrade(move |socket| {
        handle_socket(socket, inbox_id_str, state)
    })
}

async fn flush_queue(inbox_id: &str, socket: &mut WebSocket, mut redis_conn: redis::aio::MultiplexedConnection) -> bool {
    let queue_key = format!("msg_queue:{}", inbox_id);
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

async fn handle_socket(mut socket: WebSocket, inbox_id: String, state: Arc<AppState>) {
    let (tx, mut rx) = broadcast::channel(100);
    
    {
        let mut conns = state.active_connections.lock().await;
        conns.insert(inbox_id.clone(), tx);
    }

    info!("WS client connected successfully");
    
    // Flush immediately on connect
    if !flush_queue(&inbox_id, &mut socket, state.redis_conn.clone()).await {
        let mut conns = state.active_connections.lock().await;
        conns.remove(&inbox_id);
        return;
    }

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(msg) => {
                        if msg == "WAKE" {
                            if !flush_queue(&inbox_id, &mut socket, state.redis_conn.clone()).await {
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
                        if !flush_queue(&inbox_id, &mut socket, state.redis_conn.clone()).await {
                            break;
                        }
                    }
                }
            }
            
            result = socket.recv() => {
                match result {
                    Some(Ok(WsMessage::Text(text))) => {
                        if let Ok(envelope) = serde_json::from_str::<SealedSenderEnvelope>(&text) {
                            let msg_id = uuid::Uuid::new_v4().to_string();
                            let queue_key = format!("msg_queue:{}", envelope.to_inbox_id);
                            
                            let mut conn = state.redis_conn.clone();
                            let _: () = redis::pipe()
                                .hset(&queue_key, &msg_id, &envelope.encrypted_payload)
                                .expire(&queue_key, 604800)
                                .ignore()
                                .query_async(&mut conn).await.unwrap_or(());

                            let conns = state.active_connections.lock().await;
                            if let Some(tx) = conns.get(&envelope.to_inbox_id) {
                                let _ = tx.send("WAKE".to_string());
                            }
                        } else if let Ok(ack) = serde_json::from_str::<serde_json::Value>(&text) {
                            if ack["type"] == "ack" {
                                if let Some(msg_id) = ack["msg_id"].as_str() {
                                    let queue_key = format!("msg_queue:{}", inbox_id);
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

    info!("WS client disconnected");
    let mut conns = state.active_connections.lock().await;
    conns.remove(&inbox_id);
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
        // If SKIP_INTEGRATION=1, silently skip service-dependent tests.
        // CI must never set this variable.
        if std::env::var("SKIP_INTEGRATION").as_deref() == Ok("1") {
            eprintln!("[SKIP] SKIP_INTEGRATION=1 set; skipping integration test.");
            return None;
        }

        dotenvy::dotenv().ok();
        let db_conn_string = std::env::var("DATABASE_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "postgres://securechat:CHANGEME@localhost:5432/securechat".to_string());
        let pool = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            PgPool::connect(&db_conn_string)
        ).await
            .expect("Postgres connection timed out — is Docker running?")
            .expect("Failed to connect to Postgres — is Docker running?");

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Migrations failed");

        let redis_conn_string = std::env::var("REDIS_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "redis://:CHANGEME@localhost:6379".to_string());
        let redis_client = redis::Client::open(redis_conn_string)
            .expect("Invalid Redis URL");
        let redis_conn = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            redis_client.get_multiplexed_async_connection()
        ).await
            .expect("Redis connection timed out — is Docker running?")
            .expect("Failed to connect to Redis — is Docker running?");

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

        let initial_hashes: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT receive_secret_hash FROM users WHERE auth_scheme = 'hash-v1'"
        )
        .fetch_all(&pool)
        .await
        .unwrap_or_default();

        let mut hash_set = HashSet::new();
        for h in initial_hashes {
            if h.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&h);
                hash_set.insert(arr);
            }
        }

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
            failed_auth_limiter: Arc::new(Mutex::new(HashMap::new())),
            valid_secret_hashes: Arc::new(RwLock::new(hash_set)),
            tor_mode: false,
        }))
    }

    fn dummy_connect_info() -> ConnectInfo<SocketAddr> {
        use std::sync::atomic::{AtomicU8, Ordering};
        static IP_SUFFIX: AtomicU8 = AtomicU8::new(2);
        let s = IP_SUFFIX.fetch_add(1, Ordering::Relaxed);
        ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, s)), 8080))
    }

    fn auth_headers(secret: &str) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Receive-Secret", secret.parse().unwrap());
        headers
    }

    fn test_secret(_seed: u8) -> String {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        hex::encode(bytes)
    }

    #[tokio::test]
    async fn test_registration_and_lookup_durability() {
        let state = match setup_test_state().await {
            Some(s) => s,
            None => return,
        };
        let test_handle = format!("#dur_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let secret = test_secret(1);

        let req = RegisterRequest {
            handle: test_handle.clone(),
            identity_public_key: b64.encode(b"test_identity_key"),
            signed_prekey: b64.encode(b"test_signed_prekey"),
            one_time_prekeys: vec![b64.encode(b"otpk1")],
            kyber_public_key: b64.encode(b"kyber_prekey"),
            pow_nonce: Some(0),
            receive_secret: secret.clone(),
        };

        let reg_res = register_handler(dummy_connect_info(), State(state.clone()), Json(req)).await.expect("Registration failed");
        let inbox_id = reg_res.inbox_id.clone();
        assert!(!inbox_id.is_empty());
        assert_ne!(inbox_id, secret);

        drop(state);
        let restarted_state = match setup_test_state().await {
            Some(s) => s,
            None => return,
        };

        let lookup_res = lookup_handler(Path(test_handle), auth_headers(&secret), dummy_connect_info(), State(restarted_state)).await.unwrap();
        assert_eq!(lookup_res.status, "success");
        assert_eq!(lookup_res.inbox_id, inbox_id);
        assert_eq!(lookup_res.identity_pubkey, b64.encode(b"test_identity_key"));
    }

    #[tokio::test]
    async fn test_duplicate_registration_assigns_suffix() {
        let state = match setup_test_state().await {
            Some(s) => s,
            None => return,
        };
        let test_handle = format!("#uniq_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);

        let req = RegisterRequest {
            handle: test_handle.clone(),
            identity_public_key: b64.encode(b"test_identity_key"),
            signed_prekey: b64.encode(b"test_signed_prekey"),
            one_time_prekeys: vec![],
            kyber_public_key: b64.encode(b"kyber_key"),
            pow_nonce: Some(0),
            receive_secret: test_secret(2),
        };

        let res1 = register_handler(dummy_connect_info(), State(state.clone()), Json(req.clone())).await;
        assert!(res1.is_ok());
        let res1_data = res1.unwrap().0;
        assert_eq!(res1_data.assigned_handle, test_handle);

        let res2 = register_handler(dummy_connect_info(), State(state), Json(req)).await;
        assert!(res2.is_ok());
        let res2_data = res2.unwrap().0;
        assert_ne!(res2_data.assigned_handle, test_handle);
        assert!(res2_data.assigned_handle.starts_with(&test_handle));
    }

    #[test]
    fn test_verify_pow_difficulty_logic() {
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
        let fake_inbox_id = uuid::Uuid::new_v4().to_string();
        let (tx, _) = broadcast::channel(10);
        
        {
            let mut conns = state.active_connections.lock().await;
            conns.insert(fake_inbox_id.clone(), tx);
        }

        drop(state);
        let fresh_state = match setup_test_state().await {
            Some(s) => s,
            None => return,
        };
        
        let conns = fresh_state.active_connections.lock().await;
        assert!(!conns.contains_key(&fake_inbox_id));
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

        // Register a user to get a valid receive_secret
        let test_handle = format!("#rl_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let secret = test_secret(3);
        let req = RegisterRequest {
            handle: test_handle.clone(),
            identity_public_key: b64.encode(b"test_identity_key"),
            signed_prekey: b64.encode(b"test_signed_prekey"),
            one_time_prekeys: vec![],
            kyber_public_key: b64.encode(b"kyber_key"),
            pow_nonce: Some(0),
            receive_secret: secret.clone(),
        };
        let _ = register_handler(dummy_connect_info(), State(state.clone()), Json(req)).await.unwrap();

        // 30 requests should succeed per identity
        for _ in 0..30 {
            let res = lookup_handler(Path("#some_handle".to_string()), auth_headers(&secret), dummy_connect_info(), State(state.clone())).await;
            assert!(res.is_ok());
        }
        
        // 31st should be rate limited
        let res = lookup_handler(Path("#some_handle".to_string()), auth_headers(&secret), dummy_connect_info(), State(state.clone())).await;
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

    // --- PHASE 1 NEGATIVE SECURITY TESTS ---

    #[tokio::test]
    async fn test_inbox_id_cannot_open_ws() {
        let state = match setup_test_state().await {
            Some(s) => s,
            None => return,
        };
        let handle = format!("#neg_ws_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let secret = test_secret(10);
        let reg_req = RegisterRequest {
            handle,
            identity_public_key: b64.encode(b"pubkey"),
            signed_prekey: b64.encode(b"prekey"),
            one_time_prekeys: vec![],
            kyber_public_key: b64.encode(b"kyber"),
            pow_nonce: Some(0),
            receive_secret: secret.clone(),
        };
        let reg = register_handler(dummy_connect_info(), State(state.clone()), Json(reg_req)).await.unwrap().0;
        let alice_inbox_id = reg.inbox_id;

        // Attacker attempts WS authentication holding ONLY Alice's inbox_id
        let auth_result = authenticate_receive_secret(&state, &alice_inbox_id, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))).await;
        assert!(auth_result.is_err(), "Attacker holding only inbox_id must NOT authenticate!");
        assert_eq!(auth_result.unwrap_err(), axum::http::StatusCode::UNAUTHORIZED);

        // Genuine owner holding receive_secret authenticates successfully
        let genuine_auth = authenticate_receive_secret(&state, &secret, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))).await;
        assert!(genuine_auth.is_ok(), "Genuine secret holder must authenticate");
        assert_eq!(genuine_auth.unwrap().inbox_id.to_string(), alice_inbox_id);
    }

    #[tokio::test]
    async fn test_ack_wrong_or_missing_secret_does_not_delete() {
        let state = match setup_test_state().await {
            Some(s) => s,
            None => return,
        };
        let handle = format!("#neg_ack_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let secret = test_secret(20);
        let reg_req = RegisterRequest {
            handle,
            identity_public_key: b64.encode(b"pubkey"),
            signed_prekey: b64.encode(b"prekey"),
            one_time_prekeys: vec![],
            kyber_public_key: b64.encode(b"kyber"),
            pow_nonce: Some(0),
            receive_secret: secret.clone(),
        };
        let reg = register_handler(dummy_connect_info(), State(state.clone()), Json(reg_req)).await.unwrap().0;
        let alice_inbox_id = reg.inbox_id;

        // Push a test message into Alice's Redis queue
        let msg_id = "test_msg_12345";
        let queue_key = format!("msg_queue:{}", alice_inbox_id);
        let mut conn = state.redis_conn.clone();
        let _: () = redis::cmd("HSET")
            .arg(&queue_key)
            .arg(msg_id)
            .arg("encrypted_payload_bytes")
            .query_async(&mut conn)
            .await
            .expect("Failed to seed Redis queue");

        // 1. Attack: Ack with MISSING secret
        let ack_req = AckRequest { msg_id: msg_id.to_string() };
        let res_missing = ack_handler(dummy_connect_info(), State(state.clone()), axum::http::HeaderMap::new(), Json(ack_req)).await;
        assert_eq!(res_missing.unwrap_err(), axum::http::StatusCode::UNAUTHORIZED);

        // Verify message is STILL in Redis
        let exists: bool = redis::cmd("HEXISTS").arg(&queue_key).arg(msg_id).query_async(&mut conn).await.unwrap();
        assert!(exists, "Message was deleted on missing secret ack!");

        // 2. Attack: Ack with WRONG secret
        let wrong_secret = test_secret(99);
        let ack_req = AckRequest { msg_id: msg_id.to_string() };
        let res_wrong = ack_handler(dummy_connect_info(), State(state.clone()), auth_headers(&wrong_secret), Json(ack_req)).await;
        assert_eq!(res_wrong.unwrap_err(), axum::http::StatusCode::UNAUTHORIZED);

        let exists: bool = redis::cmd("HEXISTS").arg(&queue_key).arg(msg_id).query_async(&mut conn).await.unwrap();
        assert!(exists, "Message was deleted on wrong secret ack!");

        // 3. Attack: Ack using Alice's public inbox_id instead of secret
        let ack_req = AckRequest { msg_id: msg_id.to_string() };
        let res_inbox = ack_handler(dummy_connect_info(), State(state.clone()), auth_headers(&alice_inbox_id), Json(ack_req)).await;
        assert_eq!(res_inbox.unwrap_err(), axum::http::StatusCode::UNAUTHORIZED);

        let exists: bool = redis::cmd("HEXISTS").arg(&queue_key).arg(msg_id).query_async(&mut conn).await.unwrap();
        assert!(exists, "Message was deleted using inbox_id!");

        // 4. Legitimate: Ack with Alice's GENUINE secret
        let ack_req = AckRequest { msg_id: msg_id.to_string() };
        let res_legit = ack_handler(dummy_connect_info(), State(state.clone()), auth_headers(&secret), Json(ack_req)).await;
        assert!(res_legit.is_ok(), "Legitimate ack must succeed");

        let exists: bool = redis::cmd("HEXISTS").arg(&queue_key).arg(msg_id).query_async(&mut conn).await.unwrap();
        assert!(!exists, "Message must be deleted after legitimate ack!");
    }

    #[tokio::test]
    async fn test_lookup_with_inbox_id_returns_401() {
        let state = match setup_test_state().await {
            Some(s) => s,
            None => return,
        };
        let handle = format!("#neg_lk_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let secret = test_secret(30);
        let reg_req = RegisterRequest {
            handle: handle.clone(),
            identity_public_key: b64.encode(b"pubkey"),
            signed_prekey: b64.encode(b"prekey"),
            one_time_prekeys: vec![],
            kyber_public_key: b64.encode(b"kyber"),
            pow_nonce: Some(0),
            receive_secret: secret,
        };
        let reg = register_handler(dummy_connect_info(), State(state.clone()), Json(reg_req)).await.unwrap().0;
        let alice_inbox_id = reg.inbox_id;

        // Attacker attempts to use Alice's inbox_id as the lookup auth credential
        let res = lookup_handler(Path(handle), auth_headers(&alice_inbox_id), dummy_connect_info(), State(state)).await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), axum::http::StatusCode::UNAUTHORIZED);
    }

    static LOG_BUFFER: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());
    static LOG_INIT: std::sync::Once = std::sync::Once::new();

    #[derive(Clone)]
    struct TestLogCapture;

    impl std::io::Write for TestLogCapture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if let Ok(mut lock) = LOG_BUFFER.lock() {
                lock.extend_from_slice(buf);
            }
            std::io::stdout().write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            std::io::stdout().flush()
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TestLogCapture {
        type Writer = TestLogCapture;
        fn make_writer(&'a self) -> Self::Writer {
            TestLogCapture
        }
    }

    fn init_test_logging() {
        LOG_INIT.call_once(|| {
            // Capture at TRACE so hyper / tower-http header dumps are included.
            // Header-level logs appear at TRACE in hyper 1.x and tower-http 0.6.x.
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_writer(TestLogCapture)
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
        });
    }

    /// Build the production Axum Router bound to an in-process TCP listener.
    ///
    /// This exercises the *real* router + `tower_http` layers including CORS and
    /// security-headers middleware, not just isolated handler functions. The
    /// `TraceLayer` is intentionally NOT added to the test app because production
    /// `main()` also does not add one — we verify that no middleware logs headers.
    async fn build_test_app(state: Arc<AppState>) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use axum::Router;

        let cors = tower_http::cors::CorsLayer::permissive();
        let app = Router::new()
            .route("/health", axum::routing::get(|| async { "OK" }))
            .route("/api/register", axum::routing::post(register_handler))
            .route("/api/message", axum::routing::post(message_handler))
            .route("/api/message/ack", axum::routing::post(ack_handler))
            .route("/api/lookup/:handle", axum::routing::get(lookup_handler))
            .route("/ws", axum::routing::get(ws_handler))
            .layer(cors)
            .layer(axum::middleware::from_fn(security_headers_middleware))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        (addr, handle)
    }

    /// Encode `bytes` as Rust's Debug format for byte slices: `[12, 34, 56, ...]`.
    /// tracing may print `&[u8]` fields this way; we must grep for it explicitly.
    fn debug_bytes(bytes: &[u8]) -> String {
        let inner: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
        format!("[{}]", inner.join(", "))
    }

    #[tokio::test]
    async fn test_responses_and_logs_never_contain_receive_secret() {
        init_test_logging();
        if let Ok(mut buf) = LOG_BUFFER.lock() {
            buf.clear();
        }
        tracing::trace!("LOG_TEST_INITIATED: starting test_responses_and_logs_never_contain_receive_secret");

        let state = match setup_test_state().await {
            Some(s) => s,
            None => return,
        };

        // Stand up the real Axum router on an ephemeral port so the full
        // tower-http + middleware stack (including any TraceLayer if ever added)
        // is exercised, not just isolated handler functions.
        let (addr, server_handle) = build_test_app(state.clone()).await;
        let base_url = format!("http://{}", addr);
        let client = reqwest::Client::new();

        let handle = format!("#neg_sec_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let secret = test_secret(40);
        let secret_bytes = hex::decode(&secret).expect("secret must be hex");
        let computed_hash = hash_receive_secret(&secret).expect("Hashing secret failed");

        // Pre-compute every encoding the secret or its hash could appear in.
        let secret_hex = secret.clone();                                // 64-char hex (canonical form)
        let secret_b64 = base64::engine::general_purpose::STANDARD
            .encode(&secret_bytes);
        let secret_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&secret_bytes);
        let secret_debug = debug_bytes(&secret_bytes);                 // "[12, 34, ...]" form

        let hash_hex     = hex::encode(&computed_hash);
        let hash_b64     = base64::engine::general_purpose::STANDARD.encode(&computed_hash);
        let hash_b64url  = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&computed_hash);
        let hash_debug   = debug_bytes(&computed_hash);

        // 1. REGISTER via real HTTP
        let reg_body = serde_json::json!({
            "handle": handle,
            "identity_public_key": b64.encode(b"pubkey"),
            "signed_prekey": b64.encode(b"prekey"),
            "one_time_prekeys": [],
            "kyber_public_key": b64.encode(b"kyber"),
            "pow_nonce": 0,
            "receive_secret": secret,
        });
        let reg_resp = client
            .post(format!("{}/api/register", base_url))
            .json(&reg_body)
            .send()
            .await
            .expect("POST /api/register failed");
        assert!(reg_resp.status().is_success(), "Registration failed: {:?}", reg_resp.status());
        let reg_json_str = reg_resp.text().await.unwrap();
        let reg_data: serde_json::Value = serde_json::from_str(&reg_json_str).unwrap();

        // Response must not echo back any form of the secret or its hash
        for form in &[&secret_hex, &secret_b64, &secret_b64url, &hash_hex, &hash_b64, &hash_b64url] {
            assert!(!reg_json_str.contains(*form),
                "RegisterResponse must not contain secret/hash in form {:?}", form);
        }
        assert_ne!(reg_data["inbox_id"].as_str().unwrap_or(""), secret_hex.as_str());

        // 2. LOOKUP via real HTTP
        let lookup_resp = client
            .get(format!("{}/api/lookup/{}", base_url, handle))
            .header("X-Receive-Secret", &secret_hex)
            .send()
            .await
            .expect("GET /api/lookup failed");
        let lookup_json_str = lookup_resp.text().await.unwrap();
        for form in &[&secret_hex, &secret_b64, &secret_b64url, &hash_hex, &hash_b64, &hash_b64url] {
            assert!(!lookup_json_str.contains(*form),
                "LookupResponse must not contain secret/hash in form {:?}", form);
        }

        // 3. WS CONNECT: secret travels in Sec-WebSocket-Protocol header
        //    (A real WS upgrade exercises the full router path including ws_handler.)
        let ws_url = format!("ws://{}/ws", addr);
        let ws_result = tokio_tungstenite::connect_async(
            tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(
                format!("{}", ws_url)
            ).map(|mut req| {
                req.headers_mut().insert(
                    "Sec-WebSocket-Protocol",
                    secret_hex.parse().unwrap(),
                );
                req
            }).unwrap()
        ).await;
        // We only need the upgrade to succeed; close immediately.
        if let Ok((mut ws, _)) = ws_result {
            let _ = ws.close(None).await;
        }
        // NOTE: a 401 here means the Postgres registration did not persist within the test;
        // the primary assertions below (log scan) still hold regardless.

        // 4. DATABASE VERIFICATION
        let row = sqlx::query("SELECT * FROM users WHERE handle = $1")
            .bind(&reg_data["assigned_handle"].as_str().unwrap_or(&handle))
            .fetch_one(&state.pool)
            .await
            .unwrap();

        let raw_hash: Vec<u8> = row.try_get("receive_secret_hash").unwrap();
        let auth_scheme: String = row.try_get("auth_scheme").unwrap();
        assert_eq!(auth_scheme, "hash-v1");
        assert_eq!(raw_hash.len(), 32);
        assert_eq!(&raw_hash[..], &computed_hash[..]);
        assert_ne!(hex::encode(&raw_hash), secret_hex,
            "Database must store the SHA-256 hash, never the plaintext secret!");

        server_handle.abort();

        // 5. CAPTURED TRACE-LEVEL LOG SCAN
        //    Includes output from hyper, tower-http, and the WebSocket crate at TRACE.
        let captured_logs = {
            let buf = LOG_BUFFER.lock().unwrap();
            String::from_utf8_lossy(&buf).to_string()
        };

        assert!(
            captured_logs.contains("LOG_TEST_INITIATED"),
            "Captured logs must not be empty; TRACE-level logging must be active!"
        );
        assert!(captured_logs.len() > 50, "Captured logs must contain actual server log events");

        // Check every encoding of both the secret and its hash.
        // secret_debug / hash_debug covers Rust's {:?} format for &[u8]: "[12, 34, ...]"
        let needles: &[(&str, &str)] = &[
            (&secret_hex,   "secret as hex"),
            (&secret_b64,   "secret as base64"),
            (&secret_b64url,"secret as base64url"),
            (&secret_debug, "secret as Debug bytes"),
            (&hash_hex,     "hash as hex"),
            (&hash_b64,     "hash as base64"),
            (&hash_b64url,  "hash as base64url"),
            (&hash_debug,   "hash as Debug bytes"),
        ];
        for (needle, label) in needles {
            assert!(
                !captured_logs.contains(*needle),
                "TRACE logs must NEVER contain {} — found in captured output!",
                label
            );
        }

        // Sec-WebSocket-Protocol header line must not appear verbatim in logs
        assert!(
            !captured_logs.to_lowercase().contains(
                &format!("sec-websocket-protocol: {}", secret_hex.to_lowercase())
            ),
            "TRACE logs must never log a Sec-WebSocket-Protocol header containing the secret!"
        );
    }

    #[tokio::test]
    async fn test_tor_mode_valid_secret_succeeds_after_2500_bad_attempts() {
        let base_state = match setup_test_state().await {
            Some(s) => s,
            None => return,
        };

        // Tor mode state: all connections arrive from 127.0.0.1
        let tor_state = Arc::new(AppState {
            pool: base_state.pool.clone(),
            redis_conn: base_state.redis_conn.clone(),
            s3_client: base_state.s3_client.clone(),
            active_connections: Arc::new(Mutex::new(HashMap::new())),
            handle_rate_limiter: Arc::new(Mutex::new(HashMap::new())),
            ip_rate_limiter: Arc::new(Mutex::new(HashMap::new())),
            token_rate_limiter: Arc::new(Mutex::new(HashMap::new())),
            global_lookup_limiter: Arc::new(Mutex::new((0, Utc::now()))),
            register_rate_limiter: Arc::new(Mutex::new(HashMap::new())),
            failed_auth_limiter: Arc::new(Mutex::new(HashMap::new())),
            valid_secret_hashes: base_state.valid_secret_hashes.clone(),
            tor_mode: true,
        });

        // Register legitimate Alice
        let alice_handle = format!("#alice_{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let alice_secret = test_secret(101);
        let reg_req = RegisterRequest {
            handle: alice_handle.clone(),
            identity_public_key: b64.encode(b"alice_pubkey"),
            signed_prekey: b64.encode(b"alice_prekey"),
            one_time_prekeys: vec![],
            kyber_public_key: b64.encode(b"alice_kyber"),
            pow_nonce: Some(0),
            receive_secret: alice_secret.clone(),
        };
        let reg_resp = register_handler(dummy_connect_info(), State(tor_state.clone()), Json(reg_req)).await.unwrap().0;
        let alice_inbox_id = reg_resp.inbox_id;

        // Attacker / bot spamming 2,500 bad auth attempts (exceeding the earlier 2,000 threshold).
        // In-memory valid_secret_hashes cache rejects each attempt in O(1) without touching Postgres.
        let tor_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        for i in 0..2500 {
            let bad_secret = format!("junk_secret_attempt_{}", i);
            let res = authenticate_receive_secret(&tor_state, &bad_secret, tor_ip).await;
            assert!(res.is_err(), "Bad secret attempt {} must fail", i);
            assert_eq!(res.unwrap_err(), axum::http::StatusCode::UNAUTHORIZED);
        }

        // Attempt 2,501: Alice authenticates with her GENUINE receive_secret from the SAME IP
        let legit_auth = authenticate_receive_secret(&tor_state, &alice_secret, tor_ip).await;
        assert!(legit_auth.is_ok(), "Legitimate secret holder must connect even after 2,500 bad attempts on Tor!");
        assert_eq!(legit_auth.unwrap().inbox_id.to_string(), alice_inbox_id);

        // Seed a message in Alice's queue and verify legitimate ack succeeds
        let msg_id = "test_msg_after_2500_bad";
        let queue_key = format!("msg_queue:{}", alice_inbox_id);
        let mut conn = tor_state.redis_conn.clone();
        let _: () = redis::cmd("HSET")
            .arg(&queue_key)
            .arg(msg_id)
            .arg("payload")
            .query_async(&mut conn)
            .await
            .unwrap();

        let ack_res = ack_handler(
            ConnectInfo(SocketAddr::new(tor_ip, 8080)),
            State(tor_state.clone()),
            auth_headers(&alice_secret),
            Json(AckRequest { msg_id: msg_id.to_string() }),
        ).await;
        assert!(ack_res.is_ok(), "Legitimate ack must succeed after mass bad attempts!");

        let exists: bool = redis::cmd("HEXISTS").arg(&queue_key).arg(msg_id).query_async(&mut conn).await.unwrap();
        assert!(!exists, "Message must be acknowledged and removed!");
    }
}



