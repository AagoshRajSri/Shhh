use sqlx::postgres::PgPoolOptions;
use tokio;

#[tokio::main]
async fn main() {
    let db_conn_string = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://shhhchat:password@localhost:5432/shhh".to_string());
    
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_conn_string)
        .await
        .expect("Failed to connect");

    // Insert dummy data
    sqlx::query("INSERT INTO users (handle, identity_pubkey, signed_prekey, created_week) VALUES ('bob', '\\x00', '\\x00', CURRENT_DATE) ON CONFLICT DO NOTHING;")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO users (handle, identity_pubkey, signed_prekey, created_week) VALUES ('alice', '\\x00', '\\x00', CURRENT_DATE) ON CONFLICT DO NOTHING;")
        .execute(&pool).await.unwrap();

    let rows: Vec<(String,)> = sqlx::query_as("EXPLAIN ANALYZE SELECT identity_pubkey FROM users WHERE handle = 'alice';")
        .fetch_all(&pool)
        .await
        .unwrap();

    println!("--- EXPLAIN ANALYZE OUTPUT ---");
    for (row,) in rows {
        println!("{}", row);
    }
}
