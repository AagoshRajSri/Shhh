# Shhh

**Shhh** is a zero-knowledge, end-to-end encrypted messaging application. It ensures that only you and your intended recipient can read your messages. The server acts purely as a blind relay and holds no cryptographic capability to impersonate users or decrypt traffic.

## Features
- **End-to-End Encryption:** Double Ratchet ECIES with AES-GCM and ephemeral ECDH (X25519).
- **Zero-Knowledge Identity:** Sender authentication via independently verified ECDSA P-256 signatures. Provides a mechanism to detect server-side impersonation, when used.
- **Robust Replay Protection:** Per-message UUID nonce deduplication with a strict 7-day TTL window (synchronized securely across browser tabs via Web Locks API).
- **Encrypted Media:** Client-side convergent encryption (ChaCha20-Poly1305) for attachments, chunked securely to a self-hosted S3-compatible backend (MinIO).
- **Ephemeral Rate Limiting:** IP-based and handle-based limiters to prevent global and targeted enumeration attacks.

## Architecture
- **Frontend:** React, TypeScript, Tailwind CSS, Vite. Cryptography is handled natively via the Web Crypto API.
- **Backend:** Rust, Axum, Tokio. Fast, memory-safe, and asynchronous WebSocket relay.
- **Storage:** 
  - **PostgreSQL:** For persisting public keys and routing identities.
  - **Redis:** For the offline message queue (7-day TTL).
  - **MinIO:** For encrypted media attachment blobs.

### Deployment & Scaling Constraints
**Note:** The current backend architecture utilizes in-memory `HashMap` structures for WebSocket connection mapping and rate-limiting. This design explicitly constrains deployment to a **single backend instance**. Running multiple load-balanced instances of the backend will result in fragmented connection states (users routed to different instances will be unable to communicate) and bypassed rate limits. To scale horizontally beyond a single process, the connection map and rate limiters must first be migrated to Redis.

## Prerequisites
- Docker & Docker Compose
- Rust (Cargo) & `dotenvy`
- Node.js & npm

## Getting Started

### 1. Environment Setup
Clone the repository and set up your environment variables:
```bash
cp .env.example .env
```
*Edit the `.env` file to include your secure passwords.* 

### 2. Infrastructure
Start the PostgreSQL database, Redis, and MinIO storage containers:
```bash
docker-compose up -d
```

### 3. Backend (Rust)
Navigate to the backend directory and run the server:
```bash
cd backend
cargo run
```
The relay API and WebSocket will listen on `ws://localhost:3000`.

### 4. Frontend (React)
Navigate to the frontend directory, install dependencies, and start the development server:
```bash
cd frontend
npm install
npm run dev
```
Open your browser to `http://localhost:5173`.

## Security Model
Shhh is built on the principle of **Trust-On-First-Use (TOFU)** augmented with out-of-band verification. 

Inside an active chat, click on the remote user's handle to reveal the **Safety Number**. Compare this 60-digit fingerprint with your contact over a secure, out-of-band channel (e.g., in person or a trusted video call). If the numbers match, you are guaranteed that no Man-In-The-Middle (MITM) attack or server-side key impersonation has occurred.
