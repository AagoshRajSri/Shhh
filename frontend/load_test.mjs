import WebSocket from 'ws';

// ==========================================
// LOAD TEST CONFIGURATION
// ==========================================
const CONCURRENT_USERS = 500; 
const MESSAGES_PER_SECOND_PER_USER = 1; 
const TEST_DURATION_SECONDS = 30; 
// ==========================================

const baseUrl = 'http://localhost:3000';
const users = [];

let metrics = {
    connected: 0,
    messagesSent: 0,
    messagesReceived: 0,
    errors: 0,
    totalLatencyMs: 0
};

async function registerUser(i) {
    const handle = `#loaduser_${i}_${Date.now()}`;
    // Mock the crypto keys to save CPU time during load testing 
    // (The backend doesn't verify the math of the keys during registration, it just stores them)
    const body = {
        handle,
        identity_public_key: 'bW9ja19pZGVudGl0eV9rZXk=', // base64
        signed_prekey: 'bW9ja19zaWduZWRfcHJla2V5',
        one_time_prekeys: [],
        kyber_public_key: 'bW9ja19reWJlcl9rZXk='
    };

    try {
        const res = await fetch(`${baseUrl}/api/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        return { handle, token: data.routing_token };
    } catch (e) {
        metrics.errors++;
        return null;
    }
}

async function run() {
    console.log(`🚀 Starting Load Test: ${CONCURRENT_USERS} Users`);
    console.log(`Phase 1: Registering users...`);
    
    // Register in batches of 50 to respect the 50-connection Postgres pool limit
    for (let i = 0; i < CONCURRENT_USERS; i += 50) {
        const batch = [];
        for (let j = 0; j < 50 && (i + j) < CONCURRENT_USERS; j++) {
            batch.push(registerUser(i + j));
        }
        const results = await Promise.all(batch);
        for (const res of results) {
            if (res) users.push(res);
        }
        process.stdout.write(`\rRegistered ${users.length} / ${CONCURRENT_USERS}`);
    }
    console.log(`\n✅ Registration complete.`);

    console.log(`\nPhase 2: Opening WebSockets...`);
    await new Promise(resolve => {
        let opened = 0;
        for (const user of users) {
            const ws = new WebSocket(`ws://localhost:3000/ws?token=${user.token}`);
            
            ws.on('open', () => {
                metrics.connected++;
                opened++;
                if (opened === users.length) resolve();
            });

            ws.on('message', (data) => {
                try {
                    const msg = JSON.parse(data.toString());
                    if (msg.encrypted_payload) {
                        metrics.messagesReceived++;
                        ws.send(JSON.stringify({ type: "ack", msg_id: msg.msg_id }));
                        
                        const parts = msg.encrypted_payload.split('_');
                        const ts = parseInt(parts[parts.length - 1]);
                        if (ts) {
                            metrics.totalLatencyMs += (Date.now() - ts);
                        }
                    }
                } catch (e) {
                    console.log("RCVD non-JSON:", data.toString());
                }
            });

            ws.on('error', () => { metrics.errors++; });
            ws.on('close', () => { metrics.connected--; });
            
            user.ws = ws;
        }
    });
    console.log(`✅ All ${metrics.connected} WebSockets connected.`);

    console.log(`\nPhase 3: Blasting Messages for ${TEST_DURATION_SECONDS} seconds...`);
    
    const intervalMs = 1000 / MESSAGES_PER_SECOND_PER_USER;
    
    // Start blast
    const intervals = users.map(user => {
        return setInterval(() => {
            // Pick a random recipient
            const recipient = users[Math.floor(Math.random() * users.length)];
            
            const envelope = {
                to_routing_token: recipient.token,
                encrypted_payload: "MOCK_ENCRYPTED_BLOB_" + Date.now()
            };
            
            fetch(`${baseUrl}/api/message`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(envelope)
            }).then(async (res) => {
                if (!res.ok) {
                    const text = await res.text();
                    console.error("HTTP ERROR:", res.status, text);
                    metrics.errors++;
                } else {
                    metrics.messagesSent++;
                }
            }).catch((e) => {
                console.error("FETCH ERR:", e);
                metrics.errors++;
            });
        }, intervalMs);
    });

    // Monitor throughput every second
    let timeRemaining = TEST_DURATION_SECONDS;
    const monitor = setInterval(() => {
        console.log(`[${timeRemaining}s left] Active Conns: ${metrics.connected} | Sent: ${metrics.messagesSent} | Rcvd: ${metrics.messagesReceived} | Errors: ${metrics.errors}`);
        timeRemaining--;
    }, 1000);

    // End test
    setTimeout(() => {
        intervals.forEach(clearInterval);
        clearInterval(monitor);
        
        console.log(`\n🎉 Load Test Complete!`);
        console.log(`=========================`);
        console.log(`Total Users: ${CONCURRENT_USERS}`);
        console.log(`Total Sent:  ${metrics.messagesSent}`);
        console.log(`Total Rcvd:  ${metrics.messagesReceived}`);
        console.log(`Errors:      ${metrics.errors}`);
        const avgLatency = metrics.messagesReceived > 0 ? (metrics.totalLatencyMs / metrics.messagesReceived).toFixed(2) : 0;
        console.log(`Avg Latency: ${avgLatency} ms`);
        const throughput = (metrics.messagesReceived / TEST_DURATION_SECONDS).toFixed(2);
        console.log(`Throughput : ${throughput} msgs/sec`);
        
        // Slight delay to allow final ACKs to process
        setTimeout(() => {
            console.log(`Closing connections...`);
            users.forEach(u => u.ws.close());
            process.exit(0);
        }, 2000);
    }, TEST_DURATION_SECONDS * 1000);
}

run();
