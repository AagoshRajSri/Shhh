import WebSocket from 'ws';

async function runLoadTest() {
    const clients = [];
    const NUM_CLIENTS = 500;
    
    console.log(`Starting load test with ${NUM_CLIENTS} concurrent websockets...`);
    
    // Connect 500 websockets
    const connectStart = performance.now();
    for (let i = 0; i < NUM_CLIENTS; i++) {
        // use fake UUIDs for token
        const fakeToken = `test-token-${i}`;
        const ws = new WebSocket(`ws://localhost:3000/ws?token=${fakeToken}`);
        clients.push(new Promise((resolve) => {
            ws.on('open', () => resolve(ws));
            ws.on('error', () => resolve(ws)); // Ignore errors for load test
        }));
    }
    
    const sockets = await Promise.all(clients);
    const connectEnd = performance.now();
    console.log(`Connected ${NUM_CLIENTS} websockets in ${connectEnd - connectStart} ms`);
    console.log(`Average connection latency: ${(connectEnd - connectStart) / NUM_CLIENTS} ms`);
    
    // Send 10 messages per socket concurrently to trigger lock contention in tx channel map
    console.log(`Broadcasting messages...`);
    const broadcastStart = performance.now();
    const promises = [];
    
    for (const ws of sockets) {
        if (ws.readyState === WebSocket.OPEN) {
            for (let j = 0; j < 10; j++) {
                promises.push(new Promise((resolve) => {
                    ws.send(JSON.stringify({
                        to_routing_token: `test-token-${j}`,
                        encrypted_payload: "dummy"
                    }), () => resolve());
                }));
            }
        }
    }
    
    await Promise.all(promises);
    const broadcastEnd = performance.now();
    console.log(`Broadcasted ${promises.length} messages in ${broadcastEnd - broadcastStart} ms`);
    console.log(`Average message processing latency: ${(broadcastEnd - broadcastStart) / promises.length} ms`);
    
    for (const ws of sockets) {
        if (ws.readyState === WebSocket.OPEN) {
            ws.close();
        }
    }
}

runLoadTest().catch(console.error);
