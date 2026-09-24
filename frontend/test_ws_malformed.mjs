import WebSocket from 'ws';

async function testWS() {
    console.log("Connecting to WS...");
    const ws = new WebSocket('ws://localhost:3000/ws');
    
    ws.on('open', () => {
        console.log("Connected. Sending initial valid lookup handshake...");
        ws.send(JSON.stringify({ type: 'lookup_response', sender: 'bob' }));
        
        setTimeout(() => {
            console.log("Sending MALFORMED JSON...");
            ws.send("{ garbage: true, [[");
            
            setTimeout(() => {
                console.log("Sending oversized text frame (10MB)...");
                ws.send("A".repeat(10 * 1024 * 1024));
                
                setTimeout(() => {
                    console.log("Test finished. Closing.");
                    ws.close();
                }, 1000);
            }, 1000);
        }, 1000);
    });

    ws.on('message', (msg) => {
        console.log("Received:", msg.toString());
    });

    ws.on('error', (err) => {
        console.error("WS Error:", err);
    });
    
    ws.on('close', (code, reason) => {
        console.log("WS Closed:", code, reason.toString());
    });
}

testWS();
