const baseUrl = 'http://localhost:3000';
let passed = 0;
let total = 0;

async function test(name, fn) {
    total++;
    try {
        const result = await fn();
        if (result.pass) {
            passed++;
            console.log(`✅ PASS: ${name} ${result.detail ? `(${result.detail})` : ''}`);
        } else {
            console.error(`❌ FAIL: ${name} - ${result.detail}`);
        }
    } catch (e) {
        console.error(`❌ ERR : ${name} - ${e.message}`);
    }
}

async function run() {
    console.log('\n=== LIVE API TEST RESULTS ===\n');

    // 1. Health
    await test('GET /health', async () => {
        const res = await fetch(`${baseUrl}/health`);
        const text = await res.text();
        return { pass: text === 'OK', detail: text };
    });

    const handle = `#test_${Date.now()}`;
    const body = {
        handle,
        identity_public_key: 'dGVzdGtleQ==',
        signed_prekey: 'dGVzdHNpZ25lZA==',
        one_time_prekeys: [],
        kyber_public_key: 'a3liZXI='
    };
    let routingToken;

    // 2. Register
    await test('POST /api/register', async () => {
        const res = await fetch(`${baseUrl}/api/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await res.json();
        routingToken = data.routing_token;
        return { pass: data.status === 'success' && !!routingToken, detail: `token=${routingToken}` };
    });

    // 3. Duplicate
    await test('POST /api/register (duplicate)', async () => {
        const res = await fetch(`${baseUrl}/api/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        return { pass: res.status === 409, detail: `Status: ${res.status}` };
    });

    // 4. Lookup
    await test('GET /api/lookup (exists)', async () => {
        const res = await fetch(`${baseUrl}/api/lookup/${encodeURIComponent(handle)}`);
        const data = await res.json();
        return { pass: data.routing_token === routingToken, detail: `token_match=${data.routing_token === routingToken}` };
    });

    // 5. Ghost
    await test('GET /api/lookup (ghost/anti-enum)', async () => {
        const res = await fetch(`${baseUrl}/api/lookup/%23ghost_xyz`);
        const data = await res.json();
        return { pass: res.status === 200 && data.status === 'success', detail: `Fake data returned 200` };
    });

    // 6. Rate Limit
    await test('GET /api/lookup (rate limit 429)', async () => {
        let hit = false;
        let on = 0;
        const rlHandle = `#rl_${Date.now()}`;
        for(let i=1; i<=25; i++) {
            const res = await fetch(`${baseUrl}/api/lookup/${encodeURIComponent(rlHandle)}`);
            if (res.status === 429) {
                hit = true;
                on = i;
                break;
            }
        }
        return { pass: hit, detail: hit ? `429 on request #${on}` : 'Never hit 429' };
    });

    // 7. Message
    await test('POST /api/message (envelope)', async () => {
        if (!routingToken) throw new Error('No routing token');
        const res = await fetch(`${baseUrl}/api/message`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ to_routing_token: routingToken, encrypted_payload: 'test' })
        });
        const data = await res.json();
        return { pass: data.status === 'queued', detail: data.status };
    });

    console.log(`\nSCORE: ${passed} / ${total} tests passed`);
}

run();
