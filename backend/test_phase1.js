const crypto = require('crypto');

async function testPhase1() {
  console.log("Testing Rate Limiting & Shape Identicality...");
  
  // 1. Hammer /api/lookup/:handle
  let statusCodes = {};
  for(let i = 0; i < 25; i++) {
    const res = await fetch(`http://localhost:3000/api/lookup/%23fake_${i}`);
    statusCodes[res.status] = (statusCodes[res.status] || 0) + 1;
  }
  console.log("Lookup status codes after hammering:", statusCodes);
  
  // 2. Shape Identicality
  const regRes = await fetch('http://localhost:3000/api/register', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      handle: '#test_real',
      identity_public_key: Buffer.from('test').toString('base64'),
      signed_prekey: 'test',
      one_time_prekeys: [],
      kyber_public_key: 'test'
    })
  });
  
  const waitRes = await new Promise(resolve => setTimeout(resolve, 11000)); // wait 11s for rate limit to reset
  
  const realRes = await fetch('http://localhost:3000/api/lookup/%23test_real');
  const realData = await realRes.json();
  
  const fakeRes = await fetch('http://localhost:3000/api/lookup/%23test_fake');
  const fakeData = await fakeRes.json();
  
  console.log("Real lookup keys:", Object.keys(realData).sort());
  console.log("Fake lookup keys:", Object.keys(fakeData).sort());
  
  console.log("Real Data Shape:", {
      statusType: typeof realData.status,
      tokenType: typeof realData.routing_token,
      tokenLength: realData.routing_token.length,
      pubkeyType: typeof realData.identity_pubkey
  });
  console.log("Fake Data Shape:", {
      statusType: typeof fakeData.status,
      tokenType: typeof fakeData.routing_token,
      tokenLength: fakeData.routing_token.length,
      pubkeyType: typeof fakeData.identity_pubkey
  });

}

testPhase1().catch(console.error);
