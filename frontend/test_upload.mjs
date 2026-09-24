import crypto from 'crypto';

async function testLargeUpload() {
  const hash = crypto.randomBytes(32).toString('hex');
  const numParts = 10;
  const partSize = 5 * 1024 * 1024; // 5MB per part

  console.log("Upload 1: Initializing 50MB file in 10 parts...");
  let res = await fetch('http://localhost:3000/api/upload/init', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hash, parts: numParts })
  });
  let initData = await res.json();
  console.log("Init:", initData.status);

  if (initData.status === 'uploading') {
    const etags = [];
    for (let i = 0; i < numParts; i++) {
      const uploadUrl = initData.urls[i];
      console.log(`Uploading chunk ${i+1}/${numParts} to MinIO...`);
      const fileData = crypto.randomBytes(partSize);
      const putRes = await fetch(uploadUrl, {
        method: 'PUT',
        body: fileData
      });
      const eTag = putRes.headers.get('ETag');
      etags.push(eTag);
    }
    
    console.log("Completing multipart upload...");
    const compRes = await fetch('http://localhost:3000/api/upload/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        hash, 
        upload_id: initData.upload_id,
        etags
      })
    });
    console.log("Complete status:", await compRes.json());
  }
}

testLargeUpload();
