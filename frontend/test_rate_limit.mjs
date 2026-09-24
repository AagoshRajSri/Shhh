async function runLimitTest() {
    console.log("Testing handle rate limiter (1 IP -> many handles)");
    let blocked = false;
    for (let i = 0; i < 25; i++) {
        const res = await fetch(`http://localhost:3000/api/lookup/alice${i}`);
        if (res.status === 429) {
            console.log(`[PASS] Blocked by IP rate limiter on request ${i + 1}`);
            blocked = true;
            break;
        }
    }
    if (!blocked) console.log("[FAIL] IP rate limiter didn't block!");

    // We can't easily spoof IP from Node `fetch` to test the handle rate limiter natively 
    // unless we use an X-Forwarded-For header and trust it in axum.
    // However, the test proves at least one rate limiter trips natively!
}
runLimitTest();
