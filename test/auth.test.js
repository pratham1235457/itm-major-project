const assert = require("node:assert/strict");
const { after, before, test } = require("node:test");

process.env.AUTH_PASSWORD = "test-only-password";
process.env.AUTH_USER_ID = "test-user";
process.env.AUTH_EMAIL = "test@example.com";
const app = require("../server");

let server;
let baseUrl;

before(async () => {
  server = app.listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  if (server) await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

test("protects the app and analysis API until login, then supports logout", async () => {
  const unauthenticatedPage = await fetch(baseUrl);
  assert.equal(unauthenticatedPage.status, 200);
  assert.match(await unauthenticatedPage.text(), /User ID or email/);

  const deniedAnalysis = await fetch(`${baseUrl}/api/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ prompt: "ordinary text" })
  });
  assert.equal(deniedAnalysis.status, 401);

  const invalidLogin = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ identifier: "test-user", password: "wrong-password" })
  });
  assert.equal(invalidLogin.status, 401);

  const login = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ identifier: "test@example.com", password: "test-only-password" })
  });
  assert.equal(login.status, 200);
  const cookie = login.headers.get("set-cookie").split(";")[0];

  const protectedPage = await fetch(baseUrl, { headers: { Cookie: cookie } });
  assert.equal(protectedPage.status, 200);
  assert.match(await protectedPage.text(), /Prompt Injection Detector/);

  const allowedAnalysis = await fetch(`${baseUrl}/api/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookie },
    body: JSON.stringify({ prompt: "ordinary text" })
  });
  assert.equal(allowedAnalysis.status, 200);

  const logout = await fetch(`${baseUrl}/api/auth/logout`, {
    method: "POST",
    headers: { Cookie: cookie }
  });
  assert.equal(logout.status, 204);

  const deniedAfterLogout = await fetch(`${baseUrl}/api/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookie },
    body: JSON.stringify({ prompt: "ordinary text" })
  });
  assert.equal(deniedAfterLogout.status, 401);

  for (let attempt = 1; attempt <= 5; attempt += 1) {
    const failedLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ identifier: "test-user", password: "wrong-password" })
    });
    assert.equal(failedLogin.status, attempt === 5 ? 429 : 401);
  }

  const rateLimitedLogin = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ identifier: "test-user", password: "test-only-password" })
  });
  assert.equal(rateLimitedLogin.status, 429);
});
