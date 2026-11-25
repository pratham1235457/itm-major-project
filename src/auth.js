const { randomBytes, scrypt: scryptCallback, timingSafeEqual, createHash } = require("crypto");
const { promisify } = require("util");

const scrypt = promisify(scryptCallback);
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const MAX_LOGIN_FAILURES = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function createAuth({ userId, email, password }) {
  if (typeof password !== "string" || password.length === 0) {
    throw new Error("AUTH_PASSWORD must be set before starting the server.");
  }

  const salt = randomBytes(16);
  const passwordHashPromise = scrypt(password, salt, 64);
  const sessions = new Map();
  const failures = new Map();
  const cookieName = "prompt_detector_session";
  const cookieOptions = {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: SESSION_TTL_MS
  };

  function getToken(req) {
    const cookieHeader = req.headers.cookie || "";
    const cookie = cookieHeader.split(";").map((part) => part.trim())
      .find((part) => part.startsWith(`${cookieName}=`));
    return cookie ? cookie.slice(cookieName.length + 1) : "";
  }

  function attachSession(req, res, next) {
    const now = Date.now();
    for (const [hash, session] of sessions) {
      if (session.expiresAt <= now) sessions.delete(hash);
    }

    const token = getToken(req);
    const tokenHash = token ? createHash("sha256").update(token).digest("hex") : "";
    const session = sessions.get(tokenHash);
    req.session = session && session.expiresAt > now ? session : null;
    next();
  }

  async function login(identifier, candidatePassword, address) {
    const now = Date.now();
    const attempt = failures.get(address);
    if (attempt && attempt.blockedUntil > now) return { ok: false, limited: true };
    const count = attempt && attempt.windowEndsAt > now ? attempt.count + 1 : 1;
    const windowEndsAt = attempt && attempt.windowEndsAt > now
      ? attempt.windowEndsAt
      : now + LOGIN_WINDOW_MS;
    failures.set(address, {
      count,
      windowEndsAt,
      blockedUntil: count >= MAX_LOGIN_FAILURES ? now + LOGIN_WINDOW_MS : 0
    });

    const [passwordHash, candidateHash] = await Promise.all([
      passwordHashPromise,
      scrypt(candidatePassword, salt, 64)
    ]);
    const identifierMatches = safeEqual(identifier.trim().toLowerCase(), userId.toLowerCase())
      || safeEqual(identifier.trim().toLowerCase(), email.toLowerCase());
    const passwordMatches = timingSafeEqual(passwordHash, candidateHash);

    if (!identifierMatches || !passwordMatches) {
      return { ok: false, limited: count >= MAX_LOGIN_FAILURES };
    }

    failures.delete(address);
    const token = randomBytes(32).toString("base64url");
    const tokenHash = createHash("sha256").update(token).digest("hex");
    sessions.set(tokenHash, { expiresAt: now + SESSION_TTL_MS });
    return { ok: true, token };
  }

  function logout(req) {
    const token = getToken(req);
    if (token) sessions.delete(createHash("sha256").update(token).digest("hex"));
  }

  return { userId, email, cookieName, cookieOptions, attachSession, login, logout };
}

module.exports = { createAuth };
