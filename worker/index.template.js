const APP_HTML = __APP_HTML__;
const DATA_REPO = "year-compass-private-data";
const DATA_PATH = "year-compass.json";
const GITHUB_API = "https://api.github.com";
const GITHUB_PAGES_ORIGIN = "https://bbbym.github.io";

const json = (body, status = 200, origin = "") => new Response(JSON.stringify(body), {
  status,
  headers: {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...(origin === GITHUB_PAGES_ORIGIN ? { "access-control-allow-origin": origin, "vary": "Origin" } : {})
  }
});

const b64url = bytes => btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
const fromB64url = value => Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((value.length + 3) % 4)), c => c.charCodeAt(0));
const utf8ToBase64 = value => {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 32768) binary += String.fromCharCode(...bytes.subarray(i, i + 32768));
  return btoa(binary);
};
const base64ToUtf8 = value => new TextDecoder().decode(Uint8Array.from(atob(value.replace(/\s/g, "")), c => c.charCodeAt(0)));

async function secretKey(secret) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return crypto.subtle.importKey("raw", digest, "AES-GCM", false, ["encrypt", "decrypt"]);
}
async function seal(value, secret) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await secretKey(secret), new TextEncoder().encode(JSON.stringify(value)));
  return `${b64url(iv)}.${b64url(new Uint8Array(encrypted))}`;
}
async function unseal(token, secret) {
  const [iv, payload] = String(token || "").split(".");
  if (!iv || !payload) throw new Error("Invalid session");
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64url(iv) }, await secretKey(secret), fromB64url(payload));
  const value = JSON.parse(new TextDecoder().decode(decrypted));
  if (value.exp && Date.now() > value.exp) throw new Error("Session expired");
  return value;
}

function safeReturnTo(value, requestUrl) {
  try {
    const url = new URL(value || requestUrl.origin, requestUrl.origin);
    const sameSite = url.origin === requestUrl.origin;
    const githubPage = url.origin === GITHUB_PAGES_ORIGIN && url.pathname.startsWith("/year-compass-journal/");
    return sameSite || githubPage ? `${url.origin}${url.pathname}${url.search}` : `${requestUrl.origin}/`;
  } catch {
    return `${requestUrl.origin}/`;
  }
}

async function github(token, path, options = {}) {
  return fetch(`${GITHUB_API}${path}`, {
    ...options,
    headers: {
      "accept": "application/vnd.github+json",
      "authorization": `Bearer ${token}`,
      "x-github-api-version": "2022-11-28",
      "user-agent": "year-compass-journal",
      ...(options.body ? { "content-type": "application/json" } : {}),
      ...(options.headers || {})
    }
  });
}

async function authenticated(request, env) {
  const header = request.headers.get("authorization") || "";
  if (!header.startsWith("Bearer ")) throw new Error("Not signed in");
  return unseal(header.slice(7), env.SESSION_SECRET);
}

async function githubUser(token) {
  const response = await github(token, "/user");
  if (!response.ok) throw new Error("GitHub session expired");
  return response.json();
}

async function readData(token, login) {
  const response = await github(token, `/repos/${encodeURIComponent(login)}/${DATA_REPO}/contents/${DATA_PATH}`);
  if (response.status === 404) return { data: null, sha: "" };
  if (!response.ok) throw new Error("Unable to read the private data repository");
  const file = await response.json();
  const envelope = JSON.parse(base64ToUtf8(file.content));
  return { data: envelope.data || envelope, updatedAt: envelope.updatedAt || null, sha: file.sha };
}

async function ensureRepository(token, login) {
  const existing = await github(token, `/repos/${encodeURIComponent(login)}/${DATA_REPO}`);
  if (existing.ok) return;
  throw new Error("The Year Compass GitHub App is not installed on the private data repository");
}

async function writeData(token, login, data, expectedSha) {
  await ensureRepository(token, login);
  const current = await readData(token, login);
  if (current.sha && expectedSha && current.sha !== expectedSha) return { conflict: true, ...current };
  const envelope = { updatedAt: new Date().toISOString(), data };
  const body = { message: "Sync Year Compass data", content: utf8ToBase64(JSON.stringify(envelope)), ...(current.sha ? { sha: current.sha } : {}) };
  const response = await github(token, `/repos/${encodeURIComponent(login)}/${DATA_REPO}/contents/${DATA_PATH}`, { method: "PUT", body: JSON.stringify(body) });
  if (!response.ok) throw new Error("Unable to save the private journal data");
  const result = await response.json();
  return { sha: result.content?.sha || "", updatedAt: envelope.updatedAt };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("origin") || "";
    if (request.method === "OPTIONS" && url.pathname.startsWith("/api/")) return new Response(null, { status: 204, headers: { "access-control-allow-origin": origin === GITHUB_PAGES_ORIGIN ? origin : url.origin, "access-control-allow-methods": "GET, PUT, OPTIONS", "access-control-allow-headers": "authorization, content-type", "access-control-max-age": "86400", "vary": "Origin" } });
    try {
      if (url.pathname === "/auth/login") {
        if (!env.GITHUB_CLIENT_ID || !env.SESSION_SECRET) return json({ error: "GitHub login is not configured" }, 503, origin);
        const returnTo = safeReturnTo(url.searchParams.get("return_to"), url);
        const state = await seal({ returnTo, exp: Date.now() + 10 * 60 * 1000 }, env.SESSION_SECRET);
        const target = new URL("https://github.com/login/oauth/authorize");
        target.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
        target.searchParams.set("state", state);
        return Response.redirect(target, 302);
      }
      if (url.pathname === "/auth/callback") {
        const state = await unseal(url.searchParams.get("state"), env.SESSION_SECRET);
        const exchange = await fetch("https://github.com/login/oauth/access_token", { method: "POST", headers: { "accept": "application/json", "content-type": "application/json" }, body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code: url.searchParams.get("code") }) });
        const result = await exchange.json();
        if (!result.access_token) throw new Error("GitHub authorization was not completed");
        const session = await seal({ gh: result.access_token, exp: Date.now() + 180 * 24 * 60 * 60 * 1000 }, env.SESSION_SECRET);
        return Response.redirect(`${state.returnTo}#sync_token=${encodeURIComponent(session)}`, 302);
      }
      if (url.pathname === "/api/sync") {
        const session = await authenticated(request, env);
        const user = await githubUser(session.gh);
        if (request.method === "GET") {
          const stored = await readData(session.gh, user.login);
          return json({ user: { login: user.login, avatarUrl: user.avatar_url }, ...stored }, 200, origin);
        }
        if (request.method === "PUT") {
          const input = await request.json();
          if (!input || typeof input.data !== "object") return json({ error: "Invalid journal data" }, 400, origin);
          const saved = await writeData(session.gh, user.login, input.data, input.sha || "");
          if (saved.conflict) return json({ error: "A newer cloud copy exists. Press Sync now to load it.", ...saved }, 409, origin);
          return json(saved, 200, origin);
        }
        return json({ error: "Method not allowed" }, 405, origin);
      }
      if (request.method === "GET") return new Response(APP_HTML, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-cache" } });
      return new Response("Not found", { status: 404 });
    } catch (error) {
      const status = /signed in|session|authorization/i.test(error.message) ? 401 : 500;
      return json({ error: error.message || "Unexpected error" }, status, origin);
    }
  }
};
