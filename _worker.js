// _worker.js
// Usque MASQUE register relay + password login + KV subscription endpoint

const API_ORIGIN = "https://api.cloudflareclient.com";
const API_VERSION = "v0a4471";
const COOKIE_NAME = "usque_session";
const SESSION_TTL = 7 * 24 * 3600; // 7 天有效期（秒）

const CF_HEADERS = {
  "User-Agent": "WARP for Android",
  "CF-Client-Version": "a-6.35-4471",
  "Content-Type": "application/json; charset=UTF-8",
  "Accept": "application/json"
};

/* ---------------- 基础响应 ---------------- */

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extra
    }
  });
}

function htmlResponse(body, status = 200, extra = {}) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extra
    }
  });
}

/* ---------------- 登录 / 会话工具 ---------------- */

function b64urlFromBytes(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hmacSign(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );
  return b64urlFromBytes(new Uint8Array(sig));
}

function safeEqualStr(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

async function makeSessionToken(password) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL;
  const payload = String(exp);
  const sig = await hmacSign(password, payload);
  return `${payload}.${sig}`;
}

function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  const out = {};
  for (const part of header.split(/;\s*/)) {
    if (!part) continue;
    const i = part.indexOf("=");
    if (i === -1) continue;
    out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

async function hasValidSession(request, env) {
  const password = env.ADMIN_PASSWORD;
  if (!password) return false;
  const cookies = parseCookies(request);
  const token = cookies[COOKIE_NAME];
  if (!token) return false;
  const dot = token.lastIndexOf(".");
  if (dot <= 0) return false;
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const exp = Number(payload);
  if (!Number.isFinite(exp)) return false;
  if (exp < Math.floor(Date.now() / 1000)) return false;
  const expected = await hmacSign(password, payload);
  return safeEqualStr(expected, sig);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

function renderLoginPage({ error = "" } = {}) {
  const errBlock = error
    ? `<div class="login-error">${escapeHtml(error)}</div>`
    : "";
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="robots" content="noindex,nofollow">
<title>登录 · Usque MASQUE</title>
<style>
  :root{color-scheme:dark}
  *{box-sizing:border-box}
  body{
    margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;
    font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
    background:radial-gradient(circle at 30% 10%,rgba(48,151,235,.16),transparent 30rem),#071523;
    color:#edf7ff;
  }
  .login-card{
    width:min(400px,100%);padding:30px 26px;border:1px solid #27485f;border-radius:18px;
    background:linear-gradient(180deg,#0c2031,#091a29);
    box-shadow:0 20px 60px rgba(0,0,0,.35);
  }
  .login-card h1{margin:0 0 8px;font-size:22px;letter-spacing:-.02em}
  .login-card p{margin:0 0 20px;color:#88a6b9;font-size:13px;line-height:1.6}
  .login-card label{display:block;margin-bottom:14px}
  .login-card label > span{
    display:block;margin-bottom:7px;color:#c7d9e7;font-size:13px;font-weight:700;
  }
  .login-card input{
    width:100%;background:#071827;border:1px solid #2c5069;color:#edf7ff;
    border-radius:9px;padding:12px 13px;outline:none;font:inherit;
  }
  .login-card input:focus{
    border-color:#62c1ff;box-shadow:0 0 0 3px rgba(98,193,255,.09);
  }
  .login-card button{
    width:100%;padding:12px;border:1px solid #68baff;border-radius:9px;
    background:linear-gradient(135deg,#2495ea,#3f67ec);color:#fff;
    font-weight:800;font-size:14px;cursor:pointer;margin-top:6px;
  }
  .login-card button:hover{filter:brightness(1.06)}
  .login-error{
    margin-bottom:14px;padding:10px 12px;border:1px solid #7a3948;border-radius:9px;
    background:rgba(124,48,65,.16);color:#ffd0d7;font-size:12.5px;line-height:1.5;
  }
  .login-foot{margin-top:16px;color:#6d8ba0;font-size:11px;text-align:center}
</style>
</head>
<body>
<form class="login-card" method="POST" action="/__auth/login" autocomplete="off">
  <h1>🔒 Usque MASQUE</h1>
  <p>此站点受密码保护，请输入访问密码继续。</p>
  ${errBlock}
  <label>
    <span>访问密码</span>
    <input type="password" name="password" autocomplete="current-password" autofocus required>
  </label>
  <button type="submit">登录</button>
  <div class="login-foot">Cookie 会话有效期 7 天</div>
</form>
</body>
</html>`;
}

async function handleLogin(request, env) {
  const password = env.ADMIN_PASSWORD;
  if (!password) {
    return htmlResponse(
      renderLoginPage({ error: "服务端未配置 ADMIN_PASSWORD 环境变量，无法登录。" }),
      500
    );
  }

  const ct = (request.headers.get("Content-Type") || "").toLowerCase();
  let supplied = "";

  try {
    if (ct.includes("application/json")) {
      const body = await request.json();
      supplied = String(body?.password || "");
    } else {
      const fd = await request.formData();
      supplied = String(fd.get("password") || "");
    }
  } catch {
    supplied = "";
  }

  if (!safeEqualStr(supplied, password)) {
    return htmlResponse(
      renderLoginPage({ error: "密码错误，请重试。" }),
      401
    );
  }

  const token = await makeSessionToken(password);
  const cookie =
    `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL}`;

  return new Response(null, {
    status: 303,
    headers: {
      "Location": "/",
      "Set-Cookie": cookie,
      "Cache-Control": "no-store"
    }
  });
}

function handleLogout() {
  return new Response(null, {
    status: 303,
    headers: {
      "Location": "/",
      "Set-Cookie": `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
      "Cache-Control": "no-store"
    }
  });
}

/* ---------------- 订阅端点（KV 优先） ---------------- */

const KV_SUB_YAML = "usque:subscription:yaml";
const KV_SUB_META = "usque:subscription:meta";
const SUB_MAX_BYTES = 2 * 1024 * 1024; // 2MB

async function getSubContent(env) {
  if (env.USQUE_KV) {
    try {
      const fromKv = await env.USQUE_KV.get(KV_SUB_YAML);
      if (fromKv != null && String(fromKv).length > 0) {
        return { content: String(fromKv), source: "kv" };
      }
    } catch (e) {
      // KV 读取失败时回退到环境变量
    }
  }
  if (env.SUB_CONTENT) {
    return { content: String(env.SUB_CONTENT), source: "env" };
  }
  return { content: null, source: "none" };
}

async function getSubMeta(env) {
  if (!env.USQUE_KV) return null;
  try {
    const raw = await env.USQUE_KV.get(KV_SUB_META);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function handleSubscription(request, env) {
  const uuid = String(env.SUB_UUID || "");
  if (!uuid) {
    return json({ message: "订阅未配置（缺少 SUB_UUID 环境变量）" }, 503);
  }

  const { content, source } = await getSubContent(env);

  if (!content) {
    const tip =
      "# Usque MASQUE 订阅端点已就绪\n" +
      "# 当前没有可用内容。\n" +
      "# 请登录管理页 → 生成 Clash 配置 → 点击「推送到在线订阅」。\n" +
      "# 需要绑定 Cloudflare KV（变量名 USQUE_KV），并设置环境变量 SUB_UUID。\n" +
      "# 当前路径: " + new URL(request.url).pathname + "\n" +
      "# KV 绑定: " + (env.USQUE_KV ? "已绑定" : "未绑定") + "\n";
    return new Response(tip, {
      status: 200,
      headers: {
        "Content-Type": "text/yaml; charset=UTF-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff"
      }
    });
  }

  // 配置显示名：域名（Clash Verge 对带引号的 filename 常会把 \" 吃进名称）
  const host = (new URL(request.url).hostname || "").trim() || "usque";
  const safeHost = host.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 64) || "usque";
  // Verge / Meta 推荐：Profile-Title: base64:<标准 base64>
  let titleB64 = "";
  try {
    titleB64 = btoa(unescape(encodeURIComponent(host)));
  } catch {
    titleB64 = btoa(safeHost);
  }
  const headers = {
    "Content-Type": "text/yaml; charset=UTF-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Profile-Update-Interval": "24",
    "Profile-Title": `base64:${titleB64}`,
    // 不使用引号，避免名称变成 \"myque.pages.dev\
    "Content-Disposition": `attachment; filename=${safeHost}`,
    "X-Usque-Sub-Source": source,
    "X-Usque-Profile-Title": host
  };
  return new Response(content, { status: 200, headers });
}

async function handleSubInfo(request, env) {
  const uuid = String(env.SUB_UUID || "");
  const origin = new URL(request.url).origin;
  const { content, source } = await getSubContent(env);
  const meta = await getSubMeta(env);
  return json({
    ok: true,
    uuid: uuid || null,
    url: uuid ? `${origin}/${uuid}` : null,
    has_content: !!content,
    source,
    kv_bound: !!env.USQUE_KV,
    bytes: content ? content.length : 0,
    meta: meta || null
  });
}

async function handleSubSave(request, env) {
  if (!env.USQUE_KV) {
    return json({
      message: "未绑定 Cloudflare KV。请在 Pages 项目设置里绑定 KV 命名空间，变量名必须为 USQUE_KV。"
    }, 503);
  }
  if (!String(env.SUB_UUID || "")) {
    return json({ message: "缺少 SUB_UUID 环境变量，无法生成订阅路径。" }, 503);
  }

  const ct = (request.headers.get("Content-Type") || "").toLowerCase();
  let content = "";
  let note = "";

  try {
    if (ct.includes("application/json")) {
      const text = await request.text();
      if (text.length > SUB_MAX_BYTES + 4096) {
        return json({ message: `请求体过大，上限约 ${SUB_MAX_BYTES} 字节` }, 413);
      }
      const body = JSON.parse(text || "{}");
      content = String(body?.content ?? body?.yaml ?? "");
      note = String(body?.note || "").slice(0, 200);
    } else {
      content = await request.text();
      if (content.length > SUB_MAX_BYTES) {
        return json({ message: `YAML 过大，上限 ${SUB_MAX_BYTES} 字节` }, 413);
      }
    }
  } catch (e) {
    return json({ message: "无法解析请求体：" + String(e?.message || e) }, 400);
  }

  content = String(content || "").trim();
  if (!content) {
    return json({ message: "content / yaml 不能为空" }, 400);
  }
  if (content.length > SUB_MAX_BYTES) {
    return json({ message: `YAML 过大（${content.length} 字节），上限 ${SUB_MAX_BYTES}` }, 413);
  }

  const meta = {
    updated_at: new Date().toISOString(),
    bytes: content.length,
    note: note || "clash",
    profile: "MASQUE-Pro"
  };

  try {
    await env.USQUE_KV.put(KV_SUB_YAML, content);
    await env.USQUE_KV.put(KV_SUB_META, JSON.stringify(meta));
  } catch (e) {
    return json({
      message: "写入 KV 失败：" + String(e?.message || e)
    }, 500);
  }

  const uuid = String(env.SUB_UUID);
  const origin = new URL(request.url).origin;
  return json({
    ok: true,
    message: "订阅内容已更新到 KV",
    url: `${origin}/${uuid}`,
    bytes: content.length,
    meta
  });
}

async function handleSubClear(request, env) {
  if (!env.USQUE_KV) {
    return json({ message: "未绑定 KV（USQUE_KV）" }, 503);
  }
  try {
    await env.USQUE_KV.delete(KV_SUB_YAML);
    await env.USQUE_KV.delete(KV_SUB_META);
  } catch (e) {
    return json({ message: "清除失败：" + String(e?.message || e) }, 500);
  }
  return json({ ok: true, message: "已清除 KV 中的订阅内容" });
}

/* ---------------- 原生 config.json 持久化（KV） ---------------- */

const KV_CONFIG_JSON = "usque:config:json";
const KV_CONFIG_META = "usque:config:meta";
const CONFIG_MAX_BYTES = 256 * 1024; // 256KB，原生 config 很小

async function handleConfigLoad(request, env) {
  if (!env.USQUE_KV) {
    return json({
      ok: false,
      has_config: false,
      kv_bound: false,
      message: "未绑定 KV（USQUE_KV）"
    });
  }
  try {
    const raw = await env.USQUE_KV.get(KV_CONFIG_JSON);
    let meta = null;
    try {
      const m = await env.USQUE_KV.get(KV_CONFIG_META);
      if (m) meta = JSON.parse(m);
    } catch {}
    if (!raw) {
      return json({
        ok: true,
        has_config: false,
        kv_bound: true,
        config: null,
        meta: null
      });
    }
    let config;
    try {
      config = JSON.parse(raw);
    } catch {
      return json({ message: "KV 中的 config 不是合法 JSON" }, 500);
    }
    return json({
      ok: true,
      has_config: true,
      kv_bound: true,
      config,
      meta,
      bytes: raw.length
    });
  } catch (e) {
    return json({ message: "读取 config 失败：" + String(e?.message || e) }, 500);
  }
}

async function handleConfigSave(request, env) {
  if (!env.USQUE_KV) {
    return json({
      message: "未绑定 Cloudflare KV。变量名必须为 USQUE_KV。"
    }, 503);
  }

  let configObj = null;
  let label = "";
  try {
    const text = await request.text();
    if (text.length > CONFIG_MAX_BYTES + 2048) {
      return json({ message: "请求体过大" }, 413);
    }
    const body = JSON.parse(text || "{}");
    // 支持 { config: {...} } 或直接整份 usque config
    if (body && body.config && typeof body.config === "object") {
      configObj = body.config;
      label = String(body.label || body.note || "").slice(0, 120);
    } else if (body && (body.private_key || body.endpoint_pub_key)) {
      configObj = body;
      label = String(body._label || "").slice(0, 120);
      delete configObj._label;
    } else {
      return json({ message: "缺少有效的 config 对象（需要 private_key / endpoint）" }, 400);
    }
  } catch (e) {
    return json({ message: "JSON 无效：" + String(e?.message || e) }, 400);
  }

  if (!configObj.private_key || !configObj.endpoint_pub_key) {
    return json({ message: "config 缺少 private_key 或 endpoint_pub_key" }, 400);
  }
  if (!configObj.endpoint_v4 && !configObj.endpoint_v6 && !configObj.endpoint_h2_v4 && !configObj.endpoint_h2_v6) {
    return json({ message: "config 没有可用 endpoint" }, 400);
  }

  const raw = JSON.stringify(configObj);
  if (raw.length > CONFIG_MAX_BYTES) {
    return json({ message: "config 过大" }, 413);
  }

  const meta = {
    updated_at: new Date().toISOString(),
    bytes: raw.length,
    label: label || "usque-config",
    id: configObj.id || "",
    has_v4: !!configObj.endpoint_v4,
    has_v6: !!configObj.endpoint_v6
  };

  try {
    await env.USQUE_KV.put(KV_CONFIG_JSON, raw);
    await env.USQUE_KV.put(KV_CONFIG_META, JSON.stringify(meta));
  } catch (e) {
    return json({ message: "写入 KV 失败：" + String(e?.message || e) }, 500);
  }

  return json({
    ok: true,
    message: "原生 config.json 已永久保存到 KV",
    meta,
    bytes: raw.length
  });
}

async function handleConfigClear(request, env) {
  if (!env.USQUE_KV) {
    return json({ message: "未绑定 KV（USQUE_KV）" }, 503);
  }
  try {
    await env.USQUE_KV.delete(KV_CONFIG_JSON);
    await env.USQUE_KV.delete(KV_CONFIG_META);
  } catch (e) {
    return json({ message: "清除失败：" + String(e?.message || e) }, 500);
  }
  return json({ ok: true, message: "已清除 KV 中的原生 config.json" });
}

/* ---------------- 前端设置项持久化（KV） ---------------- */

const KV_SETTINGS_JSON = "usque:settings:json";
const SETTINGS_MAX_BYTES = 64 * 1024;

async function handleSettingsLoad(request, env) {
  if (!env.USQUE_KV) {
    return json({ ok: false, has_settings: false, kv_bound: false, settings: null });
  }
  try {
    const raw = await env.USQUE_KV.get(KV_SETTINGS_JSON);
    if (!raw) {
      return json({ ok: true, has_settings: false, kv_bound: true, settings: null });
    }
    const settings = JSON.parse(raw);
    return json({ ok: true, has_settings: true, kv_bound: true, settings, bytes: raw.length });
  } catch (e) {
    return json({ message: "读取设置失败：" + String(e?.message || e) }, 500);
  }
}

async function handleSettingsSave(request, env) {
  if (!env.USQUE_KV) {
    return json({ message: "未绑定 KV（USQUE_KV）" }, 503);
  }
  let settings;
  try {
    const text = await request.text();
    if (text.length > SETTINGS_MAX_BYTES) {
      return json({ message: "设置数据过大" }, 413);
    }
    const body = JSON.parse(text || "{}");
    settings = body.settings != null ? body.settings : body;
    if (!settings || typeof settings !== "object" || Array.isArray(settings)) {
      return json({ message: "settings 必须是对象" }, 400);
    }
  } catch (e) {
    return json({ message: "JSON 无效：" + String(e?.message || e) }, 400);
  }

  const payload = {
    ...settings,
    _saved_at: new Date().toISOString()
  };
  const raw = JSON.stringify(payload);
  try {
    await env.USQUE_KV.put(KV_SETTINGS_JSON, raw);
  } catch (e) {
    return json({ message: "写入失败：" + String(e?.message || e) }, 500);
  }
  return json({ ok: true, message: "设置已保存到 KV", bytes: raw.length, saved_at: payload._saved_at });
}

async function handleSettingsClear(request, env) {
  if (!env.USQUE_KV) {
    return json({ message: "未绑定 KV（USQUE_KV）" }, 503);
  }
  try {
    await env.USQUE_KV.delete(KV_SETTINGS_JSON);
  } catch (e) {
    return json({ message: "清除失败：" + String(e?.message || e) }, 500);
  }
  return json({ ok: true, message: "已清除 KV 中的界面设置" });
}

/* ---------------- 原有 relay 逻辑（保持不变） ---------------- */

function allowedSameOrigin(request) {
  const target = new URL(request.url);
  const origin = request.headers.get("Origin");

  if (origin) {
    try {
      if (new URL(origin).origin !== target.origin) return false;
    } catch {
      return false;
    }
  }

  const site = request.headers.get("Sec-Fetch-Site");
  if (site && site !== "same-origin" && site !== "none") return false;
  return true;
}

async function readSmallJson(request) {
  const type = request.headers.get("Content-Type") || "";
  if (!type.toLowerCase().includes("application/json")) {
    throw new Error("Content-Type 必须为 application/json");
  }

  const text = await request.text();
  if (text.length > 16384) throw new Error("请求体过大");

  try {
    return JSON.parse(text || "{}");
  } catch {
    throw new Error("JSON 格式无效");
  }
}

function validB64(s, max = 4096) {
  return typeof s === "string" &&
    s.length > 0 &&
    s.length <= max &&
    /^[A-Za-z0-9+/]+={0,2}$/.test(s);
}

async function upstreamJson(url, init) {
  let res;
  try {
    res = await fetch(url, init);
  } catch (e) {
    return json({
      message: "无法连接 Cloudflare WARP 上游 API",
      detail: String(e?.message || e)
    }, 502);
  }

  const body = await res.text();
  const retryAfterHeader = res.headers.get("Retry-After");
  const retryAfter = Math.max(
    0,
    Number.parseInt(retryAfterHeader || "0", 10) || 0
  );

  const is1015 =
    res.status === 429 ||
    /\b1015\b/i.test(body) ||
    /rate\s*limit/i.test(body);

  if (is1015) {
    const wait = retryAfter || 30;
    return json({
      error: "rate_limited",
      code: 1015,
      retry_after: wait,
      message: `Cloudflare WARP 注册接口触发限流，请等待 ${wait} 秒后再试。不要连续点击注册。`
    }, 429, {
      "Retry-After": String(wait)
    });
  }

  const headers = {
    "Content-Type": res.headers.get("Content-Type") || "application/json; charset=UTF-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  };
  if (retryAfterHeader) headers["Retry-After"] = retryAfterHeader;

  return new Response(body, {
    status: res.status,
    headers
  });
}

async function relayRegister(request) {
  if (!allowedSameOrigin(request)) {
    return json({ message: "跨站请求已拒绝" }, 403);
  }

  if (request.headers.get("X-Usque-Intent") !== "single-register") {
    return json({ message: "缺少注册意图标记" }, 400);
  }

  let b;
  try {
    b = await readSmallJson(request);
  } catch (e) {
    return json({ message: e.message }, 400);
  }

  if (!validB64(b.key, 256)) {
    return json({ message: "key 无效" }, 400);
  }

  if (!/^[0-9a-f]{16}$/i.test(String(b.serial_number || ""))) {
    return json({ message: "serial_number 无效" }, 400);
  }

  if (typeof b.tos !== "string" || b.tos.length < 20 || b.tos.length > 64) {
    return json({ message: "tos 时间无效" }, 400);
  }

  const payload = {
    key: b.key,
    install_id: "",
    fcm_token: "",
    tos: b.tos,
    model: "PC",
    serial_number: b.serial_number,
    os_version: "",
    key_type: "curve25519",
    tunnel_type: "wireguard",
    locale: "en_US"
  };

  return upstreamJson(`${API_ORIGIN}/${API_VERSION}/reg`, {
    method: "POST",
    headers: CF_HEADERS,
    body: JSON.stringify(payload),
    redirect: "manual"
  });
}

async function relayEnroll(request) {
  if (!allowedSameOrigin(request)) {
    return json({ message: "跨站请求已拒绝" }, 403);
  }

  if (request.headers.get("X-Usque-Intent") !== "single-register") {
    return json({ message: "缺少注册意图标记" }, 400);
  }

  let b;
  try {
    b = await readSmallJson(request);
  } catch (e) {
    return json({ message: e.message }, 400);
  }

  const id = String(b.id || "");
  const token = String(b.token || "");
  const publicKey = String(b.public_key || "");
  const name = String(b.name || "Web-Usque").slice(0, 64);

  if (!/^[A-Za-z0-9._:-]{4,256}$/.test(id)) {
    return json({ message: "device id 无效" }, 400);
  }

  if (token.length < 8 || token.length > 4096 || /[\r\n]/.test(token)) {
    return json({ message: "token 无效" }, 400);
  }

  if (!validB64(publicKey, 4096)) {
    return json({ message: "P-256 public_key 无效" }, 400);
  }

  const payload = {
    key: publicKey,
    key_type: "secp256r1",
    tunnel_type: "masque",
    name
  };

  return upstreamJson(
    `${API_ORIGIN}/${API_VERSION}/reg/${encodeURIComponent(id)}`,
    {
      method: "PATCH",
      headers: {
        ...CF_HEADERS,
        "Authorization": `Bearer ${token}`
      },
      body: JSON.stringify(payload),
      redirect: "manual"
    }
  );
}

/* ---------------- 主入口 ---------------- */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    const subUuid = String(env.SUB_UUID || "");

    // 1) 订阅端点：/{SUB_UUID} 不校验登录
    if (subUuid && path === `/${subUuid}`) {
      return handleSubscription(request, env);
    }

    // 2) 登录 / 登出端点
    if (path === "/__auth/login") {
      if (request.method !== "POST") {
        return htmlResponse(renderLoginPage(), 200);
      }
      return handleLogin(request, env);
    }
    if (path === "/__auth/logout") {
      return handleLogout();
    }

    // 3) 其余路径都要登录
    const authed = await hasValidSession(request, env);
    if (!authed) {
      if (!env.ADMIN_PASSWORD) {
        return htmlResponse(
          renderLoginPage({
            error: "服务端未配置 ADMIN_PASSWORD 环境变量，无法登录。"
          }),
          500
        );
      }
      return htmlResponse(renderLoginPage(), 401);
    }

    // 4) 已登录：原有 API 转发
    if (path === "/api/health") {
      return json({
        ok: true,
        service: "usque-register-relay",
        worker: "running",
        kv_bound: !!env.USQUE_KV,
        sub_uuid_configured: !!String(env.SUB_UUID || "")
      });
    }

    // 在线订阅管理（需登录）
    if (path === "/api/sub/info") {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return json({ message: "Method Not Allowed" }, 405, { "Allow": "GET" });
      }
      return handleSubInfo(request, env);
    }

    if (path === "/api/sub/save") {
      if (request.method !== "POST" && request.method !== "PUT") {
        return json({ message: "Method Not Allowed" }, 405, { "Allow": "POST, PUT" });
      }
      return handleSubSave(request, env);
    }

    if (path === "/api/sub/clear") {
      if (request.method !== "POST" && request.method !== "DELETE") {
        return json({ message: "Method Not Allowed" }, 405, { "Allow": "POST, DELETE" });
      }
      return handleSubClear(request, env);
    }

    // 原生 config.json 持久化（需登录）
    if (path === "/api/config/load") {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return json({ message: "Method Not Allowed" }, 405, { "Allow": "GET" });
      }
      return handleConfigLoad(request, env);
    }

    if (path === "/api/config/save") {
      if (request.method !== "POST" && request.method !== "PUT") {
        return json({ message: "Method Not Allowed" }, 405, { "Allow": "POST, PUT" });
      }
      return handleConfigSave(request, env);
    }

    if (path === "/api/config/clear") {
      if (request.method !== "POST" && request.method !== "DELETE") {
        return json({ message: "Method Not Allowed" }, 405, { "Allow": "POST, DELETE" });
      }
      return handleConfigClear(request, env);
    }

    if (path === "/api/settings/load") {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return json({ message: "Method Not Allowed" }, 405, { "Allow": "GET" });
      }
      return handleSettingsLoad(request, env);
    }

    if (path === "/api/settings/save") {
      if (request.method !== "POST" && request.method !== "PUT") {
        return json({ message: "Method Not Allowed" }, 405, { "Allow": "POST, PUT" });
      }
      return handleSettingsSave(request, env);
    }

    if (path === "/api/settings/clear") {
      if (request.method !== "POST" && request.method !== "DELETE") {
        return json({ message: "Method Not Allowed" }, 405, { "Allow": "POST, DELETE" });
      }
      return handleSettingsClear(request, env);
    }

    if (path === "/api/warp/register") {
      if (request.method !== "POST") {
        return json({ message: "Method Not Allowed" }, 405, { "Allow": "POST" });
      }
      return relayRegister(request);
    }

    if (path === "/api/warp/enroll") {
      if (request.method !== "POST") {
        return json({ message: "Method Not Allowed" }, 405, { "Allow": "POST" });
      }
      return relayEnroll(request);
    }

    if (path.startsWith("/api/")) {
      return json({ message: "API Not Found" }, 404);
    }

    // 5) 其余：静态资源（index.html / app.js / style.css ...）
    return env.ASSETS.fetch(request);
  }
};