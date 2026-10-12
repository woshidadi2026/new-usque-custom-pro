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

function isSubFresh(meta) {
  if (!meta || !meta.updated_at) return false;
  const t = Date.parse(meta.updated_at);
  if (!Number.isFinite(t)) return false;
  return t + SUB_TTL_MS - SUB_SKEW_MS > Date.now();
}

async function loadOuterConfig(env) {
  if (!env.USQUE_KV) return null;
  try {
    const raw = await env.USQUE_KV.get(KV_CONFIG_JSON);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function loadInnerConfig(env) {
  if (!env.USQUE_KV) return null;
  try {
    const raw = await env.USQUE_KV.get(KV_CONFIG_INNER_JSON);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function loadUiSettings(env) {
  if (!env.USQUE_KV) return null;
  try {
    const raw = await env.USQUE_KV.get(KV_SETTINGS_JSON);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * 服务端自动重建订阅 YAML（方案 A）
 * 类似第一份 ensureConfig：有新鲜缓存直接用；过期则用 KV 中的 config + settings 重建。
 */
async function ensureSubscriptionYaml(env, { force = false } = {}) {
  if (!env.USQUE_KV) {
    return { content: null, source: "none", rebuilt: false, error: "未绑定 KV" };
  }

  const meta = await getSubMeta(env);
  let content = null;
  try {
    content = await env.USQUE_KV.get(KV_SUB_YAML);
  } catch {}

  if (!force && content && isSubFresh(meta)) {
    return { content: String(content), source: "kv", rebuilt: false, meta };
  }

  // 无外层 config 时无法自动生成
  const outer = await loadOuterConfig(env);
  if (!outer || !outer.private_key) {
    if (content) {
      // 有旧内容则继续用，并标注
      return {
        content: String(content),
        source: "kv-stale",
        rebuilt: false,
        meta,
        error: "缺少外层 config，无法自动重建（请先注册）"
      };
    }
    return {
      content: null,
      source: "none",
      rebuilt: false,
      error: "缺少外层 config.json，请先登录管理页完成注册"
    };
  }

  // 并发锁：90 秒内不重复重建
  try {
    const lock = await env.USQUE_KV.get(KV_SUB_LOCK);
    if (lock && !force && Date.now() - Number(lock) < 90000) {
      if (content) {
        return { content: String(content), source: "kv-locked", rebuilt: false, meta };
      }
    } else {
      await env.USQUE_KV.put(KV_SUB_LOCK, String(Date.now()), { expirationTtl: 120 });
    }
  } catch {}

  try {
    const inner = await loadInnerConfig(env);
    const settings = await loadUiSettings(env);
    const built = buildClashServer(outer, inner, settings);
    if (!built.yaml || built.yaml.length > SUB_MAX_BYTES_BUILD) {
      throw new Error("生成的 YAML 无效或过大");
    }
    const newMeta = {
      updated_at: new Date().toISOString(),
      bytes: built.yaml.length,
      note: `auto-rebuild · ${built.nodes}nodes` + (built.mom ? ` + ${built.mom}MoM` : "") +
        (built.freeCountries?.length ? ` · free:${built.freeCountries.join("+")}` : " · warp-only"),
      profile: "MASQUE-Pro",
      auto: true,
      nodes: built.nodes,
      mom: built.mom || 0,
      expires_at: new Date(Date.now() + SUB_TTL_MS).toISOString()
    };
    await env.USQUE_KV.put(KV_SUB_YAML, built.yaml);
    await env.USQUE_KV.put(KV_SUB_META, JSON.stringify(newMeta));
    return { content: built.yaml, source: "auto-rebuild", rebuilt: true, meta: newMeta };
  } catch (e) {
    // 重建失败：有旧内容则返回旧内容
    if (content) {
      return {
        content: String(content),
        source: "kv-fallback",
        rebuilt: false,
        meta,
        error: String(e?.message || e)
      };
    }
    return {
      content: null,
      source: "none",
      rebuilt: false,
      error: String(e?.message || e)
    };
  } finally {
    try {
      await env.USQUE_KV.delete(KV_SUB_LOCK);
    } catch {}
  }
}

function subscriptionResponseHeaders(request, sourceTag) {
  const host = (new URL(request.url).hostname || "").trim() || "usque";
  const safeHost = host.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 64) || "usque";
  let titleB64 = "";
  try {
    titleB64 = btoa(unescape(encodeURIComponent(host)));
  } catch {
    titleB64 = btoa(safeHost);
  }
  return {
    "Content-Type": "text/yaml; charset=UTF-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Profile-Update-Interval": "4",
    "Profile-Title": `base64:${titleB64}`,
    "Content-Disposition": `inline; filename=${safeHost}`,
    "X-Usque-Sub-Source": sourceTag || "kv",
    "X-Usque-Profile-Title": host
  };
}

async function handleSubscription(request, env) {
  const uuid = String(env.SUB_UUID || "");
  if (!uuid) {
    return json({ message: "订阅未配置（缺少 SUB_UUID 环境变量）" }, 503);
  }

  // 方案 A：订阅被拉取时自动 ensure（过期则用 KV config+settings 重建）
  let result;
  try {
    result = await ensureSubscriptionYaml(env, { force: false });
  } catch (e) {
    result = { content: null, source: "none", error: String(e?.message || e) };
  }

  if (!result.content) {
    const tip =
      "# Usque MASQUE 订阅端点已就绪\n" +
      "# 当前没有可用内容。\n" +
      "# 请登录管理页完成「一键注册」，保存 config 到 KV 后：\n" +
      "#   · 客户端刷新本订阅链接会自动生成 Clash（方案 A）\n" +
      "#   · 或手动点「推送当前 Clash 到订阅」\n" +
      "# 需要绑定 Cloudflare KV（变量名 USQUE_KV），并设置环境变量 SUB_UUID。\n" +
      "# 当前路径: " + new URL(request.url).pathname + "\n" +
      "# KV 绑定: " + (env.USQUE_KV ? "已绑定" : "未绑定") + "\n" +
      (result.error ? "# 错误: " + result.error + "\n" : "");
    return new Response(tip, {
      status: 200,
      headers: {
        "Content-Type": "text/yaml; charset=UTF-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff"
      }
    });
  }

  const headers = subscriptionResponseHeaders(request, result.source);
  if (result.rebuilt) headers["X-Usque-Rebuilt"] = "1";
  if (result.error) headers["X-Usque-Rebuild-Error"] = String(result.error).slice(0, 200);
  return new Response(result.content, { status: 200, headers });
}

async function handleSubInfo(request, env) {
  const uuid = String(env.SUB_UUID || "");
  const origin = new URL(request.url).origin;
  const { content, source } = await getSubContent(env);
  const meta = await getSubMeta(env);
  const outer = await loadOuterConfig(env);
  const fresh = isSubFresh(meta);
  return json({
    ok: true,
    uuid: uuid || null,
    url: uuid ? `${origin}/${uuid}` : null,
    has_content: !!content,
    source,
    kv_bound: !!env.USQUE_KV,
    bytes: content ? content.length : 0,
    meta: meta || null,
    auto_rebuild: true,
    sub_fresh: fresh,
    sub_ttl_hours: SUB_TTL_MS / 3600000,
    has_outer_config: !!(outer && outer.private_key),
    expires_at: meta?.expires_at || null
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


/* ---------------- 内层 MoM config.json 持久化（KV） ---------------- */

const KV_CONFIG_INNER_JSON = "usque:config:inner:json";
const KV_CONFIG_INNER_META = "usque:config:inner:meta";

async function handleConfigInnerLoad(request, env) {
  if (!env.USQUE_KV) {
    return json({
      ok: false,
      has_config: false,
      kv_bound: false,
      message: "未绑定 KV（USQUE_KV）"
    });
  }
  try {
    const raw = await env.USQUE_KV.get(KV_CONFIG_INNER_JSON);
    let meta = null;
    try {
      const m = await env.USQUE_KV.get(KV_CONFIG_INNER_META);
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
      return json({ message: "KV 中的内层 config 不是合法 JSON" }, 500);
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
    return json({ message: "读取内层 config 失败：" + String(e?.message || e) }, 500);
  }
}

async function handleConfigInnerSave(request, env) {
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
    if (body && body.config && typeof body.config === "object") {
      configObj = body.config;
      label = String(body.label || body.note || "").slice(0, 120);
    } else if (body && (body.private_key || body.endpoint_pub_key)) {
      configObj = body;
      label = String(body._label || "").slice(0, 120);
      delete configObj._label;
    } else {
      return json({ message: "缺少有效的内层 config 对象（需要 private_key / endpoint）" }, 400);
    }
  } catch (e) {
    return json({ message: "JSON 无效：" + String(e?.message || e) }, 400);
  }

  if (!configObj.private_key || !configObj.endpoint_pub_key) {
    return json({ message: "内层 config 缺少 private_key 或 endpoint_pub_key" }, 400);
  }
  if (!configObj.endpoint_v4 && !configObj.endpoint_v6 && !configObj.endpoint_h2_v4 && !configObj.endpoint_h2_v6) {
    return json({ message: "内层 config 没有可用 endpoint" }, 400);
  }

  const raw = JSON.stringify(configObj);
  if (raw.length > CONFIG_MAX_BYTES) {
    return json({ message: "内层 config 过大" }, 413);
  }

  const meta = {
    updated_at: new Date().toISOString(),
    bytes: raw.length,
    label: label || "usque-config-inner-mom",
    id: configObj.id || "",
    role: "inner",
    has_v4: !!configObj.endpoint_v4,
    has_v6: !!configObj.endpoint_v6
  };

  try {
    await env.USQUE_KV.put(KV_CONFIG_INNER_JSON, raw);
    await env.USQUE_KV.put(KV_CONFIG_INNER_META, JSON.stringify(meta));
  } catch (e) {
    return json({ message: "写入内层 KV 失败：" + String(e?.message || e) }, 500);
  }

  return json({
    ok: true,
    message: "内层 MoM config.json 已永久保存到 KV",
    meta,
    bytes: raw.length
  });
}

async function handleConfigInnerClear(request, env) {
  if (!env.USQUE_KV) {
    return json({ message: "未绑定 KV（USQUE_KV）" }, 503);
  }
  try {
    await env.USQUE_KV.delete(KV_CONFIG_INNER_JSON);
    await env.USQUE_KV.delete(KV_CONFIG_INNER_META);
  } catch (e) {
    return json({ message: "清除内层失败：" + String(e?.message || e) }, 500);
  }
  return json({ ok: true, message: "已清除 KV 中的内层 MoM config.json" });
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


/* ==================== Server-side Clash builder (Scheme A) ==================== */
/* Pure port of app.js buildClash — no DOM; takes (source, sourceInner, uiSettings) */

const SUB_TTL_MS = 4 * 3600 * 1000;      // 与 Opera 版类似：4 小时后重建
const SUB_SKEW_MS = 10 * 60 * 1000;     // 提前 10 分钟视为过期
const KV_SUB_LOCK = "usque:subscription:lock";
const SUB_MAX_BYTES_BUILD = 2 * 1024 * 1024;

const ENDPOINTS_S = {
  cf198: "162.159.198.2",
  cf198a: "162.159.198.1",
  cf199: "162.159.199.2",
  "v6-103": "2606:4700:103::2",
  "v6-103a": "2606:4700:103::1",
  "v6-104": "2606:4700:104::2",
  "v6-104a": "2606:4700:104::1",
  bestcf0: "masque.bestcf.eu.cc",
  bestcf1: "masque1.bestcf.eu.cc",
  bestcf2: "masque2.bestcf.eu.cc",
  legacy198: "162.159.198.1",
  legacy199: "162.159.199.1"
};

const DNS_PRESETS_S = {
  "cf-google-dual": ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888"],
  "cf-dual": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
  cf1: ["1.1.1.1"],
  google8: ["8.8.8.8"],
  quad9: ["9.9.9.9"],
  "cf-google": ["1.1.1.1", "8.8.8.8"],
  "cf-quad9": ["1.1.1.1", "9.9.9.9"],
  "cf-pair": ["1.1.1.1", "1.0.0.1"],
  triple: ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
  "cf-backup": ["1.0.0.1"],
  "google-backup": ["8.8.4.4"],
  "quad9-backup": ["149.112.112.112"],
  "cf-v6": ["2606:4700:4700::1111"],
  "google-v6": ["2001:4860:4860::8888"]
};

const CLASH_DOMAIN_RULESETS_S = [
  ["bilibili", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/bilibili.mrs"],
  ["cn", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.mrs"],
  ["category-ai-!cn", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ai-!cn.mrs"],
  ["youtube", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/youtube.mrs"],
  ["netflix", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/netflix.mrs"],
  ["disney", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/disney.mrs"],
  ["spotify", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/spotify.mrs"],
  ["tiktok", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/tiktok.mrs"],
  ["primevideo", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/primevideo.mrs"],
  ["hbo", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/hbo.mrs"],
  ["emby", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-emby.mrs"],
  ["telegram", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/telegram.mrs"],
  ["github", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/github.mrs"],
  ["microsoft", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/microsoft.mrs"],
  ["apple", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/apple.mrs"],
  ["cloudflare", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cloudflare.mrs"],
  ["geolocation-!cn", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/geolocation-!cn.mrs"],
  ["category-ads-all", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ads-all.mrs"],
  ["anti-ad", "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-clash.yaml"]
];

const CLASH_IP_RULESETS_S = [
  ["private_ip", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo-lite/geoip/private.mrs"],
  ["netflix_ip", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo-lite/geoip/netflix.mrs"],
  ["telegram_ip", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/telegram.mrs"],
  ["cloudflare_ip", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cloudflare.mrs"],
  ["cn_ip", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo-lite/geoip/cn.mrs"],
  ["ad_ip", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/ad.mrs"]
];

const FREE_COUNTRY_META_S = {
  US: { flag: "🇺🇸", name: "美国" },
  JP: { flag: "🇯🇵", name: "日本" },
  SG: { flag: "🇸🇬", name: "新加坡" },
  HK: { flag: "🇭🇰", name: "香港" },
  TW: { flag: "🇹🇼", name: "台湾" },
  KR: { flag: "🇰🇷", name: "韩国" }
};

const DEFAULT_UI_SETTINGS = {
  freeEgressEnabled: { t: "c", v: true },
  freeUseWarp: { t: "c", v: true },
  freeScope: { t: "v", v: "ai-streaming" },
  freeProtocolMode: { t: "v", v: "stable" },
  freeUS: { t: "c", v: true },
  freeJP: { t: "c", v: true },
  freeSG: { t: "c", v: true },
  freeHK: { t: "c", v: false },
  freeTW: { t: "c", v: false },
  freeKR: { t: "c", v: false },
  customIpRoutingEnabled: { t: "c", v: false },
  customIpRoutingRules: { t: "v", v: "" },
  endpointPreset: { t: "v", v: "auto-curated" },
  customEndpoint: { t: "v", v: "" },
  portPreset: { t: "v", v: "recommended" },
  customPort: { t: "v", v: "443" },
  sniPreset: { t: "v", v: "speed.cloudflare.com" },
  customSni: { t: "v", v: "" },
  dnsPreset: { t: "v", v: "cf-google-dual" },
  customDns: { t: "v", v: "" },
  innerIpMode: { t: "v", v: "dual" },
  customInner4: { t: "v", v: "" },
  customInner6: { t: "v", v: "" },
  networkMode: { t: "v", v: "quic" },
  stackMode: { t: "v", v: "auto" },
  ccMode: { t: "v", v: "bbr3" },
  outerCc: { t: "v", v: "bbr" },
  bbrProfile: { t: "v", v: "aggressive" },
  mtuPreset: { t: "v", v: "1280" },
  customMtu: { t: "v", v: "1280" },
  handshakeTimeout: { t: "v", v: "0" },
  ruleMode: { t: "v", v: "smart" },
  healthUrl: { t: "v", v: "http://cp.cloudflare.com/generate_204" },
  healthInterval: { t: "v", v: "300" },
  healthTolerance: { t: "v", v: "30" },
  aiHealthMode: { t: "v", v: "chatgpt" },
  enableControllerApi: { t: "c", v: true },
  controllerUrl: { t: "v", v: "http://127.0.0.1:9090" },
  controllerSecret: { t: "v", v: "" },
  nodeTag: { t: "v", v: "CDN" },
  profileName: { t: "v", v: "MASQUE-Pro" },
  nodeCountMode: { t: "v", v: "13" },
  customNodeCount: { t: "v", v: "100" },
  nodeBuildMode: { t: "v", v: "balanced" },
  extraEndpoints: { t: "v", v: "" },
  nodeNaming: { t: "v", v: "detail" },
  udpForward: { t: "c", v: true },
  remoteDns: { t: "c", v: true },
  autoSelect: { t: "c", v: true },
  showIcons: { t: "c", v: true },
  adBlock: { t: "c", v: true },
  includeTestEndpoints: { t: "c", v: true },
  dedupeNodes: { t: "c", v: true },
  h2ExtendedPool: { t: "c", v: true }
};

function sv(ui, id, fallback) {
  const item = ui && ui[id];
  if (!item) return fallback;
  if (item.t === "c") return !!item.v;
  return item.v == null ? fallback : item.v;
}

function qS(v) {
  return JSON.stringify(String(v ?? ""));
}
function boolS(v) {
  return v ? "true" : "false";
}
function uniqS(a) {
  return [...new Set((a || []).filter(Boolean))];
}
function pemBodyS(v) {
  return String(v || "")
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "")
    .trim();
}
function cidr4S(v) {
  if (!v) return "";
  return String(v).includes("/") ? String(v) : String(v) + "/32";
}
function cidr6S(v) {
  if (!v) return "";
  return String(v).includes("/") ? String(v) : String(v) + "/128";
}

function mergeUiSettings(raw) {
  const out = { ...DEFAULT_UI_SETTINGS };
  if (raw && typeof raw === "object") {
    for (const [k, v] of Object.entries(raw)) {
      if (k.startsWith("_")) continue;
      if (v && typeof v === "object" && ("t" in v || "v" in v)) out[k] = v;
    }
  }
  return out;
}

function optsFromUi(ui, source) {
  const freeCountries = uniqS([
    sv(ui, "freeUS", true) ? "US" : "",
    sv(ui, "freeJP", true) ? "JP" : "",
    sv(ui, "freeSG", true) ? "SG" : "",
    sv(ui, "freeHK", false) ? "HK" : "",
    sv(ui, "freeTW", false) ? "TW" : "",
    sv(ui, "freeKR", false) ? "KR" : ""
  ]);
  const sniPreset = String(sv(ui, "sniPreset", "speed.cloudflare.com"));
  const sni =
    sniPreset === "custom"
      ? String(sv(ui, "customSni", "") || "speed.cloudflare.com").trim()
      : sniPreset;
  const dnsPreset = String(sv(ui, "dnsPreset", "cf-google-dual"));
  let dns;
  if (dnsPreset === "custom") {
    dns = uniqS(String(sv(ui, "customDns", "")).split(",").map((x) => x.trim()));
  } else {
    dns = DNS_PRESETS_S[dnsPreset] || ["1.1.1.1"];
  }
  const mtuPreset = String(sv(ui, "mtuPreset", "1280"));
  const mtu =
    mtuPreset === "custom"
      ? Number(sv(ui, "customMtu", 1280)) || 1280
      : Number(mtuPreset) || 1280;
  return {
    sni,
    dns,
    mtu,
    network: String(sv(ui, "networkMode", "quic")),
    stack: String(sv(ui, "stackMode", "auto")),
    cc: String(sv(ui, "ccMode", "bbr3")),
    outerCc: String(sv(ui, "outerCc", "bbr") || ""),
    bbrProfile: String(sv(ui, "bbrProfile", "aggressive")),
    handshake: Number(sv(ui, "handshakeTimeout", 0)) || 0,
    udp: !!sv(ui, "udpForward", true),
    remoteDns: !!sv(ui, "remoteDns", true),
    autoSelect: !!sv(ui, "autoSelect", true),
    icons: !!sv(ui, "showIcons", true),
    adBlock: !!sv(ui, "adBlock", true),
    ruleMode: String(sv(ui, "ruleMode", "smart")),
    healthUrl: String(sv(ui, "healthUrl", "http://cp.cloudflare.com/generate_204")),
    healthInterval: Number(sv(ui, "healthInterval", 300)) || 300,
    tolerance: Number(sv(ui, "healthTolerance", 30)) || 30,
    aiHealth: String(sv(ui, "aiHealthMode", "chatgpt")),
    enableControllerApi: !!sv(ui, "enableControllerApi", true),
    controllerUrl: String(sv(ui, "controllerUrl", "http://127.0.0.1:9090")).trim(),
    controllerSecret: String(sv(ui, "controllerSecret", "")),
    freeEnabled: !!sv(ui, "freeEgressEnabled", true),
    freeUseWarp: !!sv(ui, "freeUseWarp", true),
    freeScope: String(sv(ui, "freeScope", "ai-streaming")),
    freeProtocolMode: String(sv(ui, "freeProtocolMode", "stable")),
    freeCountries,
    profile: String(sv(ui, "profileName", "MASQUE-Pro") || "MASQUE-Pro").trim(),
    nodeTag: String(sv(ui, "nodeTag", "CDN") || "CDN").trim(),
    nodeNaming: String(sv(ui, "nodeNaming", "detail")),
    endpointPreset: String(sv(ui, "endpointPreset", "auto-curated")),
    customEndpoint: String(sv(ui, "customEndpoint", "")).trim(),
    portPreset: String(sv(ui, "portPreset", "recommended")),
    customPort: Number(sv(ui, "customPort", 443)) || 443,
    nodeCountMode: String(sv(ui, "nodeCountMode", "13")),
    customNodeCount: Number(sv(ui, "customNodeCount", 100)) || 100,
    nodeBuildMode: String(sv(ui, "nodeBuildMode", "balanced")),
    extraEndpoints: String(sv(ui, "extraEndpoints", "")),
    includeTestEndpoints: !!sv(ui, "includeTestEndpoints", true),
    dedupeNodes: sv(ui, "dedupeNodes", true) !== false,
    h2ExtendedPool: !!sv(ui, "h2ExtendedPool", true),
    innerIpMode: String(sv(ui, "innerIpMode", "dual")),
    customInner4: String(sv(ui, "customInner4", "")).trim(),
    customInner6: String(sv(ui, "customInner6", "")).trim(),
    source
  };
}

function extraEndpointListS(o) {
  return uniqS(
    String(o.extraEndpoints || "")
      .split(/[\s,，;；]+/)
      .map((x) => x.trim())
  );
}

function endpointListS(o) {
  const p = o.endpointPreset;
  const tests = o.includeTestEndpoints;
  const extra = extraEndpointListS(o);
  const source = o.source;
  let list = [];
  if (p === "custom") list = [o.customEndpoint];
  else if (p === "source-auto") list = [source?.endpoint_v4, source?.endpoint_v6];
  else if (p === "auto-v4") {
    list = [source?.endpoint_v4, ENDPOINTS_S.cf198a, ENDPOINTS_S.cf198, ENDPOINTS_S.cf199];
  } else if (p === "auto-v6") {
    list = [
      source?.endpoint_v6,
      ENDPOINTS_S["v6-103a"],
      ENDPOINTS_S["v6-103"],
      ENDPOINTS_S["v6-104a"],
      ENDPOINTS_S["v6-104"]
    ];
  } else if (p === "auto-curated") {
    list = [
      source?.endpoint_v4,
      source?.endpoint_v6,
      ENDPOINTS_S.cf198a,
      ENDPOINTS_S.cf198,
      ENDPOINTS_S["v6-103a"],
      ENDPOINTS_S["v6-103"],
      ENDPOINTS_S["v6-104a"],
      ENDPOINTS_S["v6-104"]
    ];
    if (tests)
      list.push(ENDPOINTS_S.cf199, ENDPOINTS_S.bestcf0, ENDPOINTS_S.bestcf1, ENDPOINTS_S.bestcf2);
  } else {
    list = [ENDPOINTS_S[p]];
  }
  return uniqS([...list, ...extra]);
}

function portListS(o) {
  const p = o.portPreset;
  if (p === "recommended") return [500, 4500, 8095, 443];
  if (p === "all") return [443, 500, 1701, 4500, 4443, 8095, 8443];
  if (p === "custom") return [Math.max(1, Math.min(65535, o.customPort || 443))];
  return [Number(p) || 443];
}

function curatedPairsS(o) {
  const pairs = [
    ["162.159.198.1", 443],
    ["162.159.198.1", 500],
    ["162.159.198.2", 443],
    ["162.159.198.2", 500],
    ["162.159.198.2", 4500],
    ["162.159.198.2", 8095],
    ["2606:4700:103::1", 443],
    ["2606:4700:103::2", 4500],
    ["2606:4700:104::1", 500],
    ["2606:4700:104::2", 443]
  ];
  if (o.includeTestEndpoints) {
    pairs.push(
      ["162.159.199.2", 443],
      ["masque.bestcf.eu.cc", 500],
      ["masque1.bestcf.eu.cc", 500]
    );
  }
  return pairs;
}

function targetNodeCountS(o) {
  const mode = o.nodeCountMode || "13";
  if (mode === "custom") return Math.max(1, Math.min(500, o.customNodeCount || 100));
  return Math.max(1, Number(mode) || 13);
}

function dedupePairsS(pairs) {
  const seen = new Set(),
    out = [];
  for (const pair of pairs) {
    const server = String(pair?.[0] || "").trim();
    const port = Number(pair?.[1] || 0);
    if (!server || !port) continue;
    const key = `${server.toLowerCase()}|${port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push([server, port]);
  }
  return out;
}

function stableShuffleS(arr, o) {
  const out = [...arr];
  let seed = 2166136261 >>> 0;
  const material = String(o.profile || "MASQUE-Pro") + "|" + String(o.nodeTag || "CDN");
  for (let i = 0; i < material.length; i++) {
    seed ^= material.charCodeAt(i);
    seed = Math.imul(seed, 16777619) >>> 0;
  }
  for (let i = out.length - 1; i > 0; i--) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const j = seed % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

function expandedPortListS(o) {
  const p = o.portPreset;
  const target = targetNodeCountS(o);
  if (p === "recommended" && target > 13) return [443, 500, 1701, 4500, 4443, 8095, 8443];
  return portListS(o);
}

function h2Ipv4EndpointsS(limit = 508) {
  const out = [];
  for (const prefix of ["162.159.198", "162.159.199"]) {
    for (let host = 1; host <= 254; host++) {
      out.push(`${prefix}.${host}`);
      if (out.length >= limit) return out;
    }
  }
  return out;
}

function h2ConnectionPairsS(o, target, build) {
  const ports = expandedPortListS(o);
  const source = o.source;
  const sourceH2 = uniqS([source?.endpoint_h2_v4, source?.endpoint_v4]);
  let endpoints = o.h2ExtendedPool
    ? uniqS([...sourceH2, ...h2Ipv4EndpointsS(508), ...extraEndpointListS(o)])
    : uniqS([...sourceH2, ...extraEndpointListS(o)]);
  let pairs = [];
  if (build === "balanced") {
    for (const port of ports) for (const endpoint of endpoints) pairs.push([endpoint, port]);
  } else {
    for (const endpoint of endpoints) for (const port of ports) pairs.push([endpoint, port]);
  }
  pairs = dedupePairsS(pairs);
  if (build === "shuffle") pairs = stableShuffleS(pairs, o);
  return pairs.slice(0, target);
}

function connectionPairsS(o) {
  const ep = o.endpointPreset;
  const pp = o.portPreset;
  const net = o.network;
  const build = o.nodeBuildMode || "balanced";
  const target = targetNodeCountS(o);
  if (net === "h2") return h2ConnectionPairsS(o, target, build);
  let pairs = [];
  if (ep === "auto-curated" && pp === "recommended") pairs.push(...curatedPairsS(o));
  if (target > pairs.length || build === "full" || build === "shuffle") {
    const eps = endpointListS(o);
    const ports = expandedPortListS(o);
    const expanded = [];
    if (build === "balanced") {
      for (const port of ports) for (const endpoint of eps) expanded.push([endpoint, port]);
    } else {
      for (const endpoint of eps) for (const port of ports) expanded.push([endpoint, port]);
    }
    pairs.push(...expanded);
  }
  if (o.dedupeNodes !== false) pairs = dedupePairsS(pairs);
  if (build === "shuffle") pairs = stableShuffleS(pairs, o);
  return pairs.slice(0, target);
}

function nodeNameS(server, port, i, o) {
  const tag = o.nodeTag || "CDN";
  const mode = o.nodeNaming || "detail";
  if (mode === "index") return `${tag}-MASQUE-${String(i + 1).padStart(2, "0")}`;
  if (mode === "short") return `${server}:${port}`;
  return `${tag} | ${server} | ${port}`;
}

function innerIpsS(o) {
  const mode = o.innerIpMode;
  const source = o.source;
  if (mode === "custom")
    return { v4: cidr4S(o.customInner4), v6: cidr6S(o.customInner6) };
  return {
    v4: mode === "v6" ? "" : cidr4S(source?.ipv4 || ""),
    v6: mode === "v4" ? "" : cidr6S(source?.ipv6 || "")
  };
}

function makeNodeS(a, name, server, port, o, cfg, dialerProxy) {
  const use = cfg || o.source;
  if (!use) throw new Error("缺少 MASQUE config");
  const ips = cfg
    ? { v4: cidr4S(cfg.ipv4 || ""), v6: cidr6S(cfg.ipv6 || "") }
    : innerIpsS(o);
  const udp = o.network === "h3-l4proxy" ? false : o.udp;
  a.push(
    `  - name: ${qS(name)}`,
    "    type: masque",
    `    server: ${qS(server)}`,
    `    port: ${Number(port)}`,
    `    private-key: ${qS(use.private_key)}`,
    `    public-key: ${qS(pemBodyS(use.endpoint_pub_key))}`
  );
  if (dialerProxy) a.push(`    dialer-proxy: ${qS(dialerProxy)}`);
  if (ips.v4) a.push(`    ip: ${qS(ips.v4)}`);
  if (ips.v6) a.push(`    ipv6: ${qS(ips.v6)}`);
  a.push(`    mtu: ${o.mtu}`, `    udp: ${boolS(udp)}`, `    sni: ${qS(o.sni)}`);
  if (o.network !== "quic") a.push(`    network: ${o.network}`);
  a.push("    ip-stack:", `      mode: ${o.stack}`, `      congestion-controller: ${o.cc}`);
  if (o.remoteDns) {
    a.push("    remote-dns-resolve: true", "    dns:");
    for (const d of o.dns) a.push(`      - ${qS(d)}`);
  }
  if (o.outerCc) {
    a.push(`    congestion-controller: ${o.outerCc}`);
    if (o.outerCc === "bbr") a.push(`    bbr-profile: ${qS(o.bbrProfile)}`);
  }
  if (o.handshake) a.push(`    handshake-timeout: ${o.handshake}`);
}

/** MoM 节点：与外层共用同一套节点数量 / Endpoint×Port 生成逻辑 */
function momConnectionPairsS(o) {
  // 直接复用 connectionPairsS()，使「节点数量模式」「端口」「端点」「生成策略」等高级设置同时作用于 MoM
  return connectionPairsS(o);
}

function momNodeNameS(server, port, i, o) {
  const tag = o.nodeTag || "CDN";
  return `MoM-${tag}-${String(i + 1).padStart(2, "0")}|${server}|${port}`;
}

function appendMomNodesS(a, o, sourceInner) {
  const names = [];
  if (!sourceInner) return names;
  momConnectionPairsS(o).forEach(([server, port], i) => {
    const n = momNodeNameS(server, port, i, o);
    names.push(n);
    makeNodeS(a, n, server, port, o, sourceInner, "🚀 WARP自动");
  });
  return names;
}

function iconUrlS(name) {
  const base = "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/";
  const map = {
    "自动选择": "Rocket.png",
    AI自动选择: "ChatGPT.png",
    地区优选: "Global.png",
    出口检测: "Speedtest.png",
    PROXY: "Proxy.png",
    AI: "ChatGPT.png",
    YouTube: "YouTube.png",
    Emby: "Emby.png",
    TikTok: "TikTok.png",
    Netflix: "Netflix.png",
    Disney: "Disney.png",
    Spotify: "Spotify.png",
    GitHub: "GitHub.png",
    "🐙 GitHub": "GitHub.png",
    Telegram: "Telegram.png",
    Google: "Google_Search.png",
    Twitter: "Twitter.png",
    Instagram: "Instagram.png",
    Facebook: "Facebook.png",
    Apple: "Apple_1.png",
    Microsoft: "Microsoft.png",
    Steam: "Steam.png",
    Xbox: "Xbox.png",
    PlayStation: "PlayStation_1.png",
    Nintendo: "Nintendo.png",
    Porn: "Pornhub_1.png",
    国外网站: "Global.png",
    "🐟 漏网之鱼": "Final.png",
    Bilibili: "bilibili.png",
    "🔄 MasqueOverMasque": "Global.png",
    "🤖 AI": "ChatGPT.png"
  };
  return base + (map[name] || "Proxy.png");
}

function groupHeaderS(a, name, type, o) {
  a.push(`  - name: ${qS(name)}`, `    type: ${type || "select"}`);
  if (o.icons) a.push(`    icon: ${qS(iconUrlS(name))}`);
}

function appendRawNodesS(a, names, indent) {
  indent = indent || "      ";
  for (const n of names) a.push(`${indent}- ${qS(n)}`);
}

function freeProviderIdS(code, kind) {
  return `FREE-${code}-${(kind || "general").toUpperCase()}`;
}
function freeProviderUrlS(code) {
  return `https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/by-country/clash-${code}.yaml`;
}
function freeForServiceS(o, name) {
  if (!o.freeEnabled || !o.freeCountries.length) return false;
  const s = o.freeScope || "ai-streaming";
  if (s === "all-foreign") return name !== "Bilibili";
  if (s === "ai-only") return name === "AI";
  if (s === "streaming-only")
    return ["Netflix", "Disney", "TikTok", "Spotify", "PrimeVideo", "HBO", "Emby"].includes(name);
  return ["AI", "Netflix", "Disney", "TikTok", "Spotify", "PrimeVideo", "HBO", "Emby"].includes(
    name
  );
}
function freeGroupEntriesS(name) {
  if (name === "AI") return ["🤖 AI自动优选", "🌍 免费落地可手动"];
  if (["Netflix", "Disney", "TikTok", "Spotify", "PrimeVideo", "HBO", "Emby"].includes(name))
    return ["🎬 流媒体自动优选", "🌍 免费落地可手动"];
  return ["⚡ 免费落地自动", "🌍 免费落地可手动"];
}
function providerHealthS(kind) {
  if (kind === "ai")
    return { url: "https://chatgpt.com/", expected: "200-399", interval: 120, timeout: 9000 };
  if (kind === "stream")
    return { url: "https://www.netflix.com/", expected: "200-399", interval: 120, timeout: 9000 };
  return { url: "https://www.gstatic.com/generate_204", expected: "204", interval: 120, timeout: 5000 };
}
function appendOneFreeProviderS(a, o, code, kind) {
  const meta = FREE_COUNTRY_META_S[code] || { flag: "🌐", name: code };
  const hc = providerHealthS(kind);
  const pid = freeProviderIdS(code, kind);
  a.push(
    `  ${pid}:`,
    "    type: http",
    `    url: ${qS(freeProviderUrlS(code))}`,
    `    path: ${qS(`./providers/free-${code}-${kind}.yaml`)}`,
    "    interval: 3600",
    "    size-limit: 8388608"
  );
  if (o.freeUseWarp) a.push('    proxy: "WARP中转"');
  if (o.freeProtocolMode === "stable") {
    a.push('    exclude-type: "hysteria2|tuic|wireguard|http|https|socks4|socks5"');
  }
  a.push(
    "    health-check:",
    "      enable: true",
    `      url: ${qS(hc.url)}`,
    `      expected-status: ${qS(hc.expected)}`,
    `      interval: ${hc.interval}`,
    `      timeout: ${hc.timeout}`,
    "      lazy: false",
    "    override:",
    `      additional-prefix: ${qS(`${meta.flag} ${code} | `)}`
  );
  if (o.freeUseWarp) a.push('      dialer-proxy: "WARP中转"');
}
function appendFreeProvidersS(a, o) {
  if (!o.freeEnabled) return;
  if (!o.freeCountries.length) throw new Error("已启用免费落地，但没有选择任何国家/地区");
  a.push("", "proxy-providers:");
  for (const code of o.freeCountries) {
    appendOneFreeProviderS(a, o, code, "general");
    appendOneFreeProviderS(a, o, code, "ai");
    appendOneFreeProviderS(a, o, code, "stream");
  }
}
function appendProviderUseS(a, o, kind, indent) {
  indent = indent || "      ";
  for (const code of o.freeCountries) a.push(`${indent}- ${qS(freeProviderIdS(code, kind))}`);
}
function countryRuleNameS(code) {
  const meta = FREE_COUNTRY_META_S[code] || { flag: "🌐" };
  return `${meta.flag} ${code}`;
}
function appendCountryChoicesS(a, o, indent) {
  indent = indent || "      ";
  for (const code of o.freeCountries) a.push(`${indent}- ${qS(countryRuleNameS(code))}`);
}

function controllerHostPortS(url) {
  try {
    const u = new URL(url);
    return { host: u.hostname || "127.0.0.1", port: Number(u.port || 9090) };
  } catch {
    return { host: "127.0.0.1", port: 9090 };
  }
}

function clashGroupsAndRulesS(names, o) {
  const a = ["", "proxy-groups:"];
  const freeOn = o.freeEnabled && o.freeCountries.length > 0;

  groupHeaderS(a, "🚀 WARP自动", "url-test", o);
  a.push(
    "    hidden: true",
    `    url: ${qS(o.healthUrl)}`,
    `    interval: ${Math.min(Number(o.healthInterval) || 300, 180)}`,
    `    tolerance: ${Math.min(Number(o.tolerance) || 30, 40)}`,
    "    timeout: 5000",
    "    lazy: false",
    "    max-failed-times: 2",
    "    proxies:"
  );
  appendRawNodesS(a, names);

  groupHeaderS(a, "🌎 WARP可手动", "select", o);
  a.push("    proxies:", '      - "🚀 WARP自动"');
  appendRawNodesS(a, names);

  groupHeaderS(a, "WARP中转", "select", o);
  a.push("    hidden: true", "    proxies:", '      - "🚀 WARP自动"', '      - "🌎 WARP可手动"');

  if (o.momNames && o.momNames.length) {
    groupHeaderS(a, "🔄 MasqueOverMasque", "url-test", o);
    a.push(
      `    url: ${qS(o.healthUrl)}`,
      `    interval: ${Number(o.healthInterval) || 300}`,
      `    tolerance: ${Number(o.tolerance) || 30}`,
      "    timeout: 8000",
      "    lazy: false",
      "    max-failed-times: 2",
      "    proxies:"
    );
    for (const n of o.momNames) a.push(`      - ${qS(n)}`);
  }

  if (freeOn) {
    groupHeaderS(a, "⚡ 免费落地自动", "url-test", o);
    a.push(
      "    hidden: true",
      "    url: https://www.gstatic.com/generate_204",
      "    expected-status: 204",
      "    interval: 120",
      "    tolerance: 30",
      "    timeout: 5000",
      "    lazy: false",
      "    max-failed-times: 2",
      "    use:"
    );
    appendProviderUseS(a, o, "general");

    groupHeaderS(a, "🤖 AI自动优选", "url-test", o);
    a.push(
      "    hidden: true",
      "    url: https://chatgpt.com/",
      "    expected-status: 200-399",
      "    interval: 120",
      "    tolerance: 30",
      "    timeout: 9000",
      "    lazy: false",
      "    max-failed-times: 2",
      "    use:"
    );
    appendProviderUseS(a, o, "ai");

    groupHeaderS(a, "🎬 流媒体自动优选", "url-test", o);
    a.push(
      "    hidden: true",
      "    url: https://www.netflix.com/",
      "    expected-status: 200-399",
      "    interval: 120",
      "    tolerance: 30",
      "    timeout: 9000",
      "    lazy: false",
      "    max-failed-times: 2",
      "    use:"
    );
    appendProviderUseS(a, o, "stream");

    groupHeaderS(a, "🌍 免费落地可手动", "select", o);
    a.push(
      "    proxies:",
      '      - "🤖 AI自动优选"',
      '      - "🎬 流媒体自动优选"',
      '      - "⚡ 免费落地自动"',
      "    use:"
    );
    appendProviderUseS(a, o, "general");

    for (const code of o.freeCountries) {
      groupHeaderS(a, countryRuleNameS(code), "url-test", o);
      a.push(
        "    hidden: true",
        "    url: https://www.gstatic.com/generate_204",
        "    expected-status: 204",
        "    interval: 120",
        "    tolerance: 20",
        "    timeout: 5000",
        "    lazy: false",
        "    max-failed-times: 2",
        "    use:",
        `      - ${qS(freeProviderIdS(code, "general"))}`
      );
    }
  }

  groupHeaderS(a, "♻️ 自动选择", "url-test", o);
  a.push(
    "    url: https://www.gstatic.com/generate_204",
    "    expected-status: 204",
    "    interval: 120",
    "    tolerance: 20",
    "    timeout: 5000",
    "    lazy: false",
    "    max-failed-times: 2",
    "    proxies:"
  );
  if (freeOn) appendCountryChoicesS(a, o);
  a.push('      - "🚀 WARP自动"');

  groupHeaderS(a, "🛡️ 故障转移", "fallback", o);
  a.push(
    "    url: https://www.gstatic.com/generate_204",
    "    expected-status: 204",
    "    interval: 60",
    "    timeout: 5000",
    "    lazy: false",
    "    max-failed-times: 1",
    "    proxies:"
  );
  if (freeOn) appendCountryChoicesS(a, o);
  a.push('      - "🚀 WARP自动"');

  groupHeaderS(a, "⚖️ 负载均衡", "load-balance", o);
  a.push(
    "    strategy: consistent-hashing",
    "    url: https://www.gstatic.com/generate_204",
    "    interval: 180",
    "    timeout: 5000",
    "    lazy: false"
  );
  if (freeOn) {
    a.push("    use:");
    appendProviderUseS(a, o, "general");
  } else {
    a.push("    proxies:", '      - "🚀 WARP自动"');
  }

  groupHeaderS(a, "🚀 节点选择", "select", o);
  a.push(
    "    proxies:",
    '      - "♻️ 自动选择"',
    '      - "🛡️ 故障转移"',
    '      - "⚖️ 负载均衡"'
  );
  if (o.momNames && o.momNames.length) a.push('      - "🔄 MasqueOverMasque"');
  if (freeOn) appendCountryChoicesS(a, o);
  if (freeOn) a.push('      - "🌍 免费落地可手动"');
  a.push('      - "🌎 WARP可手动"', '      - "🚀 WARP自动"', "      - DIRECT");

  groupHeaderS(a, "🎯 全球直连", "select", o);
  a.push("    proxies:", "      - DIRECT");

  groupHeaderS(a, "🛑 全球拦截", "select", o);
  a.push("    proxies:", "      - REJECT", "      - REJECT-DROP");

  groupHeaderS(a, "🤖 AI", "select", o);
  a.push("    proxies:");
  if (o.momNames && o.momNames.length) a.push('      - "🔄 MasqueOverMasque"');
  if (freeOn && freeForServiceS(o, "AI")) a.push('      - "🤖 AI自动优选"');
  if (freeOn) appendCountryChoicesS(a, o);
  a.push('      - "🚀 节点选择"');
  if (freeOn) a.push('      - "🌍 免费落地可手动"');
  a.push('      - "🌎 WARP可手动"', '      - "🎯 全球直连"');

  groupHeaderS(a, "🎬 流媒体", "select", o);
  a.push("    proxies:");
  if (freeOn) a.push('      - "🎬 流媒体自动优选"');
  if (o.momNames && o.momNames.length) a.push('      - "🔄 MasqueOverMasque"');
  if (freeOn) appendCountryChoicesS(a, o);
  a.push('      - "🚀 节点选择"');
  if (freeOn) a.push('      - "🌍 免费落地可手动"');
  a.push('      - "🌎 WARP可手动"', '      - "🎯 全球直连"');

  groupHeaderS(a, "⚡ YouTube-WARP极速", "url-test", o);
  a.push(
    "    hidden: true",
    "    url: https://www.gstatic.com/generate_204",
    "    expected-status: 204",
    "    interval: 60",
    "    tolerance: 10",
    "    timeout: 4000",
    "    lazy: false",
    "    max-failed-times: 1",
    "    proxies:"
  );
  appendRawNodesS(a, names);

  if (freeOn) {
    groupHeaderS(a, "⚡ YouTube-免费极速", "url-test", o);
    a.push(
      "    hidden: true",
      "    url: https://www.gstatic.com/generate_204",
      "    expected-status: 204",
      "    interval: 60",
      "    tolerance: 10",
      "    timeout: 5000",
      "    lazy: false",
      "    max-failed-times: 1",
      "    use:"
    );
    appendProviderUseS(a, o, "general");
  }

  groupHeaderS(a, "▶️ YouTube高速", "select", o);
  a.push("    proxies:", '      - "⚡ YouTube-WARP极速"');
  if (freeOn) {
    a.push('      - "⚡ YouTube-免费极速"');
    appendCountryChoicesS(a, o);
  }
  if (o.momNames && o.momNames.length) a.push('      - "🔄 MasqueOverMasque"');
  a.push('      - "🚀 节点选择"', '      - "🌎 WARP可手动"', '      - "🎯 全球直连"');

  groupHeaderS(a, "✈️ 电报信息", "select", o);
  a.push("    proxies:");
  if (o.momNames && o.momNames.length) a.push('      - "🔄 MasqueOverMasque"');
  a.push('      - "🚀 节点选择"');
  if (freeOn) appendCountryChoicesS(a, o);
  a.push('      - "♻️ 自动选择"', '      - "🌎 WARP可手动"', '      - "🎯 全球直连"');

  groupHeaderS(a, "🐙 GitHub", "select", o);
  a.push("    proxies:");
  if (o.momNames && o.momNames.length) a.push('      - "🔄 MasqueOverMasque"');
  a.push('      - "🚀 WARP自动"', '      - "🚀 节点选择"', '      - "♻️ 自动选择"');
  if (freeOn) appendCountryChoicesS(a, o);
  a.push('      - "🌎 WARP可手动"', '      - "🎯 全球直连"');

  groupHeaderS(a, "Ⓜ️ 微软服务", "select", o);
  a.push("    proxies:", '      - "🎯 全球直连"', '      - "🚀 节点选择"');
  if (freeOn) appendCountryChoicesS(a, o);
  a.push('      - "♻️ 自动选择"', '      - "🌎 WARP可手动"');

  groupHeaderS(a, "🍎 苹果服务", "select", o);
  a.push("    proxies:", '      - "🚀 节点选择"', '      - "🎯 全球直连"');
  if (freeOn) appendCountryChoicesS(a, o);
  a.push('      - "♻️ 自动选择"', '      - "🌎 WARP可手动"');

  groupHeaderS(a, "☁️ Cloudflare中国", "select", o);
  a.push(
    "    proxies:",
    '      - "🚀 WARP自动"',
    '      - "🎯 全球直连"',
    '      - "🚀 节点选择"',
    '      - "🌎 WARP可手动"',
    '      - "♻️ 自动选择"'
  );

  groupHeaderS(a, "☁️ CloudflareCDN", "select", o);
  a.push("    proxies:", '      - "🚀 节点选择"', '      - "♻️ 自动选择"');
  if (freeOn) appendCountryChoicesS(a, o);
  a.push('      - "🌎 WARP可手动"', '      - "🎯 全球直连"');

  groupHeaderS(a, "🌐 国外网站", "select", o);
  a.push("    proxies:");
  if (o.momNames && o.momNames.length) a.push('      - "🔄 MasqueOverMasque"');
  a.push('      - "🚀 WARP自动"', '      - "🚀 节点选择"', '      - "♻️ 自动选择"');
  if (freeOn) appendCountryChoicesS(a, o);
  a.push('      - "🌎 WARP可手动"', '      - "🎯 全球直连"');

  groupHeaderS(a, "🐟 漏网之鱼", "select", o);
  a.push("    proxies:");
  if (o.momNames && o.momNames.length) a.push('      - "🔄 MasqueOverMasque"');
  a.push('      - "🚀 WARP自动"', '      - "🚀 节点选择"', '      - "♻️ 自动选择"');
  if (freeOn) appendCountryChoicesS(a, o);
  a.push('      - "🌎 WARP可手动"', '      - "🎯 全球直连"');

  groupHeaderS(a, "PROXY", "select", o);
  a.push(
    "    hidden: true",
    "    proxies:",
    '      - "🚀 节点选择"',
    '      - "🌐 国外网站"',
    '      - "🚀 WARP自动"',
    "      - DIRECT"
  );

  // 出口检测（隐藏，供脚本使用）
  groupHeaderS(a, "出口检测", "select", o);
  a.push("    hidden: true", "    proxies:");
  appendRawNodesS(a, names);

  groupHeaderS(a, "地区优选", "select", o);
  a.push("    hidden: true", "    proxies:");
  appendRawNodesS(a, names);
  a.push('      - "🚀 WARP自动"');

  if (o.ruleMode === "global") {
    a.push("", "rules:", "  - MATCH,🚀 节点选择", "");
    return a;
  }

  if (o.ruleMode === "lite") {
    a.push(
      "",
      "rule-providers:",
      "  cn:",
      "    type: http",
      "    behavior: domain",
      "    format: mrs",
      "    interval: 43200",
      "    url: https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.mrs"
    );
    if (freeOn && o.freeUseWarp) a.push('    proxy: "WARP中转"');
    a.push(
      "  cn_ip:",
      "    type: http",
      "    behavior: ipcidr",
      "    format: mrs",
      "    interval: 43200",
      "    url: https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo-lite/geoip/cn.mrs"
    );
    if (freeOn && o.freeUseWarp) a.push('    proxy: "WARP中转"');
    a.push(
      "  youtube:",
      "    type: http",
      "    behavior: domain",
      "    format: mrs",
      "    interval: 43200",
      "    url: https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/youtube.mrs"
    );
    if (freeOn && o.freeUseWarp) a.push('    proxy: "WARP中转"');
    a.push(
      "",
      "rules:",
      "  - RULE-SET,youtube,▶️ YouTube高速",
      "  - RULE-SET,cn,🎯 全球直连",
      "  - RULE-SET,cn_ip,🎯 全球直连,no-resolve",
      "  - MATCH,🐟 漏网之鱼",
      ""
    );
    return a;
  }

  a.push(
    "",
    "rule-anchor:",
    "  ip: &ip {type: http, interval: 43200, behavior: ipcidr, format: mrs}",
    "  domain: &domain {type: http, interval: 43200, behavior: domain, format: mrs}",
    "",
    "rule-providers:"
  );
  for (const [tag, url] of CLASH_DOMAIN_RULESETS_S) {
    if (tag === "anti-ad") {
      a.push(
        `  ${tag}:`,
        "    type: http",
        "    behavior: domain",
        "    format: yaml",
        "    interval: 43200",
        `    url: ${url}`
      );
    } else {
      a.push(`  ${tag}:`, `    <<: *domain`, `    url: ${url}`);
    }
    if (freeOn && o.freeUseWarp) a.push('    proxy: "WARP中转"');
  }
  for (const [tag, url] of CLASH_IP_RULESETS_S) {
    a.push(`  ${tag}:`, `    <<: *ip`, `    url: ${url}`);
    if (freeOn && o.freeUseWarp) a.push('    proxy: "WARP中转"');
  }

  a.push("", "rules:");
  if (o.adBlock) {
    a.push(
      "  - RULE-SET,anti-ad,🛑 全球拦截",
      "  - RULE-SET,category-ads-all,🛑 全球拦截",
      "  - RULE-SET,ad_ip,🛑 全球拦截,no-resolve"
    );
  }
  a.push(
    "  - RULE-SET,private_ip,🎯 全球直连,no-resolve",
    "",
    "  # AI",
    "  - DOMAIN-SUFFIX,chatgpt.com,🤖 AI",
    "  - DOMAIN-SUFFIX,openai.com,🤖 AI",
    "  - DOMAIN-SUFFIX,oaistatic.com,🤖 AI",
    "  - DOMAIN-SUFFIX,oaiusercontent.com,🤖 AI",
    "  - RULE-SET,category-ai-!cn,🤖 AI",
    "",
    "  # YouTube",
    "  - RULE-SET,youtube,▶️ YouTube高速",
    "",
    "  # Streaming",
    "  - RULE-SET,netflix,🎬 流媒体",
    "  - RULE-SET,netflix_ip,🎬 流媒体,no-resolve",
    "  - RULE-SET,disney,🎬 流媒体",
    "  - RULE-SET,primevideo,🎬 流媒体",
    "  - RULE-SET,hbo,🎬 流媒体",
    "  - RULE-SET,spotify,🎬 流媒体",
    "  - RULE-SET,tiktok,🎬 流媒体",
    "  - RULE-SET,emby,🎬 流媒体",
    "",
    "  # Telegram",
    "  - RULE-SET,telegram,✈️ 电报信息",
    "  - RULE-SET,telegram_ip,✈️ 电报信息,no-resolve",
    "",
    "  # GitHub",
    "  - RULE-SET,github,🐙 GitHub",
    "",
    "  # Microsoft / Apple",
    "  - RULE-SET,microsoft,Ⓜ️ 微软服务",
    "  - RULE-SET,apple,🍎 苹果服务",
    "",
    "  # Cloudflare 中国站",
    "  - DOMAIN,www.cloudflare-cn.com,☁️ Cloudflare中国",
    "  - DOMAIN-SUFFIX,cloudflare-cn.com,☁️ Cloudflare中国",
    "",
    "  # Cloudflare",
    "  - RULE-SET,cloudflare,☁️ CloudflareCDN",
    "  - RULE-SET,cloudflare_ip,☁️ CloudflareCDN,no-resolve",
    "",
    "  # Mainland / local",
    "  - RULE-SET,bilibili,🎯 全球直连",
    "  - RULE-SET,cn,🎯 全球直连",
    "  - RULE-SET,cn_ip,🎯 全球直连,no-resolve",
    "",
    "  # Remaining foreign / final",
    "  - RULE-SET,geolocation-!cn,🌐 国外网站",
    "  - MATCH,🐟 漏网之鱼",
    ""
  );
  return a;
}

function buildClashServer(source, sourceInner, uiRaw) {
  if (!source || !source.private_key || !source.endpoint_pub_key) {
    throw new Error("KV 中缺少有效的外层 config.json（private_key / endpoint_pub_key）");
  }
  const ui = mergeUiSettings(uiRaw);
  const o = optsFromUi(ui, source);
  const pairs = connectionPairsS(o);
  const names = [];
  const a = [
    `# ${o.profile} - Clash / Mihomo MASQUE (server auto-rebuild)`,
    `# generated_at: ${new Date().toISOString()}`,
    `# nodes: ${pairs.length} outer` + (sourceInner ? " + MoM" : ""),
    "mixed-port: 7890",
    "allow-lan: false",
    "mode: rule",
    "log-level: info",
    "ipv6: true",
    "unified-delay: true",
    "tcp-concurrent: true",
    "keep-alive-interval: 15",
    "keep-alive-idle: 15"
  ];
  if (o.enableControllerApi) {
    const ctl = controllerHostPortS(o.controllerUrl);
    a.push(`external-controller: ${ctl.host}:${ctl.port}`, `secret: ${qS(o.controllerSecret)}`);
  }
  a.push(
    "",
    "dns:",
    "  enable: true",
    "  ipv6: true",
    "  enhanced-mode: fake-ip",
    "  listen: 0.0.0.0:7874",
    "  fake-ip-range: 198.18.0.1/16",
    "  fake-ip-filter:",
    '    - "*.lan"',
    '    - "*.local"',
    '    - "*.arpa"',
    '    - "*.msftncsi.com"',
    '    - "www.msftconnecttest.com"',
    "  default-nameserver:",
    "    - 223.5.5.5",
    "    - 223.6.6.6",
    "  nameserver:",
    "    - https://doh.pub/dns-query",
    "    - https://dns.alidns.com/dns-query",
    "",
    "proxies:"
  );
  pairs.forEach(([server, port], i) => {
    const n = nodeNameS(server, port, i, o);
    names.push(n);
    makeNodeS(a, n, server, port, o, null, null);
  });
  const momNames = appendMomNodesS(a, o, sourceInner);
  if (momNames.length) o.momNames = momNames;
  appendFreeProvidersS(a, o);
  a.push(...clashGroupsAndRulesS(names, o));
  return {
    yaml: a.join("\n"),
    nodes: names.length,
    mom: momNames.length,
    freeCountries: o.freeCountries
  };
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

    // 方案 A：强制服务端重建订阅（需登录）
    if (path === "/api/sub/rebuild") {
      if (request.method !== "POST") {
        return json({ message: "Method Not Allowed" }, 405, { "Allow": "POST" });
      }
      try {
        const result = await ensureSubscriptionYaml(env, { force: true });
        if (!result.content) {
          return json({
            ok: false,
            message: result.error || "重建失败：无可用内容"
          }, 500);
        }
        const origin = new URL(request.url).origin;
        const uuid = String(env.SUB_UUID || "");
        return json({
          ok: true,
          message: result.rebuilt
            ? `服务端已重建订阅（${result.meta?.nodes || "?"} 节点）`
            : "订阅内容仍然有效，未强制改写",
          url: uuid ? `${origin}/${uuid}` : null,
          bytes: result.content.length,
          source: result.source,
          rebuilt: !!result.rebuilt,
          meta: result.meta || null
        });
      } catch (e) {
        return json({ ok: false, message: String(e?.message || e) }, 500);
      }
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


    // 内层 MoM config.json 持久化（需登录）
    if (path === "/api/config/inner/load") {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return json({ message: "Method Not Allowed" }, 405, { "Allow": "GET" });
      }
      return handleConfigInnerLoad(request, env);
    }

    if (path === "/api/config/inner/save") {
      if (request.method !== "POST" && request.method !== "PUT") {
        return json({ message: "Method Not Allowed" }, 405, { "Allow": "POST, PUT" });
      }
      return handleConfigInnerSave(request, env);
    }

    if (path === "/api/config/inner/clear") {
      if (request.method !== "POST" && request.method !== "DELETE") {
        return json({ message: "Method Not Allowed" }, 405, { "Allow": "POST, DELETE" });
      }
      return handleConfigInnerClear(request, env);
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