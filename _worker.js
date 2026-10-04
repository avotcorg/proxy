function isValidIPv4(ip) {
  const p = ip.split(".");
  return p.length === 4 && p.every(x => /^\d+$/.test(x) && Number(x) >= 0 && Number(x) <= 255);
}

function isValidIPv6(ip) {
  if (!ip || !ip.includes(":") || /[^0-9a-fA-F:.]/.test(ip)) return false;
  const parts = ip.split("::");
  if (parts.length > 2) return false;
  const hasCompression = parts.length === 2;
  const left = parts[0] ? parts[0].split(":") : [];
  const right = parts.length === 2 && parts[1] ? parts[1].split(":") : [];
  if (left.some(x => !/^[0-9a-fA-F]{1,4}$/.test(x)) || right.some(x => !/^[0-9a-fA-F]{1,4}$/.test(x))) return false;
  const total = left.length + right.length;
  return hasCompression ? total < 8 : total === 8;
}

function isValidPort(port) {
  const n = Number(port);
  return Number.isInteger(n) && n >= 1 && n <= 65535;
}

const parseHostPort = (addr, defaultPort = 443) => {
  let host = addr,
    port = defaultPort;
  if (addr.charCodeAt(0) === 91) {
    const closeIdx = addr.indexOf("]");
    if (closeIdx !== -1) {
      host = addr.substring(1, closeIdx);
      const rest = addr.substring(closeIdx + 1);
      if (rest.startsWith(":")) port = rest.substring(1);
    }
  } else {
    const colonCount = (addr.match(/:/g) || []).length;
    if (colonCount > 1) {
      host = addr;
    } else if (colonCount === 1) {
      const idx = addr.lastIndexOf(":");
      host = addr.substring(0, idx);
      port = addr.substring(idx + 1);
    }
  }
  return [host.trim(), (port = parseInt(port, 10), isNaN(port) ? defaultPort : port)];
};

function classifyHost(host) {
  if (isValidIPv4(host)) return "ipv4";
  if (isValidIPv6(host)) return "ipv6";
  return "domain";
}

function displayHost(host, family) {
  return family === "ipv6" ? `[${host}]` : host;
}

const DOH_ENDPOINTS = [
  "https://cloudflare-dns.com/dns-query"
];
const DOH_TYPES = { A: 1, AAAA: 28, TXT: 16 };

async function dohOne(base, name, type) {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 2500);
    try {
      const resp = await fetch(`${base}?name=${encodeURIComponent(name)}&type=${type}`, {
        headers: { accept: "application/dns-json" },
        signal: ctrl.signal
      });
      if (!resp.ok) return [];
      const data = await resp.json();
      return Array.isArray(data && data.Answer) ? data.Answer : [];
    } finally {
      clearTimeout(timer);
    }
  } catch {
    return [];
  }
}

async function dohQuery(name, type, depth = 0) {
  const wantType = DOH_TYPES[type];
  const collected = new Set();
  let cname = null;
  for (const endpoint of DOH_ENDPOINTS) {
    const list = await dohOne(endpoint, name, type);
    for (const a of list) {
      if (a.type === wantType) {
        const value = type === "TXT"
          ? String(a.data || "").replace(/"/g, "")
          : String(a.data || "").trim();
        if (value) collected.add(value);
      } else if (a.type === 5 && a.data && !cname) {
        cname = String(a.data).replace(/\.$/, "");
      }
    }
    if (collected.size) break;
  }
  if (!collected.size && cname && depth < 3) return dohQuery(cname, type, depth + 1);
  return [...collected];
}

async function resolveDomain(name) {
  const [v4, v6, txt] = await Promise.all([
    dohQuery(name, "A"),
    dohQuery(name, "AAAA"),
    dohQuery(name, "TXT")
  ]);
  return { v4, v6, txt };
}

const ECHO_PATH = "/__proxyip_echo";
const TRACE_TIMEOUT = 10000;
const GENERIC_FAIL_REASON = "远端返回失败结果";
const DEBUG_PROBE = true;
const EXTERNAL_CHECK_API_BASE = "https://api.ytb1.dns-dynamic.net/check";

function pickField(obj, keys, fallback = "") {
  if (!obj || typeof obj !== "object") return fallback;
  for (const k of keys) {
    const v = obj[k];
    if (v !== undefined && v !== null && v !== "") return v;
  }
  return fallback;
}

function parseDelayMs(raw, fallbackMs) {
  if (raw === null || raw === undefined || raw === "") return fallbackMs;
  const num = parseFloat(String(raw).trim());
  return isNaN(num) ? fallbackMs : num;
}

function normalizeExternalResult(data, cost) {
  if (!data || typeof data !== "object") {
    return { ok: false, reason: GENERIC_FAIL_REASON };
  }

  let success = data["有效代理IP"];
  if (success === undefined) success = data["有效ProxyIP"];
  if (success === undefined && data.success !== undefined) {
    success = !!data.success;
  } else if (success === undefined && data.status !== undefined) {
    success = /^(ok|success|true|1|200)$/i.test(String(data.status).trim());
  } else if (success === undefined && data.code !== undefined) {
    const code = Number(data.code);
    success = code === 200 || code === 0;
  }
  if (success === undefined) success = true;

  if (!success) {
    const reason = pickField(data, ["失败原因", "message", "msg", "error", "reason", "detail"], GENERIC_FAIL_REASON);
    return { ok: false, reason: String(reason) };
  }

  const colo = String(pickField(data, ["数据中心", "colo", "dataCenter", "data_center", "datacenter"], "")).toUpperCase();
  const outIp = String(pickField(data, ["出口ip", "出口IP", "outIp", "out_ip", "exitIp", "exit_ip", "proxyip", "proxyIP", "ip"], ""));
  const country = String(pickField(data, ["国家", "country", "countryCode", "country_code", "loc"], ""));
  const region = String(pickField(data, ["地区", "region"], ""));
  const city = String(pickField(data, ["城市", "city"], ""));
  const asn = String(pickField(data, ["ASN", "asn", "as"], ""));
  const org = String(pickField(data, ["组织", "org", "asOrganization", "as_organization", "isp", "organization"], ""));
  const exitCountry = String(pickField(data, ["出口国家", "exitCountry", "exit_country"], ""));
  const exitCity = String(pickField(data, ["出口城市", "exitCity", "exit_city"], ""));
  const rawDelay = pickField(data, ["响应时间", "delay", "latency", "rtt", "time", "responseTime", "response_time"], null);

  if (!outIp) {
    return { ok: false, reason: "检测接口未返回出口 IP 信息" };
  }

  return {
    ok: true,
    colo: /^[A-Z]{3}$/.test(colo) ? colo : "",
    outIp,
    country,
    region,
    city,
    asn,
    org,
    exitCountry,
    exitCity,
    cost: parseDelayMs(rawDelay, cost),
    raw: data
  };
}

async function callExternalCheckApi(host, port) {
  const target = classifyHost(host) === "ipv6" ? `[${host}]:${port}` : `${host}:${port}`;
  const apiUrl = `${EXTERNAL_CHECK_API_BASE}?proxyip=${encodeURIComponent(target)}`;
  const started = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TRACE_TIMEOUT);
  try {
    const resp = await fetch(apiUrl, {
      headers: { accept: "application/json" },
      signal: ctrl.signal
    });
    const cost = Date.now() - started;
    if (!resp.ok) {
      if (DEBUG_PROBE) console.log("[probe:http-error]", target, resp.status);
      return { ok: false, reason: `检测接口返回非 200 状态: ${resp.status}` };
    }
    let data;
    try {
      data = await resp.json();
    } catch (e) {
      if (DEBUG_PROBE) console.log("[probe:bad-json]", target, e && e.message);
      return { ok: false, reason: GENERIC_FAIL_REASON };
    }
    return normalizeExternalResult(data, cost);
  } catch (err) {
    const msg = err && err.message ? err.message : String(err);
    if (DEBUG_PROBE) console.log("[probe:exception]", target, msg);
    return { ok: false, reason: `远端返回失败结果` };
  } finally {
    clearTimeout(timer);
  }
}

async function probeTarget(host, port) {
  const probe = await callExternalCheckApi(host, port);

  if (!probe.ok) {
    return { ok: false, reason: probe.reason || GENERIC_FAIL_REASON };
  }

  const outType = probe.outIp
    ? (isValidIPv4(probe.outIp) ? "ipv4" : isValidIPv6(probe.outIp) ? "ipv6" : "")
    : "";

  return {
    ok: true,
    result: {
      ip: displayHost(host, isValidIPv6(host) ? "ipv6" : "ipv4"),
      "端口": port,
      "出口ip": probe.outIp,
      "出口类型": outType,
      "数据中心": probe.colo || "未知",
      "国家": probe.country || "未知",
      "地区": probe.region || "未知",
      "城市": probe.city || "未知",
      "响应时间": probe.cost + "ms",
      "出口国家": probe.exitCountry || "",
      "出口城市": probe.exitCity || "",
      "ASN": probe.asn || "",
      "组织": probe.org || "",
      "出口地址与目标是否同族一致": probe.outIp === host,
      "有效ProxyIP": true
    }
  };
}

async function probeWithTimeout(host, port, timeoutMs = FAST_PROBE_TIMEOUT_MS) {
  let timer = null;
  try {
    const result = await Promise.race([
      probeTarget(host, port),
      new Promise((resolve) => {
        timer = setTimeout(() => resolve({ ok: false, reason: GENERIC_FAIL_REASON }), timeoutMs);
      })
    ]);
    return result;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function parseTargetSpec(raw) {
  let text = String(raw || "").trim();
  const hash = text.indexOf("#");
  if (hash >= 0) {
    text = text.slice(0, hash);
  }
  text = text.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "");
  text = text.replace(/[?].*$/, "");
  const at = text.lastIndexOf("@");
  if (at > -1) text = text.slice(at + 1);
  return { target: text.trim() };
}

const MAX_IPS_PER_FAMILY = 9999;
const MAX_TARGETS_PER_DOMAIN = 9999;
const FAST_PROBE_TIMEOUT_MS = 12000;

function parseTxtHosts(records, defaultPort) {
  const out = [];
  const seen = new Set();
  for (const rec of records || []) {
    const text = String(rec || "").replace(/^"|"$/g, "").trim();
    if (!text) continue;
    for (const tok of text.split(/[\s,;|#]+/)) {
      if (!tok) continue;
      const [h, p] = parseHostPort(tok, defaultPort);
      if (!h || !isValidPort(p)) continue;
      const kind = classifyHost(h);
      if (kind === "domain" && !/^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/.test(h)) continue;
      const key = `${h.toLowerCase()}|${p}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ host: h, port: p, family: kind });
    }
  }
  return out;
}

async function expandTarget(raw) {
  const spec = parseTargetSpec(raw);
  const trimmed = spec.target;
  if (!trimmed) return [];

  const [host, port] = parseHostPort(trimmed, 443);
  if (!host || !isValidPort(port)) return [];
  const kind = classifyHost(host);

  if (kind !== "domain") {
    return [{ host, port, input: raw, family: kind, isDomain: false }];
  }

  const { v4, v6, txt } = await resolveDomain(host);
  const targets = [];
  const seen = new Set();

  const push = (h, p, family, source) => {
    if (!isValidPort(p)) return;
    const key = h + "|" + p;
    if (seen.has(key) || targets.length >= MAX_TARGETS_PER_DOMAIN) return;
    seen.add(key);
    targets.push({
      host: h,
      port: p,
      input: trimmed,
      family,
      isDomain: true,
      domain: host,
      source
    });
  };

  v4.filter(isValidIPv4)
    .slice(0, MAX_IPS_PER_FAMILY)
    .forEach((ip) => push(ip, port, "ipv4", "A"));

  v6.filter(isValidIPv6)
    .slice(0, MAX_IPS_PER_FAMILY)
    .forEach((ip) => push(ip, port, "ipv6", "AAAA"));

  parseTxtHosts(txt, port).forEach((t) => {
    push(t.host, t.port, t.family, "TXT");
  });

  if (!targets.length) {
    return [{
      host,
      port,
      input: trimmed,
      family: "hostname",
      isDomain: true,
      domain: host,
      viaHostname: true
    }];
  }

  return targets;
}

async function runPool(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        results[i] = await fn(items[i], i);
      }
    })
  );
  return results;
}

const HTML_PAGE = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover" />
<meta name="color-scheme" content="dark" />
<title>Check ProxyIP</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="icon" href="https://dash.cloudflare.com/favicon.ico" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#0a0e14;
    --bg-panel:#10161f;
    --bg-elevated:#161e2a;
    --border:#212b38;
    --border-soft:#1a222e;
    --text:#e6ecf3;
    --text-dim:#8b98a8;
    --text-faint:#57667a;
    --accent:#2dd4a7;
    --accent-soft:rgba(45,212,167,.13);
    --warn:#e3a53d;
    --warn-soft:rgba(227,165,61,.13);
    --danger:#f2596f;
    --danger-soft:rgba(242,89,111,.13);
    --info:#5b93ff;
    --radius:10px;
    --sans:'IBM Plex Sans', system-ui, -apple-system, 'Segoe UI', sans-serif;
    --mono:'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  *{box-sizing:border-box}
  html,body{margin:0;padding:0}
  body{
    background:var(--bg);
    color:var(--text);
    font-family:var(--sans);
    line-height:1.55;
    -webkit-font-smoothing:antialiased;
  }
  ::selection{background:var(--accent-soft);color:var(--accent)}
  a{color:var(--info)}
  [hidden]{display:none !important}
  .wrap{
    max-width:760px;margin:0 auto;
    padding:clamp(32px,7vw,64px) clamp(16px,4vw,20px) clamp(32px,6vw,48px);
    padding-left:max(clamp(16px,4vw,20px), env(safe-area-inset-left, 0px));
    padding-right:max(clamp(16px,4vw,20px), env(safe-area-inset-right, 0px));
  }

  .hero{margin-bottom:40px}
  .hero-status{
    display:inline-flex;align-items:center;gap:8px;
    font-family:var(--mono);font-size:12.5px;color:var(--text-dim);
    padding:5px 10px 5px 8px;border:1px solid var(--border);border-radius:999px;
    margin-bottom:22px;
  }
  .dot{width:7px;height:7px;border-radius:50%;background:var(--text-faint);flex:none}
  .dot.live{background:var(--accent);box-shadow:0 0 0 0 var(--accent-soft);animation:pulse 1.8s infinite}
  @keyframes pulse{
    0%{box-shadow:0 0 0 0 rgba(45,212,167,.45)}
    70%{box-shadow:0 0 0 7px rgba(45,212,167,0)}
    100%{box-shadow:0 0 0 0 rgba(45,212,167,0)}
  }
  .dot.warn{background:var(--warn);animation:pulse-warn 1.8s infinite}
  @keyframes pulse-warn{
    0%{box-shadow:0 0 0 0 rgba(227,165,61,.45)}
    70%{box-shadow:0 0 0 7px rgba(227,165,61,0)}
    100%{box-shadow:0 0 0 0 rgba(227,165,61,0)}
  }
  .dot.error{background:var(--danger);animation:none}
  #backendFlag{width:16px;height:12px;object-fit:cover;border-radius:2px;flex:none}
  .hero h1{
    font-size:clamp(22px,4.2vw,28px);line-height:1.32;font-weight:600;letter-spacing:-.01em;
    margin:0 0 12px;max-width:24ch;
  }
  .hero p{color:var(--text-dim);font-size:clamp(13.5px,2.6vw,15px);margin:0;max-width:56ch}

  .panel{
    background:var(--bg-panel);border:1px solid var(--border);
    border-radius:var(--radius);padding:22px 22px 20px;margin-bottom:18px;
  }
  .panel-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:16px;flex-wrap:wrap}
  .panel-head h2{font-size:14.5px;font-weight:600;margin:0;color:var(--text)}

  .mode-switch{display:flex;background:var(--bg-elevated);border:1px solid var(--border);border-radius:8px;padding:3px;gap:2px}
  .mode-btn{
    font-family:var(--sans);font-size:13px;color:var(--text-dim);background:transparent;border:0;
    padding:6px 13px;border-radius:6px;cursor:pointer;transition:color .15s, background .15s;
  }
  .mode-btn.active{background:var(--bg);color:var(--text)}
  .mode-btn:hover:not(.active){color:var(--text)}

  #input-single{display:flex;flex-direction:column;gap:10px}
  #singleInput, #batchInput{
    width:100%;background:var(--bg-elevated);border:1px solid var(--border);
    color:var(--text);font-family:var(--mono);font-size:14px;
    border-radius:8px;padding:11px 12px;outline:none;transition:border-color .15s, background .15s;
  }
  #singleInput:focus, #batchInput:focus{border-color:var(--accent)}
  #singleInput.input-error{border-color:var(--danger)}
  #batchInput{
    display:block;
    min-height:240px;
    max-height:70vh;
    resize:vertical;
    line-height:1.7;
    white-space:pre;
    overflow:auto;
    tab-size:4;
  }
  #batchInput.drag-over{border-color:var(--accent);background:var(--accent-soft)}

  #input-batch{display:flex;flex-direction:column;gap:10px}
  .batch-tools{
    display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;
  }
  .batch-count{font-family:var(--mono);font-size:12.5px;color:var(--text-faint)}
  .batch-count b{color:var(--accent);font-weight:600}
  .batch-count .warn{color:var(--warn)}
  .batch-btns{display:flex;gap:8px;flex-wrap:wrap}

  .history{display:flex;flex-wrap:wrap;gap:6px;min-height:0}
  .chip{
    font-family:var(--mono);font-size:12px;color:var(--text-dim);
    background:var(--bg-elevated);border:1px solid var(--border-soft);
    padding:4px 9px;border-radius:999px;cursor:pointer;transition:color .15s, border-color .15s;
  }
  .chip:hover{color:var(--text);border-color:var(--border)}

  .panel-actions{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:14px;flex-wrap:wrap}
  .hint{font-size:12.5px;color:var(--text-faint)}
  .hint.error{color:var(--danger)}
  .btn-primary{
    font-family:var(--sans);font-weight:600;font-size:13.5px;color:#06120e;
    background:var(--accent);border:0;border-radius:8px;padding:9px 18px;
    cursor:pointer;transition:filter .15s, transform .1s;white-space:nowrap;
  }
  .btn-primary:hover{filter:brightness(1.08)}
  .btn-primary:active{transform:translateY(1px)}
  .btn-primary:disabled{opacity:.5;cursor:default;filter:none}
  .btn-ghost{
    font-family:var(--sans);font-size:12.5px;color:var(--text-dim);
    background:transparent;border:1px solid var(--border);border-radius:7px;
    padding:6px 11px;cursor:pointer;transition:color .15s, border-color .15s;
  }
  .btn-ghost:hover{color:var(--text);border-color:var(--text-faint)}

  .status-pill{
    font-family:var(--mono);font-size:12px;padding:4px 10px;border-radius:999px;
    background:var(--bg-elevated);color:var(--text-dim);border:1px solid var(--border);
  }
  .status-pill.running{color:var(--warn);border-color:rgba(227,165,61,.35)}
  .status-pill.done{color:var(--accent);border-color:rgba(45,212,167,.35)}

  .stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
  .stat{
    background:var(--bg-elevated);border:1px solid var(--border-soft);border-radius:8px;
    padding:13px 14px;
  }
  .stat-num{display:block;font-family:var(--mono);font-size:22px;font-weight:600;line-height:1.1;color:var(--text)}
  .stat-label{display:block;font-size:12px;color:var(--text-faint);margin-top:4px}
  .stat.good .stat-num{color:var(--accent)}
  .stat.pending .stat-num{color:var(--warn)}
  .stat.bad .stat-num{color:var(--danger)}

  .export-row{display:flex;gap:8px;flex-wrap:wrap}

  .filter-box{
    background:var(--bg-elevated);border:1px solid var(--border-soft);border-radius:9px;
    padding:14px 16px;margin-bottom:14px;display:flex;flex-direction:column;gap:12px;
  }
  .filter-summary{font-size:14px;color:var(--text-dim)}
  .filter-summary b{color:var(--text);font-weight:600}
  .filter-row{display:flex;align-items:flex-start;gap:12px}
  .filter-label{
    flex:none;width:34px;padding-top:6px;font-size:12.5px;font-weight:600;color:var(--text-faint);
  }
  .filter-chips{display:flex;flex-wrap:wrap;gap:8px;min-width:0}
  .filter-chip{
    font-family:var(--sans);font-size:12.5px;font-weight:500;color:var(--text-dim);
    background:var(--bg-panel);border:1px solid var(--border);border-radius:999px;
    padding:5px 13px;cursor:pointer;white-space:nowrap;transition:color .15s, border-color .15s, background .15s;
  }
  .filter-chip:hover:not(:disabled):not(.active){color:var(--text);border-color:var(--text-faint)}
  .filter-chip.active{background:var(--accent-soft);color:var(--accent);border-color:rgba(45,212,167,.5)}
  .filter-chip:disabled{opacity:.35;cursor:default}
  .results-list{display:flex;flex-direction:column;gap:10px}
  .result-card{
    border:1px solid var(--border-soft);border-radius:9px;background:var(--bg-elevated);
    padding:14px 16px;
  }
  .result-card.ok{border-left:3px solid var(--accent)}
  .result-card.fail{border-left:3px solid var(--danger)}
  .result-card.loading{border-left:3px solid var(--text-faint)}
  .rc-head{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
  .rc-target{font-family:var(--mono);font-size:13.5px;color:var(--text);word-break:break-all}
  .rc-target.copyable{cursor:pointer;transition:color .15s;-webkit-user-select:none;user-select:none}
  .rc-target.copyable:hover{color:var(--accent)}
  .rc-target.copyable.copied{color:var(--accent)}
  .rc-sub{font-family:var(--mono);font-size:11.5px;color:var(--text-faint);margin-top:2px}
  .badge{font-family:var(--mono);font-size:11px;padding:3px 8px;border-radius:999px;white-space:nowrap;flex:none}
  .badge.ok{background:var(--accent-soft);color:var(--accent)}
  .badge.fail{background:var(--danger-soft);color:var(--danger)}
  .badge.loading{background:var(--bg);color:var(--text-faint)}
  .rc-fields{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px 16px;margin-top:12px}
  .rc-field-label{font-size:11px;color:var(--text-faint)}
  .rc-field-value{font-family:var(--mono);font-size:13px;color:var(--text);margin-top:2px;word-break:break-all}
  .rc-field-label.has-tip{border-bottom:1px dashed var(--text-faint);display:inline-block;cursor:help}
  .rc-reason{font-size:12.5px;color:var(--danger);margin-top:10px}
  .spinner{
    width:12px;height:12px;border-radius:50%;
    border:2px solid var(--border);border-top-color:var(--text-dim);
    animation:spin .7s linear infinite;flex:none;
  }
  @keyframes spin{to{transform:rotate(360deg)}}
  .empty-note{color:var(--text-faint);font-size:13px}

  .toast-container{
    position:fixed;left:50%;bottom:24px;transform:translateX(-50%);
    z-index:9999;display:flex;flex-direction:column;gap:8px;
    align-items:center;pointer-events:none;
    padding-bottom:env(safe-area-inset-bottom, 0px);
  }
  .toast{
    font-family:var(--sans);font-size:13.5px;font-weight:500;color:var(--text);
    background:var(--bg-elevated);border:1px solid var(--border);
    border-radius:999px;padding:9px 18px;box-shadow:0 8px 24px rgba(0,0,0,.35);
    display:flex;align-items:center;gap:8px;white-space:nowrap;
    opacity:0;transform:translateY(8px);
    transition:opacity .18s ease, transform .18s ease;
  }
  .toast.show{opacity:1;transform:translateY(0)}
  .toast.success{border-color:rgba(45,212,167,.45)}
  .toast.success .toast-icon{color:var(--accent)}
  .toast.error{border-color:rgba(242,89,111,.45)}
  .toast.error .toast-icon{color:var(--danger)}
  .toast-icon{flex:none;font-size:14px;line-height:1}

  @media (max-width:600px){
    .toast{font-size:13px;padding:8px 15px;max-width:86vw;white-space:normal;text-align:center}
  }

  .guide h2{font-size:14.5px;font-weight:600;margin:0 0 16px}
  .guide-grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(200px,1fr))}
  .guide-item h3{font-size:14px;font-weight:600;margin:0 0 6px;color:var(--text)}
  .guide-item p{font-size:13.5px;color:var(--text-dim);margin:0;max-width:62ch}

  .site-footer{
    margin-top:8px;padding-top:20px;border-top:1px solid var(--border-soft);
    font-size:12px;color:var(--text-faint);display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;
  }

  @media (min-width:1025px){
    .wrap{max-width:860px}
    .rc-fields{grid-template-columns:repeat(auto-fill,minmax(150px,1fr))}
    #batchInput{min-height:280px}
  }

  @media (min-width:601px) and (max-width:1024px){
    .wrap{max-width:680px}
    .stat-grid{grid-template-columns:repeat(4,1fr);gap:8px}
    .stat{padding:11px 12px}
  }

  @media (max-width:600px){
    .panel{padding:16px 14px 14px}
    .stat-grid{grid-template-columns:repeat(2,1fr)}
    .panel-head{gap:10px}
    .panel-actions{flex-direction:column;align-items:stretch}
    .panel-actions .btn-primary{width:100%}
    .export-row{flex-direction:column}
    .export-row .btn-ghost{width:100%;text-align:center}
    .rc-head{align-items:flex-start}
    .rc-fields{grid-template-columns:repeat(2,minmax(0,1fr))}
    #batchInput{min-height:200px}
    .batch-tools{flex-direction:column;align-items:stretch}
    .batch-btns .btn-ghost{flex:1;text-align:center}
  }

  @media (max-width:380px){
    .stat-grid{grid-template-columns:repeat(2,1fr);gap:8px}
    .stat-num{font-size:19px}
  }

  @media (hover:none) and (pointer:coarse){
    .btn-primary,.btn-ghost{min-height:42px}
    .mode-btn{min-height:36px;padding:8px 14px}
    .chip{min-height:30px;padding:6px 11px}
    #singleInput,#batchInput{font-size:16px}
  }

  @media (prefers-reduced-motion: reduce){
    .dot.live,.dot.warn{animation:none}
    .spinner{animation:none}
  }
</style>
</head>
<body>
<div class="toast-container" id="toastContainer" aria-live="polite"></div>
<div class="wrap">

  <header class="hero">
    <div class="hero-status" id="backendStatus" title="">
      <span class="dot live" id="backendDot"></span>
      <img id="backendFlag" alt="" hidden />
      <span id="backendStatusText">正在检测后端节点…</span>
    </div>
    <h3>基于 Cloudflare 的 ProxyIP 检测工具，支持单个或批量目标解析、可用性验证与出口信息查看。</h3>
  </header>

  <section class="panel" id="panel-input">
    <div class="panel-head">
      <h2>开始检测</h2>
      <div class="mode-switch">
        <button class="mode-btn active" data-mode="single" type="button">单目标</button>
        <button class="mode-btn" data-mode="batch" type="button">批量</button>
      </div>
    </div>

    <div id="input-single">
      <input id="singleInput" type="text" autocomplete="off" spellcheck="false"
        placeholder="单个 IP / IPv6 / 域名 / 网址，例如 1.1.1.1:443、proxy.example.com（格式与端口是否有效由服务器判断）" />
      <div class="history" id="historyChips"></div>
    </div>

    <div id="input-batch" hidden>
      <textarea id="batchInput" spellcheck="false" wrap="off" autocomplete="off" autocapitalize="off" autocorrect="off" placeholder="随便粘贴，每行/每个都行，会自动识别其中的 IPv4、IPv6、域名：&#10;1.1.1.1&#10;5.6.7.8:2053  这是一段说明文字也没关系&#10;[2606:4700::1111]&#10;proxy.example.com&#10;https://proxy.example.com:8443/&#10;（没写端口的一律按 443 处理，格式与端口是否有效由服务器判断）&#10;&#10;也可以直接把 .txt / .csv 文件拖进来"></textarea>
      <div class="batch-tools">
        <span class="batch-count" id="batchCount">已识别 <b>0</b> 个目标</span>
        <div class="batch-btns">
          <button class="btn-ghost" id="importBtn" type="button">导入文件</button>
          <button class="btn-ghost" id="dedupeBtn" type="button">整理去重</button>
          <button class="btn-ghost" id="clearBtn" type="button">清空</button>
        </div>
      </div>
      <input type="file" id="fileInput" accept=".txt,.csv,.list,text/plain,text/csv" hidden />
    </div>

    <div class="panel-actions">
      <span class="hint" id="inputHint">按 Enter 直接开始检测</span>
      <button class="btn-primary" id="runBtn" type="button">开始检测</button>
    </div>
  </section>

  <section class="panel" id="panel-summary" hidden>
    <div class="panel-head">
      <h2>概览</h2>
      <span class="status-pill" id="statusPill">等待开始</span>
    </div>
    <div class="stat-grid">
      <div class="stat"><span class="stat-num" id="statTotal">0</span><span class="stat-label">目标数</span></div>
      <div class="stat good"><span class="stat-num" id="statValid">0</span><span class="stat-label">有效</span></div>
      <div class="stat pending"><span class="stat-num" id="statPending">0</span><span class="stat-label">待完成</span></div>
      <div class="stat bad"><span class="stat-num" id="statFail">0</span><span class="stat-label">失败</span></div>
    </div>
  </section>

  <section class="panel" id="panel-results" hidden>
    <div class="panel-head">
      <h2>检测结果</h2>
      <div class="export-row">
        <button class="btn-ghost" id="copyBtn" type="button">复制有效结果</button>
        <button class="btn-ghost" id="copyFailBtn" type="button">复制失败结果</button>
        <button class="btn-ghost" id="txtBtn" type="button">导出 TXT</button>
        <button class="btn-ghost" id="csvBtn" type="button">导出 CSV</button>
      </div>
    </div>
    <div class="filter-box" id="filterBox" hidden>
      <div class="filter-summary">筛选：<b id="filterSummary">全部结果</b></div>
      <div class="filter-row">
        <span class="filter-label">筛选</span>
        <div class="filter-chips" id="statusChips"></div>
      </div>
      <div class="filter-row">
        <span class="filter-label">地区</span>
        <div class="filter-chips" id="regionChips"></div>
      </div>
    </div>
    <div class="results-list" id="resultsList"></div>
  </section>

  <section class="panel guide">
    <h2>什么是 ProxyIP</h2>
    <div class="guide-grid">
      <div class="guide-item">
        <h3>它转发，而不是拥有</h3>
        <p>ProxyIP 不是 Cloudflare 分配给你的接入地址，而是一台第三方服务器 —— 它把自己端口收到的流量，反向代理到 Cloudflare 的边缘网络。</p>
      </div>
      <div class="guide-item">
        <h3>为什么 Workers 用得上它</h3>
        <p>Cloudflare Workers 发起的出站 TCP 连接无法直接打到 Cloudflare 自己的 IP 段。借一台第三方节点中转一次，就能绕开这层限制，间接触达 Cloudflare 服务。</p>
      </div>
      <div class="guide-item">
        <h3>怎样才算“有效”</h3>
        <p>这里不是单纯探测端口通不通，而是真的完成一次 TLS 握手、发出一次请求，确认目标稳定可用，并且愿意把流量代理到 Cloudflare。</p>
      </div>
    </div>
  </section>

  <footer class="site-footer">
    <span>基于 Cloudflare Workers 构建，自部署 ProxyIP 检测工具 TG频道@otcfxq</span>
    <span id="footerTime"></span>
  </footer>

</div>

<script>
(function () {
  "use strict";
  var HISTORY_KEY = "TG频道@otcfxq";
  var MAX_HISTORY = 8;
  var MAX_BATCH_TARGETS = 500;
  var mode = "single";
  var resultsData = [];
  var pendingCount = 0;
  var totalTargets = 0;
  var el = {
    backendStatus: document.getElementById("backendStatus"),
    backendDot: document.getElementById("backendDot"),
    backendFlag: document.getElementById("backendFlag"),
    backendStatusText: document.getElementById("backendStatusText"),
    modeBtns: document.querySelectorAll(".mode-btn"),
    singleWrap: document.getElementById("input-single"),
    batchWrap: document.getElementById("input-batch"),
    singleInput: document.getElementById("singleInput"),
    batchInput: document.getElementById("batchInput"),
    batchCount: document.getElementById("batchCount"),
    importBtn: document.getElementById("importBtn"),
    dedupeBtn: document.getElementById("dedupeBtn"),
    clearBtn: document.getElementById("clearBtn"),
    fileInput: document.getElementById("fileInput"),
    historyChips: document.getElementById("historyChips"),
    inputHint: document.getElementById("inputHint"),
    runBtn: document.getElementById("runBtn"),
    panelSummary: document.getElementById("panel-summary"),
    panelResults: document.getElementById("panel-results"),
    statusPill: document.getElementById("statusPill"),
    statTotal: document.getElementById("statTotal"),
    statValid: document.getElementById("statValid"),
    statPending: document.getElementById("statPending"),
    statFail: document.getElementById("statFail"),
    resultsList: document.getElementById("resultsList"),
    copyBtn: document.getElementById("copyBtn"),
    copyFailBtn: document.getElementById("copyFailBtn"),
    txtBtn: document.getElementById("txtBtn"),
    csvBtn: document.getElementById("csvBtn"),
    footerTime: document.getElementById("footerTime"),
    filterBox: document.getElementById("filterBox"),
    filterSummary: document.getElementById("filterSummary"),
    statusChips: document.getElementById("statusChips"),
    regionChips: document.getElementById("regionChips"),
    toastContainer: document.getElementById("toastContainer")
  };

  var TOAST_DURATION_MS = 2200;
  function showToast(message, type) {
    if (!el.toastContainer) return;
    var toast = document.createElement("div");
    toast.className = "toast " + (type === "error" ? "error" : "success");
    var icon = document.createElement("span");
    icon.className = "toast-icon";
    icon.textContent = type === "error" ? "✕" : "✓";
    var text = document.createElement("span");
    text.textContent = message;
    toast.appendChild(icon);
    toast.appendChild(text);
    el.toastContainer.appendChild(toast);
    requestAnimationFrame(function () { toast.classList.add("show"); });
    setTimeout(function () {
      toast.classList.remove("show");
      setTimeout(function () {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 220);
    }, TOAST_DURATION_MS);
  }

  function writeTextToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      if (fallbackCopy(text)) resolve();
      else reject(new Error("execCommand copy failed"));
    });
  }

  function loadHistory() {
    try {
      var raw = localStorage.getItem(HISTORY_KEY);
      var list = raw ? JSON.parse(raw) : [];
      return Array.isArray(list) ? list : [];
    } catch (e) {
      return [];
    }
  }

  function saveHistory(value) {
    var list = loadHistory().filter(function (v) { return v !== value; });
    list.unshift(value);
    if (list.length > MAX_HISTORY) list = list.slice(0, MAX_HISTORY);
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify(list)); } catch (e) {}
    renderHistory();
  }

  function renderHistory() {
    var list = loadHistory();
    el.historyChips.innerHTML = "";
    list.forEach(function (v) {
      var chip = document.createElement("button");
      chip.type = "button";
      chip.className = "chip";
      chip.textContent = v;
      chip.addEventListener("click", function () {
        el.singleInput.value = v;
        el.singleInput.focus();
      });
      el.historyChips.appendChild(chip);
    });
  }

  renderHistory();

  function getFlagUrlFromCountryCode(code) {
    if (!code || typeof code !== "string" || code.length !== 2) return null;
    var cc = code.toUpperCase();
    if (!/^[A-Z]{2}$/.test(cc)) return null;
    return "https://flagcdn.com/24x18/" + cc.toLowerCase() + ".png";
  }

  function updateSummaryBackendFlag(countryCode) {
    var url = getFlagUrlFromCountryCode(countryCode);
    if (url) {
      el.backendFlag.src = url;
      el.backendFlag.hidden = false;
    } else {
      el.backendFlag.hidden = true;
      el.backendFlag.removeAttribute("src");
    }
  }

  function setSummaryBackendStatus(state, text, tooltip) {
    var cls = state === "ok" ? "live" : state === "warn" ? "warn" : state === "error" ? "error" : "live";
    el.backendDot.className = "dot " + cls;
    el.backendStatusText.textContent = text;
    el.backendStatus.title = tooltip || "";
  }

  var BACKEND_STATUS_TIMEOUT_MS = 6000;
  function initBackendStatus() {
    setSummaryBackendStatus("warn", "正在检测后端节点…", "");
    var ctrl = (typeof AbortController !== "undefined") ? new AbortController() : null;
    var timedOut = false;
    var timer = setTimeout(function () {
      timedOut = true;
      if (ctrl) { try { ctrl.abort(); } catch (e) {} }
    }, BACKEND_STATUS_TIMEOUT_MS);

    fetch("/__proxyip_echo", {
      headers: { "Accept": "application/json" },
      signal: ctrl ? ctrl.signal : undefined
    })
      .then(function (res) {
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.json();
      })
      .then(function (data) {
        clearTimeout(timer);
        var colo = data && data.colo ? String(data.colo).toUpperCase() : "";
        var country = data && data.country ? String(data.country).toUpperCase() : "";
        var city = data && data.city ? data.city : "";
        updateSummaryBackendFlag(country);
        var label = [country, colo || city].filter(function (x) { return x; }).join(" · ");
        setSummaryBackendStatus(
          "ok",
          (label ? label + " " : "") + "服务已就绪",
          "检测结果基于本系统 所在节点发起 TLS 探测，若目标服务器与该节点距离较远，可能因网络延迟被误判为无效"
        );
      })
      .catch(function (err) {
        clearTimeout(timer);
        if (typeof console !== "undefined" && console.warn) {
          console.warn(
            "[backend-status] /__proxyip_echo 检测失败：",
            timedOut ? "请求超时（" + BACKEND_STATUS_TIMEOUT_MS + "ms 无响应）" : err
          );
        }
        updateSummaryBackendFlag(null);
        setSummaryBackendStatus(
          "error",
          timedOut ? "后端节点无响应" : "后端节点状态未知",
          timedOut
            ? "请求 /__proxyip_echo 超过 " + (BACKEND_STATUS_TIMEOUT_MS / 1000) + " 秒未返回，请检查该路径的路由是否可达（可打开浏览器控制台查看详情）"
            : "无法获取当前节点信息，但检测功能通常仍可正常使用（详情见浏览器控制台）"
        );
      });
  }

  initBackendStatus();

  function setMode(next) {
    mode = next;
    el.modeBtns.forEach(function (b) {
      var active = b.getAttribute("data-mode") === next;
      b.classList.toggle("active", active);
    });
    el.singleWrap.hidden = next !== "single";
    el.batchWrap.hidden = next !== "batch";
    el.singleInput.classList.remove("input-error");
    el.inputHint.classList.remove("error");
    el.inputHint.textContent = next === "single"
      ? "单目标仅支持一个 IP:端口，按 Enter 直接开始检测（格式与端口是否有效由服务器判断）"
      : "自动识别粘贴内容里的 IPv4/IPv6/域名，未写端口默认 443，格式与端口是否有效由服务器判断，Ctrl/⌘ + Enter 开始";
    if (next === "batch") {
      updateBatchCount();
      el.batchInput.focus();
    } else {
      el.singleInput.focus();
    }
  }

  el.modeBtns.forEach(function (b) {
    b.addEventListener("click", function () { setMode(b.getAttribute("data-mode")); });
  });

  el.singleInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter") { e.preventDefault(); startCheck(); }
  });
  el.runBtn.addEventListener("click", startCheck);

  function looksLikeIPv4Shape(ip) {
    var p = ip.split(".");
    return p.length === 4 && p.every(function (x) { return /^\\d{1,3}$/.test(x); });
  }

  function looksLikeIPv6Shape(ip) {
    return !!ip && ip.indexOf(":") !== -1 && !/[^0-9a-fA-F:]/.test(ip);
  }

  function looksLikePortShape(p) {
    if (p === null || p === undefined || p === "") return true;
    return /^\\d{1,5}$/.test(String(p));
  }

  var DOMAIN_SHAPE_RE = /^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\\.[a-zA-Z0-9-]+$/;
  var DEFAULT_PORT = "443";
  function extractTargets(rawText) {
    var work = " " + rawText + " ";
    var found = [];
    var seen = {};

    function add(hostForKey, port) {
      if (!looksLikePortShape(port)) return;
      var key = hostForKey + ":" + (port || DEFAULT_PORT);
      if (seen[key]) return;
      seen[key] = true;
      found.push(key);
    }
    work = work.replace(/\\[([^\\]\\[]*)\\]\\(([^)\\s]*)\\)/g, " $1 $2 ");
    work = work.replace(/\\b[a-zA-Z][a-zA-Z0-9+.-]*:\\/\\/([^\\s\\/?#"'<>()]*)/g, function (m, auth) {
      var at = auth.lastIndexOf("@");
      if (at > -1) auth = auth.slice(at + 1);
      return " " + auth + " ";
    });
    work = work.replace(/\\[([0-9a-fA-F:]{2,45})\\](?::(\\d{1,5}))?/g, function (m, addr, port) {
      if (looksLikeIPv6Shape(addr)) { add("[" + addr + "]", port); return " "; }
      return m;
    });
    work = work.replace(/(^|[^0-9a-fA-F:.])((?:[0-9a-fA-F]{1,4}:){1,7}:?(?:[0-9a-fA-F]{1,4})?(?::[0-9a-fA-F]{1,4}){0,6})(?![0-9a-fA-F:])/g, function (m, pre, addr) {
      if (addr.indexOf(":") !== -1 && looksLikeIPv6Shape(addr)) { add("[" + addr + "]", null); return pre + " "; }
      return m;
    });
    work = work.replace(/\\b(\\d{1,3}(?:\\.\\d{1,3}){3})(?::(\\d{1,5}))?\\b/g, function (m, ip, port) {
      if (looksLikeIPv4Shape(ip)) { add(ip, port); return " "; }
      return m;
    });
    work.split(/[\\s,;，；()\\[\\]<>"']+/).forEach(function (tok) {
      var t = tok.trim().split(/[\\/?#]/)[0].replace(/[.。]+$/, "");
      if (!t) return;
      var host = t, port = null;
      var idx = t.lastIndexOf(":");
      if (idx > -1 && /^\\d{1,5}$/.test(t.slice(idx + 1))) {
        host = t.slice(0, idx);
        port = t.slice(idx + 1);
      }
      if (DOMAIN_SHAPE_RE.test(host)) add(host.toLowerCase(), port);
    });

    return found;
  }

  function getTargets() {
    var raw = mode === "single" ? el.singleInput.value : el.batchInput.value;
    if (mode === "batch") return extractTargets(raw);

    var single = raw.trim();
    if (!single) return [];
    return [single];
  }
  function updateBatchCount() {
    var n = extractTargets(el.batchInput.value).length;
    var html = "已识别 <b>" + n + "</b> 个目标";
    if (n > MAX_BATCH_TARGETS) {
      html += ' <span class="warn">（超过 ' + MAX_BATCH_TARGETS + ' 个，仅检测前 ' + MAX_BATCH_TARGETS + ' 个）</span>';
    }
    el.batchCount.innerHTML = html;
  }

  el.batchInput.addEventListener("input", updateBatchCount);

  function dedupeBatchInput() {
    var list = extractTargets(el.batchInput.value);
    if (list.length === 0) {
      updateBatchCount();
      return;
    }
    el.batchInput.value = list.join("\\n");
    updateBatchCount();
  }

  el.batchInput.addEventListener("paste", function () {
    setTimeout(dedupeBatchInput, 0);
  });

  el.batchInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      startCheck();
    }
  });

  el.clearBtn.addEventListener("click", function () {
    el.batchInput.value = "";
    updateBatchCount();
    el.batchInput.focus();
  });
  el.dedupeBtn.addEventListener("click", dedupeBatchInput);

  function readFileIntoBatch(file) {
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function () {
      var text = String(reader.result || "");
      var cur = el.batchInput.value;
      el.batchInput.value = cur && !/\\n$/.test(cur) ? cur + "\\n" + text : cur + text;
      dedupeBatchInput();
    };
    reader.readAsText(file);
  }

  el.importBtn.addEventListener("click", function () { el.fileInput.click(); });
  el.fileInput.addEventListener("change", function () {
    var files = el.fileInput.files;
    for (var i = 0; i < files.length; i++) readFileIntoBatch(files[i]);
    el.fileInput.value = "";
  });

  ["dragenter", "dragover"].forEach(function (ev) {
    el.batchInput.addEventListener(ev, function (e) {
      e.preventDefault();
      el.batchInput.classList.add("drag-over");
    });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    el.batchInput.addEventListener(ev, function () {
      el.batchInput.classList.remove("drag-over");
    });
  });
  el.batchInput.addEventListener("drop", function (e) {
    e.preventDefault();
    var files = e.dataTransfer && e.dataTransfer.files;
    if (files && files.length) {
      for (var i = 0; i < files.length; i++) readFileIntoBatch(files[i]);
    } else if (e.dataTransfer) {
      var txt = e.dataTransfer.getData("text");
      if (txt) {
        el.batchInput.value += (el.batchInput.value ? "\\n" : "") + txt;
        dedupeBatchInput();
      }
    }
  });
  var filterStatus = "all";
  var filterRegion = "all";
  var STATUS_DEFS = [
    ["all", "全部"],
    ["valid", "有效"],
    ["fail", "失败"],
    ["v4", "OnlyIPv4"],
    ["v6", "OnlyIPv6"],
    ["both", "IPv4&IPv6"]
  ];
  function entryFamily(e) {
    if (e["有效ProxyIP"] !== true) return "";
    var t = e["出口类型"];
    return t === "ipv4" ? "4" : (t === "ipv6" ? "6" : "");
  }
  function groupKey(e) { return e["输入"] || e["目标"] || ""; }

  function buildGroupMap() {
    var map = {};
    resultsData.forEach(function (e) {
      if (entryFamily(e) === "") return;
      var k = groupKey(e);
      (map[k] = map[k] || []).push(e);
    });
    return map;
  }
  function dualPair(e, map) {
    var g = map[groupKey(e)];
    if (!g || g.length !== 2) return false;
    return entryFamily(g[0]) !== entryFamily(g[1]);
  }

  function entryGroup(e, map) {
    var fam = entryFamily(e);
    if (!fam) return "";
    if (dualPair(e, map)) return "both";
    return fam === "4" ? "v4" : "v6";
  }

  function matchStatus(e, s, map) {
    if (s === "all") return true;
    if (s === "valid") return e["有效ProxyIP"] === true;
    if (s === "fail") return e["有效ProxyIP"] !== true;
    return entryGroup(e, map) === s;
  }

  function makeChip(label, count, active, onClick) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "filter-chip" + (active ? " active" : "");
    b.textContent = label + "(" + count + ")";
    if (count === 0 && !active) b.disabled = true;
    b.addEventListener("click", onClick);
    return b;
  }

  function refreshFilters() {
    if (resultsData.length === 0) {
      el.filterBox.hidden = true;
      return;
    }
    el.filterBox.hidden = false;
    var map = buildGroupMap();
    el.statusChips.innerHTML = "";
    STATUS_DEFS.forEach(function (d) {
      var n = resultsData.filter(function (e) { return matchStatus(e, d[0], map); }).length;
      el.statusChips.appendChild(makeChip(d[1], n, filterStatus === d[0], function () {
        filterStatus = d[0];
        refreshFilters();
      }));
    });
    var counts = {};
    resultsData.forEach(function (e) {
      var c = e["出口国家"];
      if (c && e["有效ProxyIP"] === true) counts[c] = (counts[c] || 0) + 1;
    });
    var codes = Object.keys(counts).sort(function (a, b) {
      return counts[b] - counts[a] || (a < b ? -1 : 1);
    });
    el.regionChips.innerHTML = "";
    el.regionChips.appendChild(makeChip("全部", resultsData.length, filterRegion === "all", function () {
      filterRegion = "all";
      refreshFilters();
    }));
    codes.forEach(function (c) {
      el.regionChips.appendChild(makeChip(c, counts[c], filterRegion === c, function () {
        filterRegion = c;
        refreshFilters();
      }));
    });
    var kids = el.resultsList.children;
    var shown = 0;
    for (var i = 0; i < kids.length; i++) {
      var card = kids[i];
      var e = card._entry;
      if (!e) {
        card.hidden = !(filterStatus === "all" && filterRegion === "all");
        continue;
      }
      var show = matchStatus(e, filterStatus, map) && (filterRegion === "all" || e["出口国家"] === filterRegion);
      card.hidden = !show;
      if (show) shown++;
    }

    var parts = [];
    STATUS_DEFS.forEach(function (d) { if (d[0] === filterStatus && d[0] !== "all") parts.push(d[1]); });
    if (filterRegion !== "all") parts.push(filterRegion);
    el.filterSummary.textContent = (parts.length ? parts.join(" · ") : "全部结果") + "（显示 " + shown + " 条）";
  }

  function resetPanels(targets) {
    resultsData = [];
    totalTargets = targets.length;
    pendingCount = targets.length;
    el.panelSummary.hidden = false;
    el.panelResults.hidden = false;
    el.statTotal.textContent = String(totalTargets);
    el.statValid.textContent = "0";
    el.statFail.textContent = "0";
    el.statPending.textContent = String(pendingCount);
    el.statusPill.textContent = "检测中";
    el.statusPill.className = "status-pill running";
    el.resultsList.innerHTML = "";
    filterStatus = "all";
    filterRegion = "all";
    refreshFilters();
    targets.forEach(function (t, idx) { makePlaceholderCard(t, idx, true); });
  }

  function buildPlaceholder(label, subText) {
    var card = document.createElement("div");
    card.className = "result-card loading";
    var head = document.createElement("div");
    head.className = "rc-head";
    var left = document.createElement("div");
    var t = document.createElement("div");
    t.className = "rc-target";
    t.textContent = label;
    var sub = document.createElement("div");
    sub.className = "rc-sub";
    sub.textContent = subText;
    left.appendChild(t);
    left.appendChild(sub);

    var badge = document.createElement("span");
    badge.className = "badge loading";
    var spinner = document.createElement("span");
    spinner.className = "spinner";
    badge.appendChild(spinner);

    head.appendChild(left);
    head.appendChild(badge);
    card.appendChild(head);
    card._title = t;
    card._sub = sub;
    return card;
  }

  function makePlaceholderCard(target, idx, queued) {
    var card = buildPlaceholder(target, queued ? "排队中…" : "正在解析…");
    card.id = "rc-" + idx;
    el.resultsList.appendChild(card);
    return card;
  }

  function setCardSub(card, text) {
    if (card && card._sub) card._sub.textContent = text;
  }
  function asnText(e) {
    var asn = e["ASN"] ? "AS" + e["ASN"] : "";
    var org = e["组织"] || "";
    if (asn && org) return asn + " · " + org;
    return asn || org || "—";
  }
  function exitInfo(e) {
    var own = { ip: e["出口ip"] || "—", type: e["出口类型"] || "—" };
    if (e["有效ProxyIP"] !== true) return own;
    var map = buildGroupMap();
    if (!dualPair(e, map)) return own;
    var v4 = "", v6 = "";
    map[groupKey(e)].forEach(function (x) {
      if (entryFamily(x) === "4") v4 = x["出口ip"]; else v6 = x["出口ip"];
    });
    return { ip: v4 + " / " + v6, type: "ipv4/ipv6" };
  }

  function normalizeColoCode(colo) {
    if (!colo || typeof colo !== "string") return null;
    var c = colo.trim().toUpperCase();
    return /^[A-Z]{3}$/.test(c) ? c : null;
  }

  function getLatencyTooltipText(data) {
    var coloCode = normalizeColoCode(data && data.colo);
    var coloText = coloCode ? "Cloudflare " + coloCode + " 机房" : "Cloudflare 测试机房";
    return "这个延迟不是你到 ProxyIP 的检测延迟，而是 " + coloText + " 到 ProxyIP 的检测延迟。";
  }

  function fallbackCopy(text) {
    try {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.top = "-1000px";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      return true;
    } catch (e) {
      return false;
    }
  }

  function flashCopied(el) {
    el.classList.add("copied");
    clearTimeout(el._copyTimer);
    el._copyTimer = setTimeout(function () {
      el.classList.remove("copied");
    }, 900);
  }

  function copyText(text, feedbackEl, toastLabel) {
    if (!text) return;
    writeTextToClipboard(text)
      .then(function () {
        if (feedbackEl) flashCopied(feedbackEl);
        showToast("已复制" + (toastLabel ? "：" + toastLabel : ""), "success");
      })
      .catch(function (err) {
        console.error("复制失败", err);
        showToast("复制失败，请检查浏览器权限", "error");
      });
  }

  function refillGroup(key) {
    var kids = el.resultsList.children;
    for (var i = 0; i < kids.length; i++) {
      var c = kids[i];
      if (c._entry && c._entry["输入"] === key && c._entry["有效ProxyIP"] === true) fillCard(c, c._entry);
    }
  }

  function fieldRow(container, label, value, tooltip) {
    var wrap = document.createElement("div");
    var l = document.createElement("div");
    l.className = "rc-field-label" + (tooltip ? " has-tip" : "");
    l.textContent = label;
    if (tooltip) {
      l.title = tooltip;
      wrap.title = tooltip;
    }
    var v = document.createElement("div");
    v.className = "rc-field-value";
    v.textContent = value;
    wrap.appendChild(l);
    wrap.appendChild(v);
    container.appendChild(wrap);
  }

  function fillCard(card, entry) {
    card.innerHTML = "";
    var ok = entry["有效ProxyIP"] === true;
    card.className = "result-card " + (ok ? "ok" : "fail");
    card._entry = entry;

    var head = document.createElement("div");
    head.className = "rc-head";

    var left = document.createElement("div");
    var t = document.createElement("div");
    t.className = "rc-target copyable";
    t.textContent = entry["目标"] || "";
    t.title = "点击复制";
    t.addEventListener("click", function () {
      var copyValue;
      if (ok) {
        copyValue = hostPort(entry);
      } else {
        var label = String(entry["目标"] || "");
        var arrow = label.indexOf(" -> ");
        copyValue = (arrow !== -1 ? label.slice(arrow + 4) : label).trim();
      }
      copyText(copyValue, t, copyValue);
    });
    left.appendChild(t);
    if (entry["解析地址族"]) {
      var sub = document.createElement("div");
      sub.className = "rc-sub";
      sub.textContent = "解析地址族: " + entry["解析地址族"] + (entry["解析来源"] ? " · " + entry["解析来源"] + " 记录" : "");
      left.appendChild(sub);
    }

    var badge = document.createElement("span");
    badge.className = "badge " + (ok ? "ok" : "fail");
    badge.textContent = ok ? "有效" : "无效";
    head.appendChild(left);
    head.appendChild(badge);
    card.appendChild(head);

    if (ok) {
      var fields = document.createElement("div");
      fields.className = "rc-fields";
      fieldRow(fields, "检测机房", (entry["数据中心"] || "—") + " · " + (entry["城市"] || "—"),
        "发起检测的 Cloudflare 机房，不是 ProxyIP 的位置");
      fieldRow(fields, "出口国家", entry["出口国家"] || "—");
      fieldRow(fields, "出口城市", entry["出口城市"] || "—");
      fieldRow(fields, "响应时间", entry["响应时间"] || "—", getLatencyTooltipText({ colo: entry["数据中心"] }));
      var ex = exitInfo(entry);
      fieldRow(fields, "出口 IP", ex.ip);
      fieldRow(fields, "出口类型", ex.type);
      fieldRow(fields, "ASN", asnText(entry));
      card.appendChild(fields);
    } else {
      var reason = document.createElement("div");
      reason.className = "rc-reason";
      reason.textContent = entry["失败原因"] || "未知错误";
      card.appendChild(reason);
    }
  }

  function updateStats() {
    var valid = 0, fail = 0;
    resultsData.forEach(function (e) {
      if (e["有效ProxyIP"] === true) valid++; else fail++;
    });
    el.statValid.textContent = String(valid);
    el.statFail.textContent = String(fail);
    el.statPending.textContent = String(pendingCount);
    refreshFilters();
    if (pendingCount <= 0) {
      el.statusPill.textContent = "已完成";
      el.statusPill.className = "status-pill done";
      el.runBtn.disabled = false;
    }
  }

  var BATCH_CONCURRENCY = 3;
  var BATCH_STAGGER_MS = 120;
  var taskQueue = [];
  var activeTasks = 0;
  var gate = false;

  function pump() {
    if (gate) return;
    while (!gate && activeTasks < BATCH_CONCURRENCY && taskQueue.length) {
      var task = taskQueue.shift();
      activeTasks++;
      gate = true;
      var done = function () { activeTasks--; pump(); };
      Promise.resolve().then(task).then(done, done);
      setTimeout(function () { gate = false; pump(); }, BATCH_STAGGER_MS);
    }
  }

  function schedule(task) {
    taskQueue.push(task);
    pump();
  }

  function finishOne() {
    pendingCount--;
    updateStats();
  }

  function addEntry(card, entry) {
    fillCard(card, entry);
    resultsData.push(entry);
  }

  function jsonHeaders() { return { "Accept": "application/json" }; }
  var CLIENT_EXTERNAL_API_BASE = "https://api.ytb1.dns-dynamic.net/check";
  var CLIENT_PROBE_TIMEOUT_MS = 10000;

  function clientPickField(obj, keys) {
    if (!obj || typeof obj !== "object") return "";
    for (var i = 0; i < keys.length; i++) {
      var v = obj[keys[i]];
      if (v !== undefined && v !== null && v !== "") return v;
    }
    return "";
  }

  function clientParseDelayMs(raw, fallbackMs) {
    if (raw === null || raw === undefined || raw === "") return fallbackMs;
    var num = parseFloat(String(raw).trim());
    return isNaN(num) ? fallbackMs : num;
  }

  function clientNormalizeExternalResult(data, cost) {
    if (!data || typeof data !== "object") return null;

    var success = data["有效代理IP"];
    if (success === undefined) success = data["有效ProxyIP"];
    if (success === undefined && data.success !== undefined) {
      success = !!data.success;
    } else if (success === undefined && data.status !== undefined) {
      success = /^(ok|success|true|1|200)$/i.test(String(data.status).trim());
    } else if (success === undefined && data.code !== undefined) {
      var code = Number(data.code);
      success = code === 200 || code === 0;
    }
    if (success === undefined) success = true;

    if (!success) {
      var reason = clientPickField(data, ["失败原因", "message", "msg", "error", "reason", "detail"]) || "远端返回失败结果";
      return { ok: false, reason: String(reason) };
    }

    var colo = String(clientPickField(data, ["数据中心", "colo", "dataCenter", "data_center", "datacenter"])).toUpperCase();
    var outIp = String(clientPickField(data, ["出口ip", "出口IP", "outIp", "out_ip", "exitIp", "exit_ip", "proxyip", "proxyIP", "ip"]));
    var country = String(clientPickField(data, ["国家", "country", "countryCode", "country_code", "loc"]));
    var region = String(clientPickField(data, ["地区", "region"]));
    var city = String(clientPickField(data, ["城市", "city"]));
    var asn = String(clientPickField(data, ["ASN", "asn", "as"]));
    var org = String(clientPickField(data, ["组织", "org", "asOrganization", "as_organization", "isp", "organization"]));
    var exitCountry = String(clientPickField(data, ["出口国家", "exitCountry", "exit_country"]));
    var exitCity = String(clientPickField(data, ["出口城市", "exitCity", "exit_city"]));
    var rawDelay = clientPickField(data, ["响应时间", "delay", "latency", "rtt", "time", "responseTime", "response_time"]);

    if (!outIp) return { ok: false, reason: "检测接口未返回出口 IP 信息" };

    return {
      ok: true,
      colo: /^[A-Z]{3}$/.test(colo) ? colo : "",
      outIp: outIp,
      country: country,
      region: region,
      city: city,
      asn: asn,
      org: org,
      exitCountry: exitCountry,
      exitCity: exitCity,
      cost: clientParseDelayMs(rawDelay, cost)
    };
  }

  function displayHostClient(host, family) {
    return family === "ipv6" ? "[" + host + "]" : host;
  }

  function probeExternalDirect(job) {
    var target = job.family === "ipv6" ? "[" + job.host + "]:" + job.port : job.host + ":" + job.port;
    var apiUrl = CLIENT_EXTERNAL_API_BASE + "?proxyip=" + encodeURIComponent(target);
    var started = Date.now();
    var ctrl = (typeof AbortController !== "undefined") ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctrl) { try { ctrl.abort(); } catch (e) {} } }, CLIENT_PROBE_TIMEOUT_MS);

    return fetch(apiUrl, {
      headers: { Accept: "application/json" },
      signal: ctrl ? ctrl.signal : undefined
    })
      .then(function (resp) {
        clearTimeout(timer);
        var cost = Date.now() - started;
        if (!resp.ok) {
          return { "有效ProxyIP": false, "失败原因": "检测接口返回非 200 状态: " + resp.status };
        }
        return resp.json().then(function (data) {
          var norm = clientNormalizeExternalResult(data, cost);
          if (!norm) {
            return { "有效ProxyIP": false, "失败原因": "远端返回失败结果" };
          }
          if (!norm.ok) {
            return { "有效ProxyIP": false, "失败原因": norm.reason };
          }
          var outType = norm.outIp
            ? (looksLikeIPv4Shape(norm.outIp) ? "ipv4" : (looksLikeIPv6Shape(norm.outIp) ? "ipv6" : ""))
            : "";
          return {
            "ip": displayHostClient(job.host, job.family),
            "端口": job.port,
            "出口ip": norm.outIp,
            "出口类型": outType,
            "数据中心": norm.colo || "未知",
            "国家": norm.country || "未知",
            "地区": norm.region || "未知",
            "城市": norm.city || "未知",
            "响应时间": norm.cost + "ms",
            "出口国家": norm.exitCountry || "",
            "出口城市": norm.exitCity || "",
            "ASN": norm.asn || "",
            "组织": norm.org || "",
            "出口地址与目标是否同族一致": norm.outIp === job.host,
            "有效ProxyIP": true
          };
        }).catch(function () {
          return { "有效ProxyIP": false, "失败原因": "远端返回失败结果" };
        });
      })
      .catch(function () {
        clearTimeout(timer);
        return null;
      });
  }

  function resolveInput(target, idx) {
    var card = document.getElementById("rc-" + idx);
    setCardSub(card, "正在解析…");
    var api = location.pathname + "?ip=" + encodeURIComponent(target) + "&resolve=1";

    return fetch(api, { headers: jsonHeaders() })
      .then(function (res) { return res.json(); })
      .then(function (jobs) {
        if (!Array.isArray(jobs) || jobs.length === 0) throw new Error("没有可检测的目标");
        return jobs;
      })
      .then(function (jobs) {
        var extra = jobs.length - 1;
        totalTargets += extra;
        pendingCount += extra;
        el.statTotal.textContent = String(totalTargets);
        el.statPending.textContent = String(pendingCount);

        var prev = card;
        var tasks = [];
        jobs.forEach(function (job, j) {
          var c = card;
          if (j === 0) {
            if (c._title) c._title.textContent = job.label;
            setCardSub(c, "排队中…");
          } else {
            c = buildPlaceholder(job.label, "排队中…");
            el.resultsList.insertBefore(c, prev.nextSibling);
          }
          prev = c;
          tasks.push(function () { return probeJob(job, c); });
        });
        Array.prototype.unshift.apply(taskQueue, tasks);
        pump();
      }, function (err) {
        addEntry(card, {
          "目标": target,
          "有效ProxyIP": false,
          "失败原因": "解析失败: " + (err && err.message ? err.message : String(err))
        });
        finishOne();
      });
  }

  function probeViaWorker(job, card) {
    setCardSub(card, "正在通过服务器检测…");
    var api = location.pathname + "?ip=" + encodeURIComponent(job.addr) + "&direct=1" +
      (job.sni ? "&sni=" + encodeURIComponent(job.sni) : "");

    return fetch(api, { headers: jsonHeaders() })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        var entry = Array.isArray(data) ? data[0] : data;
        if (data && !Array.isArray(data) && data.error) entry = { "有效ProxyIP": false, "失败原因": String(data.error) };
        if (!entry || typeof entry !== "object") entry = { "有效ProxyIP": false, "失败原因": "无返回结果" };
        return entry;
      })
      .catch(function (err) {
        return { "有效ProxyIP": false, "失败原因": "请求失败: " + (err && err.message ? err.message : String(err)) };
      });
  }

  function probeJob(job, card) {
    setCardSub(card, "正在检测中…");
    return probeExternalDirect(job)
      .then(function (entry) {
        return entry || probeViaWorker(job, card);
      })
      .then(function (entry) {
        entry["目标"] = job.label;
        if (job.isDomain) {
          entry["输入"] = job.input;
          entry["解析地址族"] = String(job.family || "").toUpperCase();
          if (job.source) entry["解析来源"] = job.source;
        }
        if (job.viaHostname && entry["有效ProxyIP"] !== true && entry["失败原因"]) {
          entry["失败原因"] = "DoH 未解析到 A/AAAA/TXT 记录，直连域名探测也失败：" + entry["失败原因"];
        }
        addEntry(card, entry);
        if (job.isDomain) {
          var validCount = 0;
          resultsData.forEach(function (e) {
            if (e["输入"] === job.input && e["有效ProxyIP"] === true) validCount++;
          });
          if (validCount === 2) refillGroup(job.input);
        }
        finishOne();
      });
  }

  function startCheck() {
    var targets = getTargets();
    el.singleInput.classList.remove("input-error");
    el.inputHint.classList.remove("error");

    if (targets.length === 0) {
      el.inputHint.textContent = "先输入至少一个目标";
      return;
    }

    if (mode === "batch" && targets.length > MAX_BATCH_TARGETS) {
      targets = targets.slice(0, MAX_BATCH_TARGETS);
    }

    if (mode === "single") {
      saveHistory(targets[0]);
    }

    el.runBtn.disabled = true;
    resetPanels(targets);

    taskQueue = [];
    targets.forEach(function (t, idx) {
      schedule(function () { return resolveInput(t, idx); });
    });
  }
  function plainIp(e) {
    var ip = String(e["ip"] || "");
    if (ip.charAt(0) === "[" && ip.charAt(ip.length - 1) === "]") ip = ip.slice(1, -1);
    return ip;
  }
  function hostPort(e) {
    var ip = plainIp(e);
    if (ip.indexOf(":") !== -1) ip = "[" + ip + "]";
    return ip + ":" + (e["端口"] != null ? e["端口"] : "");
  }
  function formatLine(e) {
    var country = e["出口国家"] || e["国家"] || "";
    var city = e["出口城市"] || e["城市"] || "";
    var asn = e["ASN"] ? "AS" + e["ASN"] : "";
    var exitIp = e["出口ip"] || "";
    var exitType = e["出口类型"] || "";
    var tail = [country, city, asn, e["组织"] || "", exitIp, exitType]
      .filter(function (x) { return x; })
      .join(" ");
    return hostPort(e) + (tail ? "#" + tail : "");
  }

  function validLines() {
    return resultsData
      .filter(function (e) { return e["有效ProxyIP"] === true; })
      .map(formatLine);
  }

  function download(filename, content, mime) {
    var blob = new Blob([content], { type: mime });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
  }

  el.copyBtn.addEventListener("click", function () {
    var lines = validLines();
    if (lines.length === 0) {
      showToast("暂无有效结果可复制", "error");
      return;
    }
    writeTextToClipboard(lines.join("\\n"))
      .then(function () {
        var original = el.copyBtn.textContent;
        el.copyBtn.textContent = "已复制";
        setTimeout(function () { el.copyBtn.textContent = original; }, 1200);
        showToast("已复制 " + lines.length + " 条有效结果", "success");
      })
      .catch(function (err) {
        console.error("复制失败", err);
        showToast("复制失败，请检查浏览器权限", "error");
      });
  });

  function failedLines() {
    var seen = {};
    var out = [];
    resultsData.forEach(function (e) {
      if (e["有效ProxyIP"] === true) return;
      var v = String(e["目标"] || "").trim();
      var arrow = v.indexOf(" -> ");
      if (arrow !== -1) v = v.slice(arrow + 4).trim();
      if (!v || seen[v]) return;
      seen[v] = true;
      out.push(v);
    });
    return out;
  }

  el.copyFailBtn.addEventListener("click", function () {
    var lines = failedLines();
    if (lines.length === 0) {
      showToast("暂无失败结果可复制", "error");
      return;
    }
    writeTextToClipboard(lines.join("\\n"))
      .then(function () {
        var original = el.copyFailBtn.textContent;
        el.copyFailBtn.textContent = "已复制";
        setTimeout(function () { el.copyFailBtn.textContent = original; }, 1200);
        showToast("已复制 " + lines.length + " 条失败结果", "success");
      })
      .catch(function (err) {
        console.error("复制失败", err);
        showToast("复制失败，请检查浏览器权限", "error");
      });
  });

  el.txtBtn.addEventListener("click", function () {
    var lines = validLines();
    if (lines.length === 0) return;
    download("proxyip-valid.txt", lines.join("\\n"), "text/plain;charset=utf-8");
  });

  el.csvBtn.addEventListener("click", function () {
    var valid = resultsData.filter(function (e) { return e["有效ProxyIP"] === true; });
    if (valid.length === 0) return;
    var header = ["节点", "ip", "端口", "国家", "城市", "ASN", "组织", "数据中心", "响应时间", "出口ip", "出口类型"];
    function cell(e, k) {
      if (k === "节点") return formatLine(e);
      if (k === "ip") return plainIp(e);
      if (k === "国家") return e["出口国家"] || e["国家"] || "";
      if (k === "城市") return e["出口城市"] || e["城市"] || "";
      var v = e[k];
      return v === undefined || v === null ? "" : String(v);
    }
    var rows = [header.join(",")];
    valid.forEach(function (e) {
      rows.push(header.map(function (k) {
        return '"' + cell(e, k).replace(/"/g, '""') + '"';
      }).join(","));
    });
    download("proxyip-valid.csv", "\\uFEFF" + rows.join("\\n"), "text/csv;charset=utf-8");
  });

  el.footerTime.textContent = new Date().getFullYear() + " · " + location.hostname;
})();
</script>
</body>
</html>`;

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === ECHO_PATH) {
      const cf = request.cf || {};
      const clientIp =
        request.headers.get("cf-connecting-ip") ||
        request.headers.get("true-client-ip") ||
        request.headers.get("x-forwarded-for") ||
        "";
      return new Response(
        JSON.stringify({
          ip: clientIp.split(",")[0].trim(),
          colo: cf.colo || "",
          country: cf.country || "",
          city: cf.city || "",
          asn: cf.asn || "",
          asOrganization: cf.asOrganization || "",
          httpProtocol: cf.httpProtocol || "",
          tlsVersion: cf.tlsVersion || "",
          ts: Date.now() / 1000
        }),
        { status: 200, headers: { "Content-Type": "application/json; charset=utf-8" } }
      );
    }

    const ipParam = url.searchParams.get("ip");

    if (!ipParam) {
      const acceptHeader = request.headers.get("accept") || "";
      if (acceptHeader.includes("text/html")) {
        return new Response(HTML_PAGE, {
          status: 200,
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });
      }
      return new Response(
        JSON.stringify(
          {
            error:
              "请提供 ip 参数，例如: /?ip=1.1.1.1,1.0.0.1:443,[2606:4700::]:443,proxy.example.com" +
              "（端口仅支持 1-65535，超出范围视为无效；域名若同时有 A 和 AAAA 记录，会自动分别探测 IPv4 和 IPv6 并都返回）"
          },
          null,
          2
        ),
        { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } }
      );
    }

    if (url.searchParams.get("resolve") === "1") {
      const list = await expandTarget(ipParam.split(",")[0]);
      const jobs = list.map((t) => ({
        host: t.host,
        port: t.port,
        addr: t.family === "ipv6" ? `[${t.host}]:${t.port}` : `${t.host}:${t.port}`,
        family: t.family,
        isDomain: !!t.isDomain,
        domain: t.domain || "",
        source: t.source || "",
        viaHostname: !!t.viaHostname,
        input: t.input,
        label: t.isDomain
          ? `${t.domain} -> ${displayHost(t.host, t.family)}:${t.port}`
          : `${displayHost(t.host, t.family)}:${t.port}`
      }));
      return new Response(JSON.stringify(jobs), {
        status: 200,
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Access-Control-Allow-Origin": "*"
        }
      });
    }

    let targets;
    if (url.searchParams.get("direct") === "1") {
      const spec = parseTargetSpec(ipParam.split(",")[0]);
      const [dHost, dPort] = parseHostPort(spec.target, 443);
      targets = dHost && isValidPort(dPort)
        ? [{
            host: dHost,
            port: dPort,
            input: spec.target,
            family: classifyHost(dHost),
            isDomain: false
          }]
        : [];
    } else {
      const parts = ipParam.split(",");
      const expanded = [];
      for (const raw of parts) expanded.push(await expandTarget(raw));
      targets = expanded.flat();
    }

    if (targets.length === 0) {
      return new Response(JSON.stringify([]), {
        headers: { "Content-Type": "application/json; charset=utf-8" }
      });
    }

    const outcomes = await runPool(targets, 3, (t) =>
      t.viaHostname
        ? probeWithTimeout(t.host, t.port).then((o) =>
            o.ok ? o : { ok: false, reason: "DoH 未解析到 A/AAAA/TXT 记录，直连域名探测也失败：" + o.reason }
          )
        : probeWithTimeout(t.host, t.port)
    );

    const output = outcomes.map((o, idx) => {
      const t = targets[idx];
      const targetLabel = t.isDomain
        ? `${t.domain} -> ${displayHost(t.host, t.family)}:${t.port}`
        : `${displayHost(t.host, t.family)}:${t.port}`;

      return {
        目标: targetLabel,
        ...(t.isDomain
          ? { 输入: t.input, 解析地址族: t.family ? t.family.toUpperCase() : "无", ...(t.source ? { 解析来源: t.source } : {}) }
          : {}),
        ...(o.ok
          ? { 有效ProxyIP: true, ...o.result }
          : { 有效ProxyIP: false, 失败原因: o.reason })
      };
    });

    return new Response(JSON.stringify(output, null, 2), {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Access-Control-Allow-Origin": "*"
      }
    });
  }
};
