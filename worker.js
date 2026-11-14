export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // --- KONFIGURASI DATABASE GITHUB ---
    const GH_OWNER = (env && env.GITHUB_OWNER) || "vitoa7117-cell";
    const GH_REPO = (env && env.GITHUB_REPO) || "pito-chat-live";
    const GH_TOKEN = (env && env.GITHUB_TOKEN) || "";
    const STATE_PATH = "data/state.json";
    const SEC_LOG_PATH = "data/security_logs.json";

    const DEFAULT_STATE = {
      messages: [],
      users: {},
      onlineUsers: {},
      posts: [],
      dms: [],
      banned: [],
      coins: {},
      ownedItems: {},
      bios: {},
      galleries: {},
      followers: {},
      botFollowerBoost: {},
      followRequests: {},
      accountPrivacy: {},
      inboxNotifications: {},
      checkinProgress: {},
      blocks: {},
      profilesMeta: {},
      vipStatus: {},
      passStatus: {},
      dailyClaim: {},
      bugReports: [],
      lostReports: [],
      devTheme: "rgb_rainbow",
      devAccessory: "acc_dev_crown",
      devLoginMsg: "👑 DEVELOPER RGB LAGI ON NIH! Sapa developer yuk!",
      announcementAudio: "",
      devOnlineAudio: "",
      announcement: null
    };

    function encodeBase64Unicode(str) {
      const bytes = new TextEncoder().encode(str);
      let bin = "";
      for (let i = 0; i < bytes.length; i++) {
        bin += String.fromCharCode(bytes[i]);
      }
      return btoa(bin);
    }

    function decodeBase64Unicode(b64) {
      const bin = atob(b64.replace(/\n/g, ""));
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) {
        bytes[i] = bin.charCodeAt(i);
      }
      return new TextDecoder().decode(bytes);
    }

    function cleanOnlineMap(mapObj) {
      const now = Date.now();
      const cleaned = {};
      if (!mapObj || typeof mapObj !== "object") return cleaned;
      for (const [uname, entry] of Object.entries(mapObj)) {
        const lastSeen = typeof entry === "number" ? entry : (entry && entry.time) || 0;
        if (now - lastSeen < 20000) {
          cleaned[uname] = typeof entry === "number" ? { time: lastSeen } : entry;
        }
      }
      return cleaned;
    }

    async function ghGetFile(path, fallback) {
      const apiUrl = "https://api.github.com/repos/" + GH_OWNER + "/" + GH_REPO + "/contents/" + path + "?ref=main&t=" + Date.now();
      const res = await fetch(apiUrl, {
        headers: {
          Authorization: "Bearer " + GH_TOKEN,
          Accept: "application/vnd.github+json",
          "User-Agent": "Chatty-GitHub-DB-Worker"
        }
      });
      if (res.status === 404) {
        return { data: fallback, sha: null };
      }
      if (!res.ok) {
        throw new Error("GitHub GET " + path + " gagal (" + res.status + ")");
      }
      const json = await res.json();
      const rawText = json.content ? decodeBase64Unicode(json.content) : "";
      let parsed = fallback;
      try {
        parsed = rawText ? JSON.parse(rawText) : fallback;
      } catch (_) {
        parsed = fallback;
      }
      return { data: parsed, sha: json.sha || null };
    }

    async function ghPutFile(path, dataObj, sha, commitMsg) {
      const apiUrl = "https://api.github.com/repos/" + GH_OWNER + "/" + GH_REPO + "/contents/" + path;
      const body = {
        message: commitMsg || ("Update " + path),
        content: encodeBase64Unicode(JSON.stringify(dataObj, null, 2)),
        branch: "main"
      };
      if (sha) body.sha = sha;

      const res = await fetch(apiUrl, {
        method: "PUT",
        headers: {
          Authorization: "Bearer " + GH_TOKEN,
          Accept: "application/vnd.github+json",
          "Content-Type": "application/json",
          "User-Agent": "Chatty-GitHub-DB-Worker"
        },
        body: JSON.stringify(body)
      });
      if (!res.ok) {
        const errTxt = await res.text();
        throw new Error("GitHub PUT " + path + " gagal (" + res.status + "): " + errTxt);
      }
      return await res.json();
    }

    async function appendSecurityLog(entry) {
      try {
        const { data: logs, sha } = await ghGetFile(SEC_LOG_PATH, []);
        const list = Array.isArray(logs) ? logs : [];
        list.unshift(entry);
        if (list.length > 50) list.length = 50;
        await ghPutFile(SEC_LOG_PATH, list, sha, "Update security audit log");
      } catch (_) {}
    }

    // --- 1. SISTEM KEAMANAN BERLAPIS & ANTI-VPN / PROXY DETECTOR ---
    const clientIP = request.headers.get("cf-connecting-ip") || request.headers.get("x-real-ip") || "unknown";
    const userAgent = request.headers.get("user-agent") || "unknown";
    const asn = request.headers.get("cf-ipasn") || "";
    const requestMethod = request.method;

    const knownDatacenterASNs = [14061, 16509, 8100, 20473, 63949, 9009, 24940];
    const isDatacenterIP = knownDatacenterASNs.includes(parseInt(asn, 10));
    const hasProxyHeaders =
      request.headers.has("via") ||
      request.headers.has("x-forwarded-for") ||
      request.headers.has("forwarded");

    if ((isDatacenterIP || hasProxyHeaders) && clientIP !== "127.0.0.1" && !url.pathname.startsWith("/api/")) {
      ctx && ctx.waitUntil(
        appendSecurityLog({
          id: "vpn_" + Date.now(),
          ip: clientIP,
          device: userAgent,
          toolUsed: "VPN / Proxy / Anonymous Network Detected",
          targetUrl: url.pathname,
          attackVector: "VPN/Datacenter IP Blocked (ASN: " + asn + ")",
          time: Date.now()
        })
      );

      return new Response(
        JSON.stringify({
          error: "ACCESS DENIED: VPN or Proxy connection is strictly prohibited for security accuracy. Please turn off your VPN.",
          ip: clientIP,
          detected_via: "VPN / Datacenter IP Shield"
        }),
        { status: 403, headers: { "Content-Type": "application/json" } }
      );
    }

    const maliciousSignatures = [
      "sqlmap",
      "nikto",
      "nmap",
      "burpsuite",
      "havij",
      "<script>",
      "javascript:",
      "union select",
      "eval(",
      "base64_decode"
    ];
    const fullUrlString = url.toString().toLowerCase();
    let isMalicious = false;
    let attackType = "";

    for (const sig of maliciousSignatures) {
      if (fullUrlString.includes(sig) || userAgent.toLowerCase().includes(sig)) {
        isMalicious = true;
        attackType = "Signature matched: " + sig;
        break;
      }
    }

    if (isMalicious) {
      ctx && ctx.waitUntil(
        appendSecurityLog({
          id: "atk_" + Date.now(),
          ip: clientIP,
          device: userAgent,
          toolUsed: userAgent.includes("Mozilla") ? "Browser / Custom Script" : "Automated Penetration Tool",
          targetUrl: url.pathname,
          attackVector: attackType || "Suspicious payload manipulation",
          time: Date.now()
        })
      );

      return new Response(
        JSON.stringify({
          error: "ACCESS DENIED: Security Shield Triggered. Your IP, Device Fingerprint, and Activity have been logged for legal report.",
          ip: clientIP,
          tool: userAgent
        }),
        { status: 403, headers: { "Content-Type": "application/json" } }
      );
    }

    // --- 2. API ENDPOINT DATABASE GITHUB REAL-TIME ---
    if (url.pathname === "/api/security/logs" && requestMethod === "GET") {
      try {
        const { data: logs } = await ghGetFile(SEC_LOG_PATH, []);
        return new Response(JSON.stringify(logs), {
          headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { "Content-Type": "application/json" }
        });
      }
    }

    if (url.pathname === "/api/online/ping" && requestMethod === "POST") {
      try {
        const payload = await request.json();
        const uname = payload && typeof payload.user === "string" ? payload.user.trim().toLowerCase() : "";
        if (!uname) {
          return new Response(JSON.stringify({ ok: false, error: "Invalid user" }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
          });
        }
        const { data: currentState, sha } = await ghGetFile(STATE_PATH, DEFAULT_STATE);
        const onlineMap = cleanOnlineMap(currentState.onlineUsers);
        onlineMap[uname] = { time: Date.now() };
        const merged = {
          ...DEFAULT_STATE,
          ...currentState,
          onlineUsers: onlineMap
        };
        await ghPutFile(STATE_PATH, merged, sha, "Heartbeat online: " + uname);
        return new Response(JSON.stringify({ ok: true, onlineUsers: onlineMap }), {
          headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { "Content-Type": "application/json" }
        });
      }
    }

    if (url.pathname === "/api/db/state" && requestMethod === "GET") {
      try {
        const { data: state } = await ghGetFile(STATE_PATH, DEFAULT_STATE);
        const cleanedOnline = cleanOnlineMap(state.onlineUsers);
        return new Response(JSON.stringify({ ...DEFAULT_STATE, ...state, onlineUsers: cleanedOnline }), {
          headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { "Content-Type": "application/json" }
        });
      }
    }

    if (url.pathname === "/api/db/state" && requestMethod === "POST") {
      try {
        const incoming = await request.json();
        const { data: currentState, sha } = await ghGetFile(STATE_PATH, DEFAULT_STATE);
        const merged = {
          ...DEFAULT_STATE,
          ...currentState,
          ...(incoming && typeof incoming === "object" ? incoming : {}),
          coins: {
            ...(currentState.coins || {}),
            ...((incoming && incoming.coins) || {})
          },
          ownedItems: {
            ...(currentState.ownedItems || {}),
            ...((incoming && incoming.ownedItems) || {})
          },
          onlineUsers: cleanOnlineMap((incoming && incoming.onlineUsers) || currentState.onlineUsers)
        };
        await ghPutFile(STATE_PATH, merged, sha, "Sync Chatty real-time state");
        return new Response(JSON.stringify({ ok: true, state: merged }), {
          headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { "Content-Type": "application/json" }
        });
      }
    }

    const html = `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Chatty - Ultimate Supreme Secure Edition</title>
<style>
* { box-sizing: border-box; }
:root {
  --glass-bg: rgba(255, 255, 255, 0.07);
  --glass-border: rgba(255, 255, 255, 0.15);
  --glass-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
  --glass-blur: blur(16px);
}

body {
  margin: 0; padding: 0; height: 100dvh;
  background-color: #050509;
  background-image: var(--bg-image, radial-gradient(circle at 50% 10%, #1e1b4b 0%, #090d16 70%));
  background-size: cover; background-position: center; background-repeat: no-repeat;
  color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  display: flex; flex-direction: column; overflow: hidden;
}

#splash-screen {
  position: fixed; inset: 0; background: #050509; z-index: 9999;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  transition: opacity 0.4s ease;
}
.loading-spinner {
  width: 55px; height: 55px; border: 4px solid rgba(56, 189, 248, 0.2);
  border-top-color: #38bdf8; border-radius: 50%;
  animation: spinLoad 0.8s linear infinite; margin-bottom: 16px;
}
@keyframes spinLoad { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }

#announcement-banner {
  position: fixed; top: -150px; left: 50%; transform: translateX(-50%);
  background: linear-gradient(135deg, rgba(147, 51, 234, 0.95), rgba(79, 70, 229, 0.95));
  color: white; padding: 14px 24px; border-radius: 16px; box-shadow: 0 10px 30px rgba(147, 51, 234, 0.5);
  z-index: 1000; font-size: 14px; font-weight: 600; text-align: center; max-width: 90%;
  border: 1.5px solid rgba(255,255,255,0.4); transition: top 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275);
  animation: glowBanner 2s infinite alternate;
}
#announcement-banner.show { top: 20px; }

@keyframes glowBanner {
  0% { box-shadow: 0 0 15px rgba(168, 85, 247, 0.6); }
  100% { box-shadow: 0 0 25px rgba(56, 189, 248, 0.8); }
}

.glow-text {
  background: linear-gradient(45deg, #ff0055, #ffcc00, #00ffff);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: bold;
}

#login-screen {
  position: fixed; inset: 0; background: rgba(5, 5, 9, 0.95);
  backdrop-filter: blur(24px); -webkit-backdrop-filter: blur(24px);
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  z-index: 200; padding: 20px; text-align: center; overflow-y: auto;
}
#login-screen h2 { color: #f8fafc; margin-bottom: 5px; font-size: 24px; font-weight: 600; }
.avatar-upload-box {
  width: 90px; height: 90px; border-radius: 50%; border: 1.5px dashed rgba(255,255,255,0.3);
  display: flex; align-items: center; justify-content: center; overflow: hidden;
  margin-bottom: 18px; cursor: pointer; background: var(--glass-bg); backdrop-filter: var(--glass-blur);
}
.avatar-upload-box img { width: 100%; height: 100%; object-fit: cover; }
#login-screen input[type="text"], #login-screen input[type="password"] {
  padding: 14px 18px; width: 100%; max-width: 300px; border-radius: 14px;
  border: 1px solid var(--glass-border); background: var(--glass-bg); color: white; font-size: 15px; margin-bottom: 12px; text-align: center; outline: none;
}
#login-screen button {
  padding: 14px 24px; border-radius: 14px; border: 1px solid rgba(255,255,255,0.2);
  background: linear-gradient(135deg, rgba(2, 132, 199, 0.8), rgba(3, 105, 161, 0.9)); color: white; font-weight: 600; font-size: 15px; cursor: pointer; width: 100%; max-width: 300px; margin-bottom: 8px;
}

header {
  background: var(--glass-bg); backdrop-filter: var(--glass-blur);
  padding: 10px 16px; display: flex; justify-content: space-between; align-items: center;
  border-bottom: 1px solid var(--glass-border); box-shadow: var(--glass-shadow); z-index: 10; flex-shrink: 0;
}
header h1 { font-size: 15px; margin: 0; color: #f8fafc; font-weight: 600; display: flex; flex-direction: column; gap: 2px; }
.online-indicator { font-size: 11px; color: #34d399; font-weight: normal; display: flex; align-items: center; gap: 4px; }
.online-dot { width: 8px; height: 8px; background: #34d399; border-radius: 50%; box-shadow: 0 0 8px #34d399; animation: pulseDot 2s infinite; }
@keyframes pulseDot { 0% { opacity: 1; } 50% { opacity: 0.4; } 100% { opacity: 1; } }

.header-right-actions { display: flex; align-items: center; gap: 6px; }
.bug-report-header-btn {
  background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.5); color: #fca5a5;
  padding: 5px 10px; border-radius: 10px; font-weight: 600; font-size: 11px; cursor: pointer; display: flex; align-items: center; gap: 4px; transition: 0.2s;
}
.bug-report-header-btn:hover { background: rgba(239, 68, 68, 0.4); color: white; }

#dev-btn {
  background: rgba(220, 38, 38, 0.8); backdrop-filter: var(--glass-blur); color: white; border: 1px solid rgba(255,255,255,0.2); padding: 5px 10px; border-radius: 10px; font-weight: 600; font-size: 11px; cursor: pointer; display: none;
}

.tab-content { flex: 1; overflow-y: auto; padding: 16px; display: none; flex-direction: column; gap: 10px; }
.tab-content.active { display: flex; }

.message {
  background: var(--glass-bg); backdrop-filter: var(--glass-blur);
  padding: 8px 12px; border-radius: 12px; max-width: 72%; border: 1px solid var(--glass-border);
  box-shadow: var(--glass-shadow); transition: 0.3s; position: relative;
  isolation: isolate; display: flex; flex-direction: column; gap: 2px;
  font-size: 13px; cursor: pointer;
}
.message:hover { border-color: #38bdf8; }
.message.my-message { margin-left: auto; background: rgba(2, 132, 199, 0.25); border-color: rgba(56, 189, 248, 0.4); }
.message.other-message { margin-right: auto; }

.message-header { display: flex; align-items: center; gap: 8px; margin-bottom: 2px; }

.reply-quote-box {
  background: rgba(0, 0, 0, 0.3); border-left: 3px solid #38bdf8;
  padding: 4px 8px; border-radius: 4px; font-size: 11px; margin-bottom: 4px; color: rgba(255,255,255,0.8);
}
.reply-preview-bar {
  display: none; background: rgba(15, 23, 42, 0.85); border-top: 1px solid var(--glass-border);
  padding: 6px 12px; font-size: 11px; justify-content: space-between; align-items: center; flex-shrink: 0;
}

@keyframes textFlow {
  0% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}
@keyframes rgbRainbow {
  0% { filter: hue-rotate(0deg); }
  100% { filter: hue-rotate(360deg); }
}
@keyframes bubbleGlow {
  0% { box-shadow: 0 0 8px var(--bub-glow, rgba(56,189,248,0.4)), inset 0 0 4px var(--bub-glow, rgba(56,189,248,0.2)); }
  100% { box-shadow: 0 0 20px var(--bub-glow, rgba(56,189,248,0.9)), inset 0 0 8px var(--bub-glow, rgba(56,189,248,0.5)); }
}
@keyframes floatAccessory {
  0% { transform: translateY(0px) scale(1) rotate(0deg); }
  50% { transform: translateY(-4px) scale(1.1) rotate(5deg); }
  100% { transform: translateY(0px) scale(1) rotate(0deg); }
}
@keyframes supremeAccessorySpin {
  0% { transform: translateY(0px) scale(1) rotate(0deg); filter: drop-shadow(0 0 8px #facc15); }
  50% { transform: translateY(-5px) scale(1.2) rotate(-8deg); filter: drop-shadow(0 0 15px #ff007f); }
  100% { transform: translateY(0px) scale(1) rotate(0deg); filter: drop-shadow(0 0 8px #facc15); }
}

.avatar-container { width: 38px; height: 38px; position: relative; display: flex; align-items: center; justify-content: center; flex-shrink: 0; cursor: pointer; }
.profile-pic-circle { width: 28px; height: 28px; border-radius: 50%; overflow: hidden; background: #0f172a; display: flex; align-items: center; justify-content: center; z-index: 2; position: relative; }
.profile-pic-circle img { width: 100%; height: 100%; object-fit: cover; }

.border-shape-ring { position: absolute; inset: 0; pointer-events: none; z-index: 3; transition: 0.3s; }
.border-circle { border-radius: 50%; border: 2px solid #38bdf8; }
.border-smooth-rect { border-radius: 10px; border: 2px solid #38bdf8; }
.border-hexagon { border-radius: 12px; clip-path: polygon(25% 6%, 75% 6%, 100% 50%, 75% 94%, 25% 94%, 0% 50%); border: 2px solid #38bdf8; }
.border-diamond { border-radius: 8px; clip-path: polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%); border: 2px solid #38bdf8; }
.border-octagon { border-radius: 10px; clip-path: polygon(30% 0%, 70% 0%, 100% 30%, 100% 70%, 70% 100%, 30% 100%, 0% 70%, 0% 30%); border: 2px solid #38bdf8; }
.border-star { border-radius: 6px; clip-path: polygon(50% 0%, 61% 35%, 98% 35%, 68% 57%, 79% 91%, 50% 70%, 21% 91%, 32% 57%, 2% 35%, 39% 35%); border: 2px solid #38bdf8; }

.frame-accessory-badge { position: absolute; top: -6px; right: -6px; font-size: 13px; z-index: 5; animation: floatAccessory 2s infinite ease-in-out; filter: drop-shadow(0 0 5px rgba(255,255,255,0.9)); }
.frame-accessory-supreme { position: absolute; top: -8px; right: -8px; font-size: 14px; z-index: 5; animation: supremeAccessorySpin 1.8s infinite ease-in-out, rgbRainbow 4s infinite linear; }

.dev-supreme-ring { border: 2.5px solid #facc15 !important; animation: devSpinGlink 4s infinite linear, rgbRainbow 6s infinite linear !important; }
@keyframes devSpinGlink { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
.dev-supreme-name { background-size: 300% 300% !important; -webkit-background-clip: text !important; -webkit-text-fill-color: transparent !important; font-weight: 900 !important; font-size: 13px !important; letter-spacing: 0.5px; animation: textFlow 3s ease infinite, rgbRainbow 5s infinite linear !important; }
.dev-supreme-bubble { background: linear-gradient(135deg, rgba(63, 41, 14, 0.95), rgba(30, 18, 5, 0.95)) !important; border: 2px solid #facc15 !important; box-shadow: 0 0 20px rgba(250, 204, 21, 0.8), inset 0 0 8px rgba(250, 204, 21, 0.4) !important; animation: bubbleGlow 2s infinite alternate, rgbRainbow 8s infinite linear !important; }
.dev-badge { color: #000 !important; font-size: 9px !important; padding: 1px 6px !important; border-radius: 4px !important; font-weight: 900 !important; box-shadow: 0 0 8px rgba(234,179,8,0.9) !important; display: inline-block !important; }
.vip-badge { background: linear-gradient(135deg, #fbbf24, #d97706); color: #000; font-size: 8px; padding: 1px 5px; border-radius: 4px; font-weight: bold; box-shadow: 0 0 6px rgba(251,191,36,0.8); }

.dyn-ring-live { border-color: var(--glow-color, #38bdf8) !important; box-shadow: 0 0 12px var(--glow-color, #38bdf8), inset 0 0 6px var(--glow-color, #38bdf8); animation: rgbRainbow 6s infinite linear; }
.dyn-name-live { background: var(--name-grad); background-size: 300% 300%; -webkit-background-clip: text; -webkit-text-fill-color: transparent; animation: textFlow 3s ease infinite, rgbRainbow 7s infinite linear; font-weight: bold; }
.dyn-bubble-live { background: var(--bub-bg) !important; border: 2px solid var(--bub-border) !important; animation: bubbleGlow 2s infinite alternate, rgbRainbow 9s infinite linear; }
.dyn-text-live { background: var(--txt-grad); background-size: 300% 300%; -webkit-background-clip: text; -webkit-text-fill-color: transparent; animation: textFlow 4s ease infinite, rgbRainbow 6s infinite linear; }

.card-box { background: var(--glass-bg); backdrop-filter: var(--glass-blur); border: 1px solid var(--glass-border); border-radius: 16px; padding: 14px; margin-bottom: 10px; box-shadow: var(--glass-shadow); }

.shop-category-container { background: rgba(15, 23, 42, 0.7); border: 1px solid var(--glass-border); border-radius: 12px; padding: 8px; margin-bottom: 10px; }
.shop-category-tabs { display: flex; gap: 6px; overflow-x: auto; padding-bottom: 4px; scrollbar-width: thin; scrollbar-color: #38bdf8 rgba(15, 23, 42, 0.5); }
.shop-cat-btn { background: rgba(30, 41, 59, 0.8); border: 1px solid var(--glass-border); color: #cbd5e1; padding: 8px 12px; border-radius: 8px; font-size: 12px; font-weight: 600; cursor: pointer; white-space: nowrap; transition: 0.2s; }
.shop-cat-btn.active { background: linear-gradient(135deg, #0284c7, #0369a1); color: white; border-color: #38bdf8; box-shadow: 0 0 10px rgba(56, 189, 248, 0.4); }

.shop-item { display: flex; justify-content: space-between; align-items: center; background: rgba(15, 23, 42, 0.45); backdrop-filter: var(--glass-blur); padding: 8px 12px; border-radius: 10px; margin-bottom: 6px; border: 1px solid rgba(255,255,255,0.08); }
.buy-btn { background: rgba(16, 185, 129, 0.85); color: white; border: 1px solid rgba(255,255,255,0.2); padding: 5px 12px; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 11px; }
.buy-btn.owned { background: rgba(71, 85, 105, 0.7); }
.buy-btn.equipped { background: #0284c7; border-color: #38bdf8; }
.buy-btn.topup { background: linear-gradient(135deg, #f59e0b, #d97706); }

.profile-stats { display: flex; justify-content: space-around; text-align: center; margin: 10px 0; padding: 8px 0; border-top: 1px solid rgba(255,255,255,0.1); border-bottom: 1px solid rgba(255,255,255,0.1); }
.stat-item { display: flex; flex-direction: column; font-size: 12px; color: rgba(255,255,255,0.6); cursor: pointer; }
.stat-item:hover .stat-num { color: #f43f5e; }
.stat-num { font-size: 15px; font-weight: bold; color: #38bdf8; }

.checkin-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; margin-top: 8px; }
.checkin-day-card { background: rgba(15, 23, 42, 0.65); border: 1px solid var(--glass-border); border-radius: 10px; padding: 6px 4px; text-align: center; font-size: 10px; }
.checkin-day-card.claimed { background: rgba(16, 185, 129, 0.25); border-color: #10b981; color: #6ee7b7; }
.checkin-day-card.next { border-color: #fbbf24; box-shadow: 0 0 10px rgba(251, 191, 36, 0.4); }

.gallery-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px; margin-top: 8px; }
.gallery-item { aspect-ratio: 1; border-radius: 8px; overflow: hidden; border: 1px solid var(--glass-border); background: rgba(0,0,0,0.3); position: relative; cursor: pointer; }
.gallery-item img { width: 100%; height: 100%; object-fit: cover; }
.gallery-like-badge { position: absolute; bottom: 3px; right: 3px; background: rgba(0,0,0,0.6); font-size: 9px; padding: 1px 5px; border-radius: 4px; color: #fbbf24; }
.bio-textarea { width: 100%; background: rgba(15,23,42,0.5); border: 1px solid var(--glass-border); border-radius: 8px; color: white; padding: 8px; font-size: 12px; resize: none; outline: none; margin-top: 6px; }

.dm-user-card { display: flex; align-items: center; justify-content: space-between; background: rgba(15, 23, 42, 0.5); border: 1px solid var(--glass-border); padding: 8px 12px; border-radius: 10px; cursor: pointer; transition: 0.2s; margin-bottom: 6px; }
.dm-user-card:hover { background: rgba(30, 41, 59, 0.8); border-color: #38bdf8; }
.dm-user-info { display: flex; align-items: center; gap: 8px; }
.status-indicator-badge { font-size: 9px; padding: 1px 5px; border-radius: 4px; font-weight: bold; }
.status-online { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
.status-offline { background: rgba(100, 116, 139, 0.2); color: #94a3b8; border: 1px solid #64748b; }

.autocomplete-dropdown { position: absolute; top: 100%; left: 0; right: 0; background: rgba(15, 23, 42, 0.97); backdrop-filter: blur(20px); border: 1px solid var(--glass-border); border-radius: 8px; max-height: 140px; overflow-y: auto; z-index: 400; display: none; box-shadow: 0 10px 25px rgba(0,0,0,0.6); margin-top: 4px; }
.autocomplete-item { display: flex; align-items: center; gap: 8px; padding: 6px 10px; cursor: pointer; border-bottom: 1px solid rgba(255,255,255,0.05); transition: 0.15s; }
.autocomplete-item:hover { background: rgba(56, 189, 248, 0.2); }

#nav-bar { background: var(--glass-bg); backdrop-filter: var(--glass-blur); border-top: 1px solid var(--glass-border); display: flex; justify-content: space-around; padding: 6px 0 12px 0; flex-shrink: 0; }
.nav-item { background: none; border: none; color: rgba(255,255,255,0.5); font-size: 10px; display: flex; flex-direction: column; align-items: center; gap: 2px; cursor: pointer; flex: 1; position: relative; }
.nav-item.active { color: #38bdf8; font-weight: 600; }
.nav-item span.icon { font-size: 17px; }
.nav-badge-dot { position: absolute; top: 2px; right: 24%; background: #ef4444; color: white; font-size: 8px; padding: 1px 4px; border-radius: 999px; font-weight: bold; display: none; }

#chat-input-area { flex-shrink: 0; width: 100%; }
#input-container { padding: 8px 12px; background: var(--glass-bg); backdrop-filter: var(--glass-blur); display: flex; gap: 6px; border-top: 1px solid var(--glass-border); width: 100%; }
#message-input { flex: 1; padding: 10px 14px; border-radius: 12px; border: 1px solid var(--glass-border); background: rgba(15, 23, 42, 0.4); color: white; font-size: 14px; outline: none; }
#send-btn { padding: 10px 18px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.2); background: linear-gradient(135deg, #0284c7, #0369a1); color: white; font-weight: 600; cursor: pointer; font-size: 13px; }

.modal-overlay { position: fixed; inset: 0; background: rgba(5, 5, 9, 0.85); backdrop-filter: blur(20px); display: none; align-items: center; justify-content: center; z-index: 300; padding: 16px; }
.modal-content { background: rgba(30, 41, 59, 0.85); backdrop-filter: blur(30px); width: 100%; max-width: 380px; border-radius: 18px; padding: 16px; border: 1px solid var(--glass-border); display: flex; flex-direction: column; align-items: center; text-align: center; max-height: 85vh; overflow-y: auto; }
.dev-section { background: rgba(15, 23, 42, 0.6); padding: 10px; border-radius: 10px; margin-bottom: 8px; width: 100%; text-align: left; border: 1px solid var(--glass-border); }
.stalking-user-row { display: flex; justify-content: space-between; align-items: center; background: rgba(30,41,59,0.6); padding: 6px 10px; border-radius: 8px; margin-bottom: 5px; font-size: 11px; }
.user-item { display: flex; justify-content: space-between; align-items: center; background: rgba(30, 41, 59, 0.5); padding: 6px 10px; border-radius: 8px; font-size: 11px; margin-bottom: 5px; }
.ban-btn { background: rgba(220, 38, 38, 0.85); color: white; border: none; padding: 3px 8px; border-radius: 6px; cursor: pointer; font-size: 10px; font-weight: bold; }

.global-post-card { background: rgba(15, 23, 42, 0.65); border: 1px solid var(--glass-border); border-radius: 14px; padding: 10px; margin-bottom: 12px; box-shadow: var(--glass-shadow); }
.global-post-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
.global-post-img-wrap { width: 100%; aspect-ratio: 4/3; border-radius: 10px; overflow: hidden; background: #000; margin-bottom: 8px; position: relative; }
.global-post-img-wrap img { width: 100%; height: 100%; object-fit: contain; }
.global-post-actions { display: flex; align-items: center; gap: 12px; margin-bottom: 6px; font-size: 14px; }
.action-btn { background: none; border: none; color: white; cursor: pointer; display: flex; align-items: center; gap: 4px; font-size: 13px; font-weight: bold; }
.action-btn:hover { color: #38bdf8; }

.floating-plus-btn {
  position: fixed; bottom: 70px; right: 20px; width: 55px; height: 55px; border-radius: 50%;
  background: linear-gradient(135deg, #0284c7, #38bdf8); color: white; font-size: 26px; border: none;
  box-shadow: 0 4px 20px rgba(56, 189, 248, 0.6); display: flex; align-items: center; justify-content: center;
  cursor: pointer; z-index: 100; transition: transform 0.2s;
}
.floating-plus-btn:hover { transform: scale(1.1); }

.bot-photo-picker-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px; max-height: 120px; overflow-y: auto; background: rgba(15,23,42,0.8); padding: 6px; border-radius: 8px; border: 1px solid var(--glass-border); margin-bottom: 6px; }
.bot-photo-picker-item { aspect-ratio: 1; border-radius: 6px; overflow: hidden; border: 2px solid transparent; cursor: pointer; position: relative; }
.bot-photo-picker-item img { width: 100%; height: 100%; object-fit: cover; }
.bot-photo-picker-item.selected { border-color: #38bdf8; box-shadow: 0 0 10px rgba(56,189,248,0.8); }
</style>
</head>
<body>

<div id="splash-screen">
  <div class="loading-spinner"></div>
  <h2 style="color:#38bdf8; font-size:20px; margin:0;">Memuat Chatty Secure...</h2>
  <p style="color:rgba(255,255,255,0.6); font-size:12px; margin-top:6px;">GitHub Real-Time DB & Anti-VPN Aktif</p>
</div>

<div id="announcement-banner">📢 <span id="announcement-text" class="glow-text">Pengumuman Developer</span></div>

<div id="login-screen">
  <h2>💬 Chatty Global Chat</h2>
  <p style="font-size:13px; color:rgba(255,255,255,0.6); margin-bottom:16px;">Pastikan VPN mati, pilih foto profil, lalu masukkan username & password.</p>
  
  <div class="avatar-upload-box" onclick="document.getElementById('file-avatar').click()">
    <span style="font-size:12px; color:#38bdf8;" id="avatar-label">📷 Foto</span>
    <img id="preview-avatar" src="" alt="Avatar" style="display:none;">
  </div>
  <input type="file" id="file-avatar" accept="image/*" style="display:none;" onchange="loadAvatar(event)">

  <input type="text" id="login-username" placeholder="👤 Username..." maxlength="15">
  <input type="password" id="login-password" placeholder="🔑 Password..." maxlength="20">
  <button onclick="handleLoginRegister()">🚀 Masuk / Buat Akun</button>
  <button onclick="openLostAccountModal()" style="background: rgba(239,68,68,0.2); border: 1px solid rgba(239,68,68,0.4); color: #fca5a5; font-size:13px;">⚠️ Lapor Kehilangan Akun</button>
</div>

<header>
  <h1 id="header-title">
    💬 Ruang Chat Global (Secure)
    <span class="online-indicator"><span class="online-dot"></span> <span id="online-count-text">1 orang online</span></span>
  </h1>
  <div class="header-right-actions">
    <button class="bug-report-header-btn" onclick="openBugReportModal()">⚠️ Lapor Bug</button>
    <button id="dev-btn" onclick="openDevModal()">⚙️ Developer Panel</button>
  </div>
</header>

<div id="tab-chat" class="tab-content active">
  <div id="chat-container"></div>
</div>

<div id="tab-post" class="tab-content" style="display:none; flex-direction:column; height:100%;">
  <div class="card-box" style="margin-bottom:8px;">
    <h3 style="margin-top:0; font-size:15px; color:#38bdf8;">🌐 Live Foto & Postingan Global</h3>
    <p style="font-size:11px; color:rgba(255,255,255,0.6); margin:0;">Bagikan momen foto, hashtag, like & komentar ke semua pengguna.</p>
  </div>
  <div id="global-posts-container" style="flex:1; overflow-y:auto; display:flex; flex-direction:column; gap:8px; padding-bottom:60px;"></div>
  <button class="floating-plus-btn" onclick="openCreatePostModal()">➕</button>
</div>

<div id="tab-dm" class="tab-content" style="display:none; flex-direction:column; height:100%;">
  <div id="dm-list-view" style="flex:1; overflow-y:auto; display:flex; flex-direction:column;">
    <div class="card-box">
      <h3 style="margin-top:0; font-size:15px; color:#38bdf8;">📥 Kotak Masuk Pesan Privat</h3>
      <p style="font-size:11px; color:rgba(255,255,255,0.6);">Pilih profil di bawah untuk mulai atau melanjutkan obrolan.</p>
    </div>
    <div id="dm-profiles-container" style="display:flex; flex-direction:column; gap:6px;"></div>
  </div>

  <div id="dm-chat-view" style="display:none; flex-direction:column; height:100%;">
    <div style="display:flex; align-items:center; gap:8px; background:var(--glass-bg); padding:8px 12px; border-radius:10px; border:1px solid var(--glass-border); margin-bottom:8px; flex-shrink:0;">
      <button onclick="backToDMList()" style="background:none; border:none; color:#38bdf8; font-size:14px; cursor:pointer; font-weight:bold;">⬅️ Kembali</button>
      <span id="active-dm-target-name" style="font-weight:bold; color:#f8fafc; font-size:14px;">Username</span>
    </div>
    <div id="dm-container" style="flex:1; overflow-y:auto; display:flex; flex-direction:column; gap:8px; margin-bottom:8px;"></div>
    <div id="dm-reply-preview" class="reply-preview-bar">
      <div>↩️ Membalas <b id="dm-reply-target-user"></b>: <span id="dm-reply-target-text" style="color:rgba(255,255,255,0.7);"></span></div>
      <button onclick="cancelReply()" style="background:none; border:none; color:#ef4444; font-weight:bold; cursor:pointer;">✕</button>
    </div>
    <div style="display:flex; gap:6px; flex-shrink:0;">
      <input type="text" id="dm-input" placeholder="✉️ Tulis pesan privat..." style="flex:1; padding:10px; background:rgba(15,23,42,0.6); color:white; border:1px solid var(--glass-border); border-radius:10px; outline:none; font-size:13px;" onkeypress="checkDMPress(event)">
      <button onclick="sendDM()" style="padding:10px 16px; background:linear-gradient(135deg, #0284c7, #0369a1); color:white; border-radius:10px; font-weight:600; cursor:pointer; font-size:13px;">Kirim</button>
    </div>
  </div>
</div>

<div id="tab-inbox" class="tab-content">
  <div class="card-box">
    <div style="display:flex; justify-content:space-between; align-items:center;">
      <h3 style="margin:0; font-size:15px; color:#38bdf8;">🔔 Kotak Masuk Notifikasi</h3>
      <button onclick="clearMyInbox()" style="background:rgba(71,85,105,0.8); border:none; color:white; padding:4px 8px; border-radius:6px; font-size:10px; cursor:pointer;">Bersihkan</button>
    </div>
    <p style="font-size:11px; color:rgba(255,255,255,0.6); margin:4px 0 0 0;">Permintaan follow akun privat, like postingan, dan pengikut baru.</p>
  </div>
  <div id="inbox-notifications-list" style="display:flex; flex-direction:column; gap:6px;"></div>
</div>

<div id="tab-profile" class="tab-content">
  <div class="card-box" style="text-align:center;">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
      <button id="privacy-toggle-btn" onclick="toggleMyPrivacyMode()" style="background:rgba(2,132,199,0.25); color:#7dd3fc; border:1px solid rgba(56,189,248,0.5); padding:5px 10px; border-radius:8px; font-size:10px; font-weight:700; cursor:pointer;">🌐 Akun: Publik</button>
      <button onclick="logoutAccount()" style="background:rgba(220,38,38,0.85); color:white; border:1px solid rgba(255,255,255,0.2); padding:5px 10px; border-radius:8px; font-size:10px; font-weight:600; cursor:pointer;">🚪 Log Out</button>
    </div>
    <div style="width:65px; height:65px; margin:0 auto 10px; display:flex; align-items:center; justify-content:center;" id="profile-avatar-box"></div>
    <button onclick="document.getElementById('file-avatar-profile').click()" style="background:linear-gradient(135deg, #0284c7, #0369a1); color:white; border-radius:8px; padding:6px 14px; font-size:11px; cursor:pointer; margin-bottom:8px; font-weight:600;">📷 Ganti Foto Profil</button>
    <input type="file" id="file-avatar-profile" accept="image/*" style="display:none;" onchange="updateProfileAvatar(event)">
    <h3 id="profile-name" style="margin:4px 0; color:#f8fafc; font-size:18px;">Username</h3>
    <div id="daily-claim-box" style="display:none; margin:8px 0;">
      <button onclick="claimDailyCoins()" style="background:linear-gradient(135deg, #f59e0b, #d97706); color:white; border:none; padding:7px 12px; border-radius:8px; font-weight:bold; font-size:11px; cursor:pointer; box-shadow:0 0 10px rgba(245,158,11,0.5);">🎁 Klaim +100 Koin Harian VIP</button>
    </div>
    <textarea id="profile-bio-input" class="bio-textarea" placeholder="Tulis bio singkat tentang dirimu..." maxlength="120" onchange="saveMyBio(this.value)"></textarea>
    <div class="profile-stats">
      <div class="stat-item" onclick="openFollowListModal(currentUser, 'followers')"><span>Pengikut</span><span class="stat-num" id="my-followers-count">0</span></div>
      <div class="stat-item" onclick="openFollowListModal(currentUser, 'following')"><span>Mengikuti</span><span class="stat-num" id="my-following-count">0</span></div>
      <div class="stat-item"><span>Koin</span><span class="stat-num" id="user-coins">50</span></div>
    </div>

    <div style="text-align:left; background:rgba(15,23,42,0.55); border:1px solid var(--glass-border); border-radius:12px; padding:10px; margin-bottom:10px;">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <b style="font-size:12px; color:#fbbf24;">📅 Check-In Harian 7 Hari (Pengguna Baru)</b>
        <span id="checkin-streak-badge" style="font-size:10px; color:#38bdf8; font-weight:bold;">Hari 0/7</span>
      </div>
      <div class="checkin-grid" id="checkin-week-grid"></div>
      <button id="claim-weekly-checkin-btn" onclick="claimWeeklyCheckin()" style="width:100%; margin-top:8px; padding:7px; background:linear-gradient(135deg,#10b981,#059669); border:none; color:white; border-radius:8px; font-weight:bold; font-size:11px; cursor:pointer;">🎁 Klaim Check-In Hari Ini</button>
    </div>

    <h4 style="text-align:left; font-size:13px; color:#38bdf8; margin:8px 0 4px 0;">🖼️ Galeri Foto Saya</h4>
    <button onclick="document.getElementById('file-gallery-upload').click()" style="width:100%; padding:7px; background:rgba(16,185,129,0.8); color:white; border-radius:8px; border:none; font-weight:600; font-size:11px; cursor:pointer; margin-bottom:6px;">➕ Tambah Foto ke Galeri</button>
    <input type="file" id="file-gallery-upload" accept="image/*" style="display:none;" onchange="uploadGalleryPhoto(event)">
    <div class="gallery-grid" id="my-gallery-grid"></div>
  </div>
</div>

<div id="tab-shop" class="tab-content">
  <div class="card-box">
    <h3 style="color:#fbbf24; margin-top:0; font-size:15px;">🛒 Toko VIP, Top Up Koin & Aksesoris Bingkai</h3>
    <p style="font-size:11px; color:rgba(255,255,255,0.6);">Beli Koin, Paket VIP, Bentuk Border Garis, Aksesoris Emoji Melayang, & Efek RGB!</p>
    <p style="font-size:13px; font-weight:600; color:#38bdf8;">Koin Anda: <span id="shop-coins">50</span> 💰</p>
  </div>
  <div class="shop-category-container">
    <div class="shop-category-tabs">
      <button class="shop-cat-btn active" onclick="renderShopCategory('vip', this)">👑 VIP & Koin</button>
      <button class="shop-cat-btn" onclick="renderShopCategory('shape', this)">📐 Bentuk Border</button>
      <button class="shop-cat-btn" onclick="renderShopCategory('accessory', this)">✨ Aksesoris Emoji</button>
      <button class="shop-cat-btn" onclick="renderShopCategory('frame', this)">🎨 Bingkai RGB</button>
      <button class="shop-cat-btn" onclick="renderShopCategory('bubble', this)">💬 Bubble RGB</button>
      <button class="shop-cat-btn" onclick="renderShopCategory('name', this)">🌈 Nama RGB</button>
      <button class="shop-cat-btn" onclick="renderShopCategory('font', this)">✍️ Gaya Font</button>
      <button class="shop-cat-btn" onclick="renderShopCategory('text', this)">✨ Teks RGB</button>
    </div>
  </div>
  <div id="shop-items-list" style="display:flex; flex-direction:column; gap:5px;"></div>
</div>

<!-- SEMUA MODAL -->
<div id="create-post-modal" class="modal-overlay" onclick="document.getElementById('create-post-modal').style.display='none'">
  <div class="modal-content" onclick="event.stopPropagation()" style="max-width:340px; text-align:left;">
    <h3 style="color:#38bdf8; margin-top:0; font-size:15px;">➕ Buat Postingan Live Foto Global</h3>
    <div class="avatar-upload-box" style="width:100%; height:120px; border-radius:10px; margin-bottom:8px;" onclick="document.getElementById('file-new-global-post').click()">
      <span style="font-size:12px; color:#38bdf8;" id="new-post-preview-label">📷 Pilih Gambar</span>
      <img id="new-post-preview-img" src="" alt="Preview" style="display:none; width:100%; height:100%; object-fit:cover;">
    </div>
    <input type="file" id="file-new-global-post" accept="image/*" style="display:none;" onchange="loadNewPostImage(event)">
    <textarea id="new-post-caption-input" placeholder="Tulis keterangan & hashtag (contoh: #liburan #chatty)..." style="width:100%; height:80px; background:rgba(15,23,42,0.8); color:white; border:1px solid var(--glass-border); border-radius:8px; padding:8px; font-size:12px; resize:none; outline:none; margin-bottom:8px;"></textarea>
    <div style="display:flex; gap:6px;">
      <button onclick="saveAndPublishGlobalPost()" style="flex:1; background:#10b981; border:none; color:white; padding:8px; border-radius:8px; font-weight:bold; cursor:pointer; font-size:12px;">Simpan & Publikasikan</button>
      <button onclick="document.getElementById('create-post-modal').style.display='none'" style="background:rgba(71,85,105,0.8); border:none; color:white; padding:8px 12px; border-radius:8px; cursor:pointer; font-size:12px;">Batal</button>
    </div>
  </div>
</div>

<div id="follow-list-modal" class="modal-overlay" onclick="document.getElementById('follow-list-modal').style.display='none'">
  <div class="modal-content" onclick="event.stopPropagation()" style="max-width:330px; text-align:left;">
    <h3 id="follow-list-modal-title" style="color:#38bdf8; margin-top:0; font-size:15px;">👥 Daftar</h3>
    <div id="follow-list-modal-body" style="max-height:240px; overflow-y:auto; width:100%; display:flex; flex-direction:column; gap:6px; margin-bottom:10px;"></div>
    <button onclick="document.getElementById('follow-list-modal').style.display='none'" style="width:100%; background:rgba(71,85,105,0.8); border:none; color:white; padding:7px; border-radius:8px; cursor:pointer; font-size:12px;">Tutup</button>
  </div>
</div>

<div id="lost-account-modal" class="modal-overlay" onclick="document.getElementById('lost-account-modal').style.display='none'">
  <div class="modal-content" onclick="event.stopPropagation()" style="max-width:340px; text-align:left;">
    <h3 style="color:#fbbf24; margin-top:0; font-size:15px;">⚠️ Lapor Kehilangan Akun</h3>
    <input type="text" id="lost-username-input" placeholder="👤 Masukkan perkiraan username..." style="width:100%; padding:8px; background:rgba(15,23,42,0.8); color:white; border:1px solid var(--glass-border); border-radius:8px; font-size:12px; outline:none; margin-bottom:6px;">
    <textarea id="lost-details-input" placeholder="📝 Jelaskan detail ciri-ciri akun atau pesan terakhir..." style="width:100%; height:80px; background:rgba(15,23,42,0.8); color:white; border:1px solid var(--glass-border); border-radius:8px; padding:8px; font-size:12px; resize:none; outline:none; margin-bottom:8px;"></textarea>
    <div style="display:flex; gap:6px;">
      <button onclick="submitLostAccountReport()" style="flex:1; background:#f59e0b; border:none; color:white; padding:8px; border-radius:8px; font-weight:bold; cursor:pointer; font-size:12px;">Kirim ke Developer</button>
      <button onclick="document.getElementById('lost-account-modal').style.display='none'" style="background:rgba(71,85,105,0.8); border:none; color:white; padding:8px 12px; border-radius:8px; cursor:pointer; font-size:12px;">Batal</button>
    </div>
  </div>
</div>

<div id="bug-report-modal" class="modal-overlay" onclick="document.getElementById('bug-report-modal').style.display='none'">
  <div class="modal-content" onclick="event.stopPropagation()" style="max-width:340px; text-align:left;">
    <h3 style="color:#ef4444; margin-top:0; font-size:15px;">⚠️ Form Laporan Bug Website</h3>
    <textarea id="bug-report-text-input" placeholder="Jelaskan bug atau kendala yang Anda temui..." style="width:100%; height:90px; background:rgba(15,23,42,0.8); color:white; border:1px solid var(--glass-border); border-radius:8px; padding:8px; font-size:12px; resize:none; outline:none; margin-bottom:8px;"></textarea>
    <div style="display:flex; gap:6px;">
      <button onclick="submitBugReport()" style="flex:1; background:#ef4444; border:none; color:white; padding:8px; border-radius:8px; font-weight:bold; cursor:pointer; font-size:12px;">Kirim Laporan</button>
      <button onclick="document.getElementById('bug-report-modal').style.display='none'" style="background:rgba(71,85,105,0.8); border:none; color:white; padding:8px 12px; border-radius:8px; cursor:pointer; font-size:12px;">Batal</button>
    </div>
  </div>
</div>

<div id="user-profile-modal" class="modal-overlay" onclick="closeUserProfileModal(event)">
  <div class="modal-content" onclick="event.stopPropagation()">
    <div style="width:65px; height:65px; margin:0 auto 8px; display:flex; align-items:center; justify-content:center;" id="modal-user-avatar"></div>
    <div style="display:flex; align-items:center; gap:6px; margin-bottom:4px;">
      <h3 id="modal-username" style="margin:0; color:#38bdf8; font-size:16px;">Username</h3>
      <span id="modal-vip-badge-container"></span>
    </div>
    <div id="modal-privacy-tag" style="font-size:10px; color:#fbbf24; margin-bottom:4px;"></div>
    <p id="modal-user-bio" style="font-size:12px; color:rgba(255,255,255,0.8); background:rgba(15,23,42,0.4); padding:6px 10px; border-radius:8px; width:100%; margin-bottom:8px;"></p>
    <div style="display:flex; justify-content:space-around; width:100%; font-size:12px; margin-bottom:10px;">
      <div style="cursor:pointer;" onclick="openFollowListModal(viewingUser, 'followers')">Pengikut: <b id="modal-followers-num" style="color:#38bdf8;">0</b></div>
      <div style="cursor:pointer;" onclick="openFollowListModal(viewingUser, 'following')">Mengikuti: <b id="modal-following-num" style="color:#38bdf8;">0</b></div>
    </div>
    <div style="display:flex; gap:6px; width:100%; margin-bottom:10px;">
      <button id="modal-follow-btn" onclick="toggleFollowUser()" style="flex:1; padding:8px; background:#10b981; border:none; color:white; border-radius:8px; font-weight:bold; cursor:pointer; font-size:12px;">➕ Ikuti</button>
      <button id="modal-block-btn" onclick="toggleBlockUser()" style="flex:1; padding:8px; background:#ef4444; border:none; color:white; border-radius:8px; font-weight:bold; cursor:pointer; font-size:12px;">🚫 Blokir</button>
    </div>
    <h4 style="text-align:left; font-size:12px; color:#38bdf8; margin:4px 0;">🖼️ Galeri Foto</h4>
    <div class="gallery-grid" id="modal-user-gallery"></div>
    <button onclick="document.getElementById('user-profile-modal').style.display='none'" style="width:100%; padding:7px; background:rgba(71,85,105,0.8); border:none; color:white; border-radius:8px; cursor:pointer; margin-top:10px; font-size:12px;">Tutup</button>
  </div>
</div>

<div id="photo-detail-modal" class="modal-overlay" onclick="document.getElementById('photo-detail-modal').style.display='none'">
  <div class="modal-content" onclick="event.stopPropagation()" style="max-width:340px;">
    <img id="detail-photo-img" src="" style="width:100%; border-radius:10px; max-height:240px; object-fit:contain; background:#000; margin-bottom:10px;">
    <div style="display:flex; justify-content:space-around; width:100%; margin-bottom:10px; font-size:13px;">
      <button onclick="triggerDetailLike()" id="detail-like-btn" style="background:rgba(255,255,255,0.1); border:1px solid var(--glass-border); color:white; padding:6px 12px; border-radius:8px; cursor:pointer; font-weight:bold;">❤️ <span id="detail-like-count">0</span> Suka</button>
      <button onclick="sharePhotoLink()" style="background:rgba(255,255,255,0.1); border:1px solid var(--glass-border); color:white; padding:6px 12px; border-radius:8px; cursor:pointer; font-weight:bold;">🔗 Bagikan</button>
    </div>
    <div style="width:100%; text-align:left; margin-bottom:6px; font-size:12px; color:#38bdf8;">💬 Komentar:</div>
    <div id="detail-comments-list" style="width:100%; max-height:100px; overflow-y:auto; background:rgba(15,23,42,0.5); border-radius:8px; padding:6px; margin-bottom:6px; font-size:11px; text-align:left; display:flex; flex-direction:column; gap:5px;"></div>
    <div style="display:flex; gap:5px; width:100%;">
      <input type="text" id="detail-comment-input" placeholder="Tulis komentar..." style="flex:1; padding:6px; background:rgba(15,23,42,0.8); color:white; border:1px solid var(--glass-border); border-radius:6px; outline:none; font-size:11px;">
      <button onclick="postPhotoComment()" style="background:#0284c7; border:none; color:white; padding:6px 10px; border-radius:6px; font-weight:bold; cursor:pointer; font-size:11px;">Kirim</button>
    </div>
  </div>
</div>

<div id="dev-modal" class="modal-overlay">
  <div class="modal-content" style="max-width:400px; text-align:left;">
    <h3 style="color:#f87171; margin-top:0; font-size:16px;">⚙️ Developer Control Panel & Security Log</h3>
    <div class="dev-section" style="background: rgba(239, 68, 68, 0.15); border-color: rgba(239, 68, 68, 0.4);">
      <h4 style="margin:0 0 5px 0; color:#fca5a5; font-size:13px;">🛡️ Security Audit & Intrusion Logs (GitHub DB)</h4>
      <div id="security-logs-container" style="width:100%; max-height:150px; overflow-y:auto; display:flex; flex-direction:column; gap:6px; margin-bottom:5px;">
        <span style="font-size:11px; color:rgba(255,255,255,0.4); text-align:center;">Belum ada percobaan serangan atau VPN tercatat.</span>
      </div>
      <button onclick="loadSecurityAuditLogs()" style="background:#dc2626; border:none; color:white; padding:5px; border-radius:6px; font-weight:bold; cursor:pointer; width:100%; font-size:11px;">🔄 Muat Ulang Log Keamanan</button>
    </div>

    <div class="dev-section" style="background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.4);">
      <h4 style="margin:0 0 5px 0; color:#34d399; font-size:13px;">🎵 Kostum Suara Notifikasi (Terpisah)</h4>
      <div style="font-size:11px; color:#cbd5e1; margin-bottom:3px;">📢 Suara Pengumuman Global:</div>
      <input type="file" id="dev-ann-audio-file" accept="audio/*" onchange="uploadCustomAnnouncementAudio(event)" style="font-size:10px; color:#cbd5e1; margin-bottom:4px; width:100%;">
      <button onclick="testCustomAudio('announcement')" style="background:#059669; border:none; color:white; padding:4px 8px; border-radius:6px; font-weight:bold; cursor:pointer; width:100%; font-size:10px; margin-bottom:8px;">🔊 Tes Suara Pengumuman</button>

      <div style="font-size:11px; color:#fbbf24; margin-bottom:3px;">👑 Suara Admin / Developer Datang:</div>
      <input type="file" id="dev-online-audio-file" accept="audio/*" onchange="uploadCustomDevOnlineAudio(event)" style="font-size:10px; color:#cbd5e1; margin-bottom:4px; width:100%;">
      <button onclick="testCustomAudio('dev_online')" style="background:#d97706; border:none; color:white; padding:4px 8px; border-radius:6px; font-weight:bold; cursor:pointer; width:100%; font-size:10px;">🔊 Tes Suara Admin Datang</button>
    </div>

    <div class="dev-section" style="background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.4);">
      <h4 style="margin:0 0 5px 0; color:#fbbf24; font-size:13px;">⚠️ Laporan Kehilangan Akun (<span id="lost-report-count">0</span>)</h4>
      <div id="dev-lost-reports-list" style="max-height:100px; overflow-y:auto; display:flex; flex-direction:column; gap:5px; margin-bottom:5px;"></div>
    </div>
    <div class="dev-section" style="background: rgba(56, 189, 248, 0.15); border-color: rgba(56, 189, 248, 0.4);">
      <h4 style="margin:0 0 5px 0; color:#38bdf8; font-size:13px;">🔍 Search Account Database (Cek Password)</h4>
      <input type="text" id="dev-search-acc-input" placeholder="🔍 Cari berdasarkan username..." oninput="filterDevSearchAccounts(this.value)" style="width:100%; padding:7px; background:rgba(15,23,42,0.8); color:white; border:1px solid var(--glass-border); border-radius:6px; font-size:11px; outline:none; margin-bottom:5px;">
      <div id="dev-search-acc-list" style="max-height:90px; overflow-y:auto; display:flex; flex-direction:column; gap:4px;"></div>
    </div>
    <div class="dev-section" style="background: rgba(239, 68, 68, 0.15); border-color: rgba(239, 68, 68, 0.4);">
      <h4 style="margin:0 0 5px 0; color:#fca5a5; font-size:13px;">📥 Laporan Bug Masuk (<span id="bug-report-count">0</span>)</h4>
      <div id="dev-bug-reports-list" style="max-height:90px; overflow-y:auto; display:flex; flex-direction:column; gap:5px; margin-bottom:5px;"></div>
    </div>
    <div class="dev-section" style="background: rgba(147, 51, 234, 0.15); border-color: rgba(147, 51, 234, 0.4);">
      <h4 style="margin:0 0 5px 0; color:#c084fc; font-size:13px;">⚙️ Kustomisasi Notifikasi Developer Login</h4>
      <input type="text" id="dev-login-msg-input" placeholder="Teks notifikasi developer login..." style="width:100%; padding:7px; background:rgba(15,23,42,0.8); color:white; border:1px solid var(--glass-border); border-radius:6px; font-size:11px; outline:none; margin-bottom:5px;">
      <button onclick="saveDevLoginMessage()" style="background:#9333ea; border:none; color:white; padding:6px 10px; border-radius:6px; font-weight:bold; cursor:pointer; width:100%; font-size:11px;">Simpan Teks Notifikasi</button>
    </div>
    <div class="dev-section" style="background: rgba(250, 204, 21, 0.15); border-color: rgba(250, 204, 21, 0.4);">
      <h4 style="margin:0 0 5px 0; color:#facc15; font-size:13px;">👑 Aksesoris Emoji Supreme Developer</h4>
      <select id="dev-accessory-select" onchange="changeDevAccessory(this.value)" style="width:100%; padding:8px; background:rgba(15,23,42,0.9); color:#facc15; font-weight:bold; border:1px solid #facc15; border-radius:6px; margin-bottom:5px; outline:none; font-size:12px;">
        <option value="acc_dev_crown">👑 Mahkota Raja Berlian Emas Supreme</option>
        <option value="acc_dev_fire">🔥 Api Naga Mistik Menyala Terang</option>
        <option value="acc_dev_galaxy">🌌 Galaksi Bintang Legendaris Abadi</option>
        <option value="acc_dev_skull">💀 Tengkorak Kristal Hitam Phantom</option>
        <option value="acc_dev_angel">👼 Sayap Malaikat Suci Bersinar</option>
      </select>
    </div>

    <div class="dev-section" style="background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.4); position:relative;">
      <h4 style="margin:0 0 5px 0; color:#fbbf24; font-size:13px;">👑 Gift Premium (Search Username)</h4>
      <input type="text" id="dev-gift-prem-search" placeholder="🔍 Ketik username target premium..." oninput="handleGiftSearchInput('prem', this.value)" autocomplete="off" style="width:100%; padding:7px; background:rgba(15,23,42,0.8); color:white; border:1px solid var(--glass-border); border-radius:6px; margin-bottom:4px; outline:none; font-size:11px;">
      <div id="dev-gift-prem-dropdown" class="autocomplete-dropdown"></div>
      <div style="font-size:10px; color:#fbbf24; margin-bottom:4px;">Target: <b id="dev-gift-prem-selected">-</b></div>
      <select id="dev-give-tier" style="width:100%; padding:7px; background:rgba(15,23,42,0.8); color:#fbbf24; font-weight:bold; border:1px solid var(--glass-border); border-radius:6px; margin-bottom:6px; outline:none; font-size:12px;">
        <option value="2days">👑 Premium 2 Hari</option>
        <option value="1month">👑 Premium 1 Bulan</option>
        <option value="3months">👑 Premium 3 Bulan</option>
        <option value="permanent">👑 Premium Permanen</option>
      </select>
      <button onclick="devExecuteGivePremium()" style="background:linear-gradient(135deg, #f59e0b, #d97706); border:none; color:white; padding:7px 12px; border-radius:6px; font-weight:bold; cursor:pointer; width:100%; font-size:11px;">Berikan Paket Premium Sekarang</button>
    </div>

    <div class="dev-section" style="background: rgba(220, 38, 38, 0.15); border-color: rgba(220, 38, 38, 0.4);">
      <h4 style="margin:0 0 5px 0; color:#ef4444; font-size:13px;">🗑️ Hapus Seluruh Chat Global</h4>
      <button onclick="clearGlobalChat()" style="background:#ef4444; border:none; color:white; padding:7px 12px; border-radius:6px; font-weight:bold; cursor:pointer; width:100%; font-size:11px;">Hapus Semua Chat Global</button>
    </div>
    <div class="dev-section">
      <h4 style="margin:0 0 6px 0; color:#fbbf24; font-size:13px;">👑 Kustomisasi Warna RGB & Efek Developer</h4>
      <select id="dev-badge-style-select" onchange="changeDevBadgeStyle(this.value)" style="width:100%; padding:8px; background:rgba(15,23,42,0.8); color:#facc15; font-weight:bold; border:1px solid #facc15; border-radius:6px; margin-bottom:5px; outline:none; font-size:12px;">
        <option value="rgb_rainbow">🌈 RGB Rainbow Dynamic Flow (Default)</option>
        <option value="gold_shine">🌟 Emas Mewah Berkilaunya Abadi</option>
        <option value="diamond_neon">💎 Berlian Neon Biru Sinar</option>
        <option value="fire_ruby">🔥 Ruby Api Menyala Terang</option>
        <option value="purple_galaxy">🌌 Ungu Galaksi Legendaris</option>
      </select>
    </div>
    <div class="dev-section">
      <h4 style="margin:0 0 6px 0; color:#38bdf8; font-size:13px;">📢 Kirim Pengumuman Global</h4>
      <textarea id="dev-announcement-input" placeholder="Tulis teks pengumuman untuk semua user..." style="width:100%; padding:7px; background:rgba(15,23,42,0.6); color:white; border:1px solid var(--glass-border); border-radius:6px; font-size:11px; resize:none; outline:none; margin-bottom:5px;"></textarea>
      <select id="dev-announcement-duration" style="width:100%; padding:7px; background:rgba(15,23,42,0.8); color:white; border:1px solid var(--glass-border); border-radius:6px; font-size:11px; outline:none; margin-bottom:6px;">
        <option value="5000">5 Detik</option>
        <option value="10000" selected>10 Detik</option>
        <option value="15000">15 Detik</option>
        <option value="30000">30 Detik</option>
        <option value="60000">1 Menit</option>
      </select>
      <button onclick="sendGlobalAnnouncement()" style="background:#3b82f6; border:none; color:white; padding:7px 12px; border-radius:6px; font-weight:bold; cursor:pointer; width:100%; font-size:11px;">Kirim Pengumuman</button>
    </div>
    <div class="dev-section" style="position: relative;">
      <h4 style="margin:0 0 6px 0; color:#38bdf8; font-size:13px;">🤖 Bot Otomatis (Follower Visual-Only)</h4>
      <div style="position: relative; margin-bottom: 5px;">
        <input type="text" id="dev-bot-search" placeholder="🔍 Ketik username target bot..." oninput="handleBotSearchInput(this.value)" autocomplete="off" style="width:100%; padding:8px 10px; background:rgba(15,23,42,0.8); color:white; border:1px solid var(--glass-border); border-radius:6px; font-size:11px; outline:none;">
        <div id="bot-autocomplete-dropdown" class="autocomplete-dropdown"></div>
      </div>
      <div id="dev-bot-target-display" style="font-size:11px; color:#fbbf24; margin-bottom:5px; font-weight:bold;">Target Dipilih: <span id="selected-bot-target-text">- Belum ada -</span></div>
      <div id="bot-photo-picker-container" class="bot-photo-picker-grid"></div>
      <input type="number" id="dev-bot-custom-amount" value="50" min="1" max="100000000" style="width:100%; padding:7px 8px; background:rgba(15,23,42,0.8); color:#38bdf8; font-weight:bold; border:1px solid var(--glass-border); border-radius:6px; font-size:12px; outline:none; margin-bottom:6px;">
      <div style="display:flex; gap:6px;">
        <button onclick="runBotAddFollowers()" style="flex:1; background:#8b5cf6; border:none; color:white; padding:7px; border-radius:6px; font-weight:bold; cursor:pointer; font-size:11px;">🤖 +Followers (Visual)</button>
        <button onclick="runBotAddLikesToTargetPhoto()" style="flex:1; background:#ec4899; border:none; color:white; padding:7px; border-radius:6px; font-weight:bold; cursor:pointer; font-size:11px;">🤖 +Likes Foto Pilihan</button>
      </div>
    </div>
    <div class="dev-section">
      <h4 style="margin:0 0 6px 0; color:#38bdf8; font-size:13px;">🎵 Musik Publik & Mute Semua</h4>
      <input type="file" id="dev-audio-file" accept="audio/*" onchange="uploadDevAudio(event)" style="font-size:11px; color:#cbd5e1; margin-bottom:5px;">
      <button onclick="toggleMuteGlobalAudio()" id="mute-global-btn" style="width:100%; background:#ef4444; border:none; color:white; padding:5px; border-radius:6px; font-weight:bold; cursor:pointer; font-size:10px;">🔇 Mute Musik untuk Semua</button>
      <p id="now-playing-label" style="font-size:10px; color:#38bdf8; margin:4px 0 0 0;">Belum ada lagu diputar.</p>
    </div>
    <div class="dev-section">
      <h4 style="font-size:13px; margin:0 0 5px 0;">🎨 Upload Wallpaper Background</h4>
      <input type="file" id="dev-bg-file" accept="image/*" onchange="uploadDevBackground(event)" style="font-size:11px; color:#cbd5e1; margin-bottom:5px;">
      <button onclick="resetBackground()" style="background:rgba(71,85,105,0.7); color:white; border:none; padding:5px 10px; border-radius:6px; font-size:10px; cursor:pointer; font-weight:600;">Reset Wallpaper Default</button>
    </div>
    <div class="dev-section">
      <h4 style="margin:0 0 6px 0; color:#38bdf8; font-size:13px;">🔍 Stalking Pengguna Online (<span id="stalking-online-count">0</span>)</h4>
      <div id="stalking-users-list" style="max-height:70px; overflow-y:auto; display:flex; flex-direction:column; gap:5px;"></div>
    </div>
    <div class="dev-section">
      <h4 style="margin:0 0 6px 0; color:#38bdf8; font-size:13px;">🔨 Ban User</h4>
      <input type="text" id="search-ban-input" placeholder="🔍 Cari username..." oninput="filterDevBanUsers(this.value)" style="width:100%; padding:7px; background:rgba(15,23,42,0.6); color:white; border:1px solid var(--glass-border); border-radius:6px; font-size:11px; outline:none; margin-bottom:5px;">
      <input type="text" id="dev-ban-reason-input" placeholder="📝 Alasan ban..." style="width:100%; padding:7px; background:rgba(15,23,42,0.6); color:white; border:1px solid var(--glass-border); border-radius:6px; font-size:11px; outline:none; margin-bottom:5px;">
      <div id="dev-ban-list" style="max-height:70px; overflow-y:auto; display:flex; flex-direction:column; gap:5px;"></div>
    </div>

    <div class="dev-section" style="position:relative;">
      <h4 style="margin:0 0 6px 0; color:#38bdf8; font-size:13px;">💰 Gift Koin (Search Username)</h4>
      <input type="text" id="dev-gift-coin-search" placeholder="🔍 Ketik username target koin..." oninput="handleGiftSearchInput('coin', this.value)" autocomplete="off" style="width:100%; padding:7px; background:rgba(15,23,42,0.8); color:white; border:1px solid var(--glass-border); border-radius:6px; margin-bottom:4px; outline:none; font-size:11px;">
      <div id="dev-gift-coin-dropdown" class="autocomplete-dropdown"></div>
      <div style="font-size:10px; color:#38bdf8; margin-bottom:4px;">Target: <b id="dev-gift-coin-selected">-</b></div>
      <div style="display:flex; gap:6px;">
        <input type="number" id="dev-coin-amount" placeholder="Jumlah koin..." value="100" style="flex:1; padding:7px; background:rgba(15,23,42,0.6); color:white; border:1px solid var(--glass-border); border-radius:6px; outline:none; font-size:11px;">
        <button onclick="devGiveCoins()" style="background:#10b981; border:none; color:white; padding:7px 12px; border-radius:6px; font-weight:bold; cursor:pointer; font-size:11px;">Kirim</button>
      </div>
    </div>

    <button onclick="closeDevModal()" style="background:rgba(71,85,105,0.8); color:white; border:none; padding:8px; width:100%; border-radius:8px; cursor:pointer; font-weight:600; font-size:12px;">Tutup Panel</button>
  </div>
</div>

<div id="chat-input-area">
  <div id="chat-reply-preview" class="reply-preview-bar">
    <div>↩️ Membalas <b id="chat-reply-target-user"></b>: <span id="chat-reply-target-text" style="color:rgba(255,255,255,0.7);"></span></div>
    <button onclick="cancelReply()" style="background:none; border:none; color:#ef4444; font-weight:bold; cursor:pointer;">✕</button>
  </div>
  <div id="input-container">
    <input type="text" id="message-input" placeholder="💬 Tulis pesan..." autocomplete="off" onkeypress="checkEnter(event)">
    <button id="send-btn" onclick="sendMessage()">Kirim</button>
  </div>
</div>

<nav id="nav-bar">
  <button class="nav-item active" onclick="switchTab('chat', this)"><span class="icon">💬</span> Chat</button>
  <button class="nav-item" onclick="switchTab('post', this)"><span class="icon">📷</span> Live Foto</button>
  <button class="nav-item" onclick="switchTab('dm', this)"><span class="icon">🔒</span> DM</button>
  <button class="nav-item" onclick="switchTab('inbox', this)"><span class="icon">🔔</span> Kotak Masuk<span id="inbox-nav-badge" class="nav-badge-dot">0</span></button>
  <button class="nav-item" onclick="switchTab('profile', this)"><span class="icon">👤</span> Profil</button>
  <button class="nav-item" onclick="switchTab('shop', this)"><span class="icon">🛒</span> Toko</button>
</nav>

<audio id="global-bg-audio" loop></audio>

<script>
const DEV_NAME = "pito";
const DEV_PASS = "pito jago banget";

function hideSplashScreen() {
  var splash = document.getElementById('splash-screen');
  if (splash && splash.style.display !== 'none') {
    splash.style.opacity = '0';
    setTimeout(function() {
      if (splash) splash.style.display = 'none';
    }, 350);
  }
}

setTimeout(hideSplashScreen, 2500);

function sanitizeHTML(str) {
  if (!str) return "";
  var temp = document.createElement('div');
  temp.textContent = str;
  return temp.innerHTML;
}

function formatCompactNumber(num) {
  if (num >= 1000000000) return (num / 1000000000).toFixed(1).replace(/\.0$/, '') + 'M';
  if (num >= 1000000) return (num / 1000000).toFixed(1).replace(/\.0$/, '') + 'JT';
  if (num >= 1000) return (num / 1000).toFixed(1).replace(/\.0$/, '') + 'K';
  return num.toString();
}

const WEEKLY_CHECKIN_REWARDS = [25, 50, 75, 100, 150, 200, 350];

const BORDER_SHAPES = [
  { id: "shape_circle", name: "Border Lingkaran Klasik", class: "border-circle", price: 0 },
  { id: "shape_smooth_rect", name: "Border Kotak Melengkung", class: "border-smooth-rect", price: 150 },
  { id: "shape_hexagon", name: "Border Hexagon (Segi Enam)", class: "border-hexagon", price: 280 },
  { id: "shape_diamond", name: "Border Diamond (Belah Ketupat)", class: "border-diamond", price: 420 },
  { id: "shape_octagon", name: "Border Octagon (Segi Delapan)", class: "border-octagon", price: 560 },
  { id: "shape_star", name: "Border Bintang Mewah", class: "border-star", price: 850 }
];

const BORDER_ACCESSORIES = [
  { id: "acc_none", name: "Tanpa Aksesoris", emoji: "", price: 0 },
  { id: "acc_crown", name: "Mahkota Emas (👑)", emoji: "👑", price: 300 },
  { id: "acc_diamond", name: "Berlian Bersinar (💎)", emoji: "💎", price: 450 },
  { id: "acc_star", name: "Bintang Berkilau (⭐)", emoji: "⭐", price: 360 },
  { id: "acc_fire", name: "Api Menyala (🔥)", emoji: "🔥", price: 390 },
  { id: "acc_heart", name: "Hati Cinta (💖)", emoji: "💖", price: 330 }
];

const DEV_SUPREME_ACCESSORIES = {
  "acc_dev_crown": { name: "Mahkota Raja Berlian Emas Supreme", emoji: "👑" },
  "acc_dev_fire": { name: "Api Naga Mistik Menyala Terang", emoji: "🔥" },
  "acc_dev_galaxy": { name: "Galaksi Bintang Legendaris Abadi", emoji: "🌌" },
  "acc_dev_skull": { name: "Tengkorak Kristal Hitam Phantom", emoji: "💀" },
  "acc_dev_angel": { name: "Sayap Malaikat Suci Bersinar", emoji: "👼" }
};

const THEME_PALETTES = [
  { name: "RGB Cyber Rainbow", c1: "#00f2fe", c2: "#ff007f", bg: "rgba(3, 105, 161, 0.9)" },
  { name: "Inferno Magma RGB", c1: "#ff0844", c2: "#ffb199", bg: "rgba(185, 28, 28, 0.9)" },
  { name: "Royal Emerald RGB", c1: "#00b09b", c2: "#96c93d", bg: "rgba(6, 95, 70, 0.9)" },
  { name: "Electric Violet RGB", c1: "#b224ef", c2: "#7579ff", bg: "rgba(107, 33, 168, 0.9)" },
  { name: "Solar Gold RGB", c1: "#f6d365", c2: "#fda085", bg: "rgba(180, 83, 9, 0.9)" },
  { name: "Sakura Blossom RGB", c1: "#ff9a9e", c2: "#fecfef", bg: "rgba(190, 24, 93, 0.9)" },
  { name: "Aurora Borealis RGB", c1: "#43e97b", c2: "#38f9d7", bg: "rgba(17, 94, 89, 0.9)" },
  { name: "Deep Space RGB", c1: "#667eea", c2: "#764ba2", bg: "rgba(49, 46, 129, 0.9)" },
  { name: "Sunset Blaze RGB", c1: "#fa709a", c2: "#fee140", bg: "rgba(154, 52, 18, 0.9)" },
  { name: "Arctic Ice RGB", c1: "#a1c4fd", c2: "#c2e9fb", bg: "rgba(14, 116, 144, 0.9)" }
];

const FONT_STYLES = [
  { name: "Font Italic (Miring)", style: "font-style: italic;" },
  { name: "Font Bold (Tebal)", style: "font-weight: 800;" },
  { name: "Font Monospace", style: "font-family: monospace;" },
  { name: "Font Cursive (Bersambung)", style: "font-family: cursive;" },
  { name: "Font Serif Klasik", style: "font-family: serif;" },
  { name: "Font Uppercase (Kapital)", style: "text-transform: uppercase; letter-spacing: 1px;" }
];

function getEffectStyleData(itemId) {
  if (!itemId) return null;
  var parts = itemId.split('_');
  var idx = parseInt(parts[1], 10);
  if (isNaN(idx)) return null;
  var base = THEME_PALETTES[idx % THEME_PALETTES.length];
  var hueOffset = Math.floor(idx / THEME_PALETTES.length) * 65;
  return {
    name: base.name + " #" + (idx + 1),
    price: 300 + (idx * 45),
    c1: base.c1,
    c2: base.c2,
    bg: base.bg,
    hue: hueOffset
  };
}

function getFontStyleData(itemId) {
  if (!itemId) return null;
  var idx = parseInt(itemId.split('_')[1], 10);
  if (isNaN(idx)) return null;
  var base = FONT_STYLES[idx % FONT_STYLES.length];
  return { name: base.name + " #" + (idx + 1), price: 250 + (idx * 35), style: base.style };
}

function playWindowsStartupSound() {
  try {
    var AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) return;
    var ctx = new AudioCtx();
    var notes = [523.25, 659.25, 783.99, 1046.50];
    notes.forEach(function(freq, i) {
      var osc = ctx.createOscillator();
      var gain = ctx.createGain();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(freq, ctx.currentTime + (i * 0.15));
      gain.gain.setValueAtTime(0.15, ctx.currentTime + (i * 0.15));
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + (i * 0.15) + 0.8);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(ctx.currentTime + (i * 0.15));
      osc.stop(ctx.currentTime + (i * 0.15) + 0.8);
    });
  } catch (e) {}
}

let announcementAudioData = "";
let devOnlineAudioData = "";

function playSoundEffect(type) {
  try {
    if (type === 'announcement' && announcementAudioData) {
      var aud1 = new Audio(announcementAudioData);
      aud1.play().catch(function() {});
      return;
    }
    if (type === 'dev_online' && devOnlineAudioData) {
      var aud2 = new Audio(devOnlineAudioData);
      aud2.play().catch(function() {});
      return;
    }
    var AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) return;
    var ctx = new AudioCtx();
    var osc = ctx.createOscillator();
    var gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    if (type === 'ban') {
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(150, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(40, ctx.currentTime + 0.4);
      gain.gain.setValueAtTime(0.3, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.4);
      osc.start();
      osc.stop(ctx.currentTime + 0.4);
    } else if (type === 'announcement' || type === 'dev_online') {
      osc.type = 'sine';
      osc.frequency.setValueAtTime(523.25, ctx.currentTime);
      osc.frequency.setValueAtTime(659.25, ctx.currentTime + 0.15);
      osc.frequency.setValueAtTime(783.99, ctx.currentTime + 0.3);
      gain.gain.setValueAtTime(0.2, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.6);
      osc.start();
      osc.stop(ctx.currentTime + 0.6);
    }
  } catch (e) {}
}

async function uploadCustomAnnouncementAudio(event) {
  if (currentUser !== DEV_NAME) return;
  var file = event.target.files[0];
  if (!file) return;
  if (file.size > 2.5 * 1024 * 1024) { alert("Ukuran file audio maksimal 2.5MB."); return; }
  var reader = new FileReader();
  reader.onload = async function(ev) {
    announcementAudioData = ev.target.result;
    await pushGitHubState({ announcementAudio: announcementAudioData });
    alert("📢 Suara kostum pengumuman berhasil disimpan & disinkronkan!");
  };
  reader.readAsDataURL(file);
}

async function uploadCustomDevOnlineAudio(event) {
  if (currentUser !== DEV_NAME) return;
  var file = event.target.files[0];
  if (!file) return;
  if (file.size > 2.5 * 1024 * 1024) { alert("Ukuran file audio maksimal 2.5MB."); return; }
  var reader = new FileReader();
  reader.onload = async function(ev) {
    devOnlineAudioData = ev.target.result;
    await pushGitHubState({ devOnlineAudio: devOnlineAudioData });
    alert("👑 Suara kostum admin/developer datang berhasil disimpan & disinkronkan!");
  };
  reader.readAsDataURL(file);
}

function testCustomAudio(kind) {
  playSoundEffect(kind);
}

let currentUser = "";
let currentAvatar = "";
let userCoins = 50;
let ownedItems = [];
let userDatabase = {};
let onlineUsersMap = {};
let bannedUsers = [];
let userBios = {};
let userGalleries = {};
let userFollowers = {};
let botFollowerBoost = {};
let followRequests = {};
let accountPrivacy = {};
let inboxNotifications = {};
let checkinProgress = {};
let userBlocks = {};
let userProfilesMeta = {};
let userVipStatus = {};
let userPassStatus = {};
let userDailyClaim = {};
let messages = [];
let dmMessages = [];
let globalPosts = [];
let bugReports = [];
let lostReports = [];
let customBgImage = "";
let activeDevTheme = 'rgb_rainbow';
let activeDevAccessory = 'acc_dev_crown';
let devLoginNotificationText = "👑 DEVELOPER RGB LAGI ON NIH! Sapa developer yuk!";
let lastAnnouncementKey = "";
let lastDevOnlineKey = "";
let currentReplyData = null;

function getActiveOnlineMap() {
  var now = Date.now();
  var active = {};
  if (!onlineUsersMap || typeof onlineUsersMap !== "object") return active;
  for (var pair of Object.entries(onlineUsersMap)) {
    var uname = pair[0];
    var entry = pair[1];
    var lastSeen = typeof entry === "number" ? entry : (entry && entry.time) || 0;
    if (now - lastSeen < 20000) {
      active[uname] = entry;
    }
  }
  return active;
}

function renderOnlineCounterUI() {
  var active = getActiveOnlineMap();
  var count = Math.max(Object.keys(active).length, currentUser ? 1 : 0);
  var countText = document.getElementById('online-count-text');
  if (countText) countText.textContent = count + " orang online";
}

function getFollowerDisplayCount(username) {
  var realCount = (userFollowers[username] || []).length;
  var botCount = Number(botFollowerBoost[username] || 0);
  return realCount + botCount;
}

function getFollowingUsers(username) {
  var res = [];
  for (var u in userFollowers) {
    if ((userFollowers[u] || []).includes(username)) {
      res.push(u);
    }
  }
  return res;
}

function canViewPrivateProfile(targetUser) {
  if (!targetUser || targetUser === currentUser || currentUser === DEV_NAME) return true;
  if (!accountPrivacy[targetUser]) return true;
  return (userFollowers[targetUser] || []).includes(currentUser);
}

async function pushInboxNotification(targetUser, notifObj) {
  if (!targetUser || targetUser === currentUser) return;
  if (!inboxNotifications[targetUser]) inboxNotifications[targetUser] = [];
  inboxNotifications[targetUser].unshift(Object.assign({
    id: 'notif_' + Date.now() + '_' + Math.random(),
    from: currentUser,
    time: Date.now()
  }, notifObj));
  if (inboxNotifications[targetUser].length > 50) {
    inboxNotifications[targetUser].length = 50;
  }
  await pushGitHubState({ inboxNotifications: inboxNotifications });
}

function renderInboxBadge() {
  var badge = document.getElementById('inbox-nav-badge');
  if (!badge || !currentUser) return;
  var list = inboxNotifications[currentUser] || [];
  var pendingReq = ((followRequests || {})[currentUser] || []).length;
  var total = list.length + pendingReq;
  if (total > 0) {
    badge.style.display = 'inline-block';
    badge.textContent = total > 99 ? '99+' : String(total);
  } else {
    badge.style.display = 'none';
  }
}

function applyRemoteState(state) {
  if (!state || typeof state !== "object") return;
  userDatabase = state.users || {};
  if (!userDatabase[DEV_NAME]) userDatabase[DEV_NAME] = DEV_PASS;

  if (state.onlineUsers && typeof state.onlineUsers === "object") {
    onlineUsersMap = state.onlineUsers;
  }

  messages = Array.isArray(state.messages) ? state.messages : [];
  dmMessages = Array.isArray(state.dms) ? state.dms : [];
  globalPosts = Array.isArray(state.posts) ? state.posts : [];
  bannedUsers = Array.isArray(state.banned) ? state.banned : [];
  bugReports = Array.isArray(state.bugReports) ? state.bugReports : [];
  lostReports = Array.isArray(state.lostReports) ? state.lostReports : [];

  userBios = state.bios || {};
  userGalleries = state.galleries || {};
  userFollowers = state.followers || {};
  botFollowerBoost = state.botFollowerBoost || {};
  followRequests = state.followRequests || {};
  accountPrivacy = state.accountPrivacy || {};
  inboxNotifications = state.inboxNotifications || {};
  checkinProgress = state.checkinProgress || {};
  userBlocks = state.blocks || {};
  userProfilesMeta = state.profilesMeta || {};
  userVipStatus = state.vipStatus || {};
  userPassStatus = state.passStatus || {};
  userDailyClaim = state.dailyClaim || {};

  if (state.devTheme) activeDevTheme = state.devTheme;
  if (state.devAccessory) activeDevAccessory = state.devAccessory;
  if (state.devLoginMsg) devLoginNotificationText = state.devLoginMsg;
  if (typeof state.announcementAudio === "string") announcementAudioData = state.announcementAudio;
  if (typeof state.devOnlineAudio === "string") devOnlineAudioData = state.devOnlineAudio;

  if (currentUser) {
    var coinsMap = state.coins || {};
    if (typeof coinsMap[currentUser] === "number") userCoins = coinsMap[currentUser];
    var itemsMap = state.ownedItems || {};
    if (Array.isArray(itemsMap[currentUser])) ownedItems = itemsMap[currentUser];
    var meta = userProfilesMeta[currentUser];
    if (meta) {
      if (meta.avatar) currentAvatar = meta.avatar;
      if (meta.frame) activeFrame = meta.frame;
      if (meta.bubble) activeBubble = meta.bubble;
      if (meta.nameEffect) activeNameEffect = meta.nameEffect;
      if (meta.textEffect) activeTextEffect = meta.textEffect;
      if (meta.fontEffect) activeFontEffect = meta.fontEffect;
      if (meta.shape) activeBorderShape = meta.shape;
      if (meta.accessory) activeAccessory = meta.accessory;
    }
  }

  var activeOnline = getActiveOnlineMap();
  if (currentUser && currentUser !== DEV_NAME && activeOnline[DEV_NAME]) {
    var devEntry = activeOnline[DEV_NAME];
    var devKey = DEV_NAME + "_" + ((devEntry && devEntry.time) || "on");
    if (devKey !== lastDevOnlineKey) {
      lastDevOnlineKey = devKey;
      playSoundEffect('dev_online');
      showAnnouncementBanner(devLoginNotificationText, 8000);
    }
  }

  if (state.announcement && state.announcement.time) {
    var key = state.announcement.time + "_" + state.announcement.text;
    if (key !== lastAnnouncementKey) {
      lastAnnouncementKey = key;
      showAnnouncementBanner(state.announcement.text, state.announcement.duration || 10000);
    }
  }
}

async function pullGitHubState() {
  try {
    var res = await fetch('/api/db/state', { cache: 'no-store' });
    if (!res.ok) return;
    var state = await res.json();
    applyRemoteState(state);

    if (currentUser && bannedUsers.includes(currentUser)) {
      alert("AKSES DITOLAK: Akun Anda telah dibanned!");
      localStorage.removeItem('chat_current_user');
      location.reload();
      return;
    }

    renderOnlineCounterUI();
    renderInboxBadge();
    updateCoinsDisplay();
    renderMessages();
    renderGlobalPosts();
    if (activeDMTarget) renderDM(activeDMTarget);
    var dmTab = document.getElementById('tab-dm');
    if (dmTab && dmTab.style.display === 'flex') {
      renderDMProfileList();
    }
    var inboxTab = document.getElementById('tab-inbox');
    if (inboxTab && inboxTab.style.display === 'flex') {
      renderInboxNotifications();
    }
    var profileTab = document.getElementById('tab-profile');
    if (profileTab && profileTab.style.display === 'flex') {
      updateProfileView();
    }
  } catch (e) {
    console.error("Gagal sinkronisasi state GitHub:", e);
  }
}

async function pushGitHubState(partialPatch) {
  try {
    var payload = Object.assign({}, partialPatch || {});
    if (currentUser) {
      payload.coins = Object.assign({}, payload.coins || {});
      payload.coins[currentUser] = userCoins;
      payload.ownedItems = Object.assign({}, payload.ownedItems || {});
      payload.ownedItems[currentUser] = ownedItems;
    }

    await fetch('/api/db/state', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
  } catch (e) {
    console.error("Gagal menyimpan state ke GitHub:", e);
  }
}

let activeFrame = localStorage.getItem('chat_active_frame') || "";
let activeBubble = localStorage.getItem('chat_active_bubble') || "";
let activeNameEffect = localStorage.getItem('chat_active_name') || "";
let activeTextEffect = localStorage.getItem('chat_active_text') || "";
let activeFontEffect = localStorage.getItem('chat_active_font') || "";
let activeBorderShape = localStorage.getItem('chat_active_shape') || "shape_circle";
let activeAccessory = localStorage.getItem('chat_active_accessory') || "acc_none";

function changeDevBadgeStyle(themeVal) {
  activeDevTheme = themeVal;
  pushGitHubState({ devTheme: activeDevTheme });
  renderMessages();
  if (activeDMTarget) renderDM(activeDMTarget);
  alert("✨ Tema & Efek RGB Developer berhasil diperbarui!");
}

function changeDevAccessory(accVal) {
  activeDevAccessory = accVal;
  activeAccessory = accVal;
  localStorage.setItem('chat_active_accessory', activeAccessory);
  syncUserMeta();
  renderMessages();
  if (activeDMTarget) renderDM(activeDMTarget);
  updateProfileView();
  alert("👑 Aksesoris Emoji Supreme Developer berhasil dipasang!");
}

function saveDevLoginMessage() {
  if (currentUser !== DEV_NAME) return;
  var txt = document.getElementById('dev-login-msg-input').value.trim();
  if (!txt) { alert("Pesan tidak boleh kosong!"); return; }
  devLoginNotificationText = txt;
  pushGitHubState({ devLoginMsg: devLoginNotificationText });
  alert("✨ Pesan notifikasi developer login berhasil diperbarui!");
}

function getDevThemeCSS(themeKey) {
  switch (themeKey) {
    case 'diamond_neon':
      return { nameGrad: "linear-gradient(45deg, #00f2fe, #4facfe, #ffffff, #00f2fe)", badgeBg: "linear-gradient(135deg, #0284c7, #0369a1)" };
    case 'fire_ruby':
      return { nameGrad: "linear-gradient(45deg, #ff0844, #ffb199, #ffffff, #ff0844)", badgeBg: "linear-gradient(135deg, #dc2626, #991b1b)" };
    case 'purple_galaxy':
      return { nameGrad: "linear-gradient(45deg, #b224ef, #7579ff, #ffffff, #b224ef)", badgeBg: "linear-gradient(135deg, #7c3aed, #5b21b6)" };
    case 'gold_shine':
      return { nameGrad: "linear-gradient(45deg, #bf953f, #fcf6ba, #b38728, #fbf5b7, #aa771c)", badgeBg: "linear-gradient(135deg, #eab308, #ca8a04)" };
    default:
      return { nameGrad: "linear-gradient(45deg, #ff0000, #ff7f00, #ffff00, #00ff00, #0000ff, #4b0082, #8b00ff)", badgeBg: "linear-gradient(135deg, #ff007f, #7928ca)" };
  }
}

function syncUserMeta() {
  if (!currentUser) return;
  userProfilesMeta[currentUser] = {
    avatar: currentAvatar,
    frame: activeFrame,
    bubble: activeBubble,
    nameEffect: activeNameEffect,
    textEffect: activeTextEffect,
    fontEffect: activeFontEffect,
    shape: activeBorderShape,
    accessory: activeAccessory,
    isVip: isUserVip(currentUser),
    hasPass: isUserPass(currentUser)
  };
  pushGitHubState({
    profilesMeta: userProfilesMeta,
    coins: { [currentUser]: userCoins },
    ownedItems: { [currentUser]: ownedItems }
  });
}

function isUserVip(username) {
  if (username === DEV_NAME) return true;
  var vip = userVipStatus[username];
  return Boolean(vip && (!vip.expireTime || Date.now() <= vip.expireTime));
}

function isUserPass(username) {
  if (username === DEV_NAME) return true;
  var pass = userPassStatus[username];
  return Boolean(pass && (!pass.expireTime || Date.now() <= pass.expireTime));
}

let activeBannerTimer = null;
function showAnnouncementBanner(text, duration) {
  var dur = duration || 10000;
  playSoundEffect('announcement');
  var banner = document.getElementById('announcement-banner');
  document.getElementById('announcement-text').textContent = text;
  banner.classList.add('show');
  if (activeBannerTimer) clearTimeout(activeBannerTimer);
  activeBannerTimer = setTimeout(function() {
    banner.classList.remove('show');
  }, dur);
}

async function updateOnlinePresence() {
  if (!currentUser) return;
  onlineUsersMap[currentUser] = { time: Date.now() };
  renderOnlineCounterUI();
  var dmTab = document.getElementById('tab-dm');
  if (dmTab && dmTab.style.display === 'flex') {
    renderDMProfileList();
  }
  try {
    var res = await fetch('/api/online/ping', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user: currentUser })
    });
    if (res.ok) {
      var data = await res.json();
      if (data && data.onlineUsers) {
        onlineUsersMap = data.onlineUsers;
        renderOnlineCounterUI();
        if (dmTab && dmTab.style.display === 'flex') {
          renderDMProfileList();
        }
      }
    }
  } catch (_) {}
}
setInterval(updateOnlinePresence, 5000);
setInterval(pullGitHubState, 4000);

window.addEventListener('DOMContentLoaded', function() {
  playWindowsStartupSound();
  setTimeout(hideSplashScreen, 1200);
});

window.onload = async function() {
  try {
    currentUser = sanitizeHTML(localStorage.getItem('chat_current_user') || "").trim().toLowerCase();
    currentAvatar = localStorage.getItem('chat_current_avatar') || "";
    customBgImage = localStorage.getItem('chat_bg_image') || "";

    await pullGitHubState();

    if (bannedUsers.includes(currentUser)) {
      alert("AKSES DITOLAK: Akun Anda telah dibanned!");
      localStorage.removeItem('chat_current_user');
      location.reload();
      return;
    }
    if (customBgImage) {
      document.body.style.setProperty('background-image', 'url(' + customBgImage + ')');
    }

    var loginScreen = document.getElementById('login-screen');
    if (currentUser && userDatabase[currentUser]) {
      if (loginScreen) loginScreen.style.display = 'none';
      setupUserSession();
    } else {
      if (loginScreen) loginScreen.style.display = 'flex';
    }
  } catch (err) {
    console.error("Error pada window.onload:", err);
  } finally {
    hideSplashScreen();
  }
};

function loadAvatar(event) {
  var file = event.target.files[0];
  if (file) {
    if (file.size > 2 * 1024 * 1024) { alert("Ukuran gambar maksimal 2MB."); return; }
    var reader = new FileReader();
    reader.onload = function(ev) {
      currentAvatar = ev.target.result;
      var preview = document.getElementById('preview-avatar');
      if (preview) { preview.src = currentAvatar; preview.style.display = 'block'; }
      var label = document.getElementById('avatar-label');
      if (label) label.style.display = 'none';
    };
    reader.readAsDataURL(file);
  }
}

function updateProfileAvatar(event) {
  loadAvatar(event);
  setTimeout(function() {
    localStorage.setItem('chat_current_avatar', currentAvatar);
    syncUserMeta();
    updateProfileView();
    renderMessages();
    if (activeDMTarget) renderDM(activeDMTarget);
  }, 200);
}

async function handleLoginRegister() {
  try {
    var nameField = document.getElementById('login-username');
    var passField = document.getElementById('login-password');
    if (!nameField || !passField) return;

    var name = sanitizeHTML(nameField.value.trim().toLowerCase());
    var pass = passField.value.trim();

    if (!name || !pass) { alert("Masukkan username dan password!"); return; }
    if (!/^[a-z0-9_]{3,15}$/.test(name)) { alert("Username hanya boleh huruf kecil, angka, dan underscore (3-15 karakter)."); return; }

    await pullGitHubState();

    if (bannedUsers.includes(name)) { alert("Akun ini telah dibanned!"); return; }
    if (name === DEV_NAME && pass !== DEV_PASS) { alert("Password Developer salah!"); return; }

    if (!userDatabase[name]) {
      userDatabase[name] = pass;
      checkinProgress[name] = { day: 0, lastClaimDate: "" };
      await pushGitHubState({
        users: userDatabase,
        coins: { [name]: 50 },
        checkinProgress: checkinProgress
      });
    } else if (userDatabase[name] !== pass) {
      alert("Password salah!");
      return;
    }

    currentUser = name;
    localStorage.setItem('chat_current_user', currentUser);
    localStorage.setItem('chat_current_avatar', currentAvatar);

    var loginScreen = document.getElementById('login-screen');
    if (loginScreen) loginScreen.style.display = 'none';
    setupUserSession();
  } catch (e) {
    console.error("Error saat login:", e);
  }
}

function logoutAccount() {
  if (confirm("Keluar akun?")) {
    localStorage.removeItem('chat_current_user');
    location.reload();
  }
}

function setupUserSession() {
  hideSplashScreen();
  if (currentUser === DEV_NAME) {
    var devBtn = document.getElementById('dev-btn');
    if (devBtn) devBtn.style.display = 'block';
    showAnnouncementBanner(devLoginNotificationText, 10000);
  }
  syncUserMeta();
  renderInboxBadge();
  updateCoinsDisplay();
  renderShopCategory('vip', document.querySelector('.shop-cat-btn'));
  updateProfileView();
  renderMessages();
  renderGlobalPosts();
  renderDMProfileList();
  updateOnlinePresence();
}

function switchTab(tabName, element) {
  document.querySelectorAll('.tab-content').forEach(function(el) {
    el.classList.remove('active');
    el.style.display = 'none';
  });
  document.querySelectorAll('.nav-item').forEach(function(el) {
    el.classList.remove('active');
  });
  var targetTab = document.getElementById('tab-' + tabName);
  if (targetTab) {
    targetTab.classList.add('active');
    targetTab.style.display = 'flex';
  }
  if (element) element.classList.add('active');
  var inputArea = document.getElementById('chat-input-area');
  if (tabName === 'chat') {
    if (inputArea) inputArea.style.display = 'block';
  } else {
    if (inputArea) inputArea.style.display = 'none';
    if (tabName === 'dm') renderDMProfileList();
    if (tabName === 'inbox') renderInboxNotifications();
    if (tabName === 'post') renderGlobalPosts();
    if (tabName === 'profile') updateProfileView();
    if (tabName === 'shop') renderShopCategory(currentShopCat, document.querySelector('.shop-cat-btn.active'));
  }
}

function renderWeeklyCheckinUI() {
  var grid = document.getElementById('checkin-week-grid');
  var badge = document.getElementById('checkin-streak-badge');
  var btn = document.getElementById('claim-weekly-checkin-btn');
  if (!grid || !currentUser) return;

  var prog = checkinProgress[currentUser] || { day: 0, lastClaimDate: "" };
  var today = new Date().toDateString();
  var alreadyToday = prog.lastClaimDate === today;
  var nextDayIndex = alreadyToday ? prog.day : Math.min(prog.day + 1, 7);

  if (badge) badge.textContent = "Hari " + prog.day + "/7";

  grid.innerHTML = '';
  WEEKLY_CHECKIN_REWARDS.forEach(function(reward, idx) {
    var dayNum = idx + 1;
    var isClaimed = dayNum <= prog.day;
    var isNext = !alreadyToday && dayNum === nextDayIndex;
    var cls = 'checkin-day-card';
    if (isClaimed) cls += ' claimed';
    else if (isNext) cls += ' next';
    grid.innerHTML +=
      '<div class="' + cls + '">' +
        '<div style="font-weight:bold;">Hari ' + dayNum + '</div>' +
        '<div style="color:#fbbf24;">+' + reward + ' 💰</div>' +
        '<div>' + (isClaimed ? '✓' : '🔒') + '</div>' +
      '</div>';
  });

  if (btn) {
    if (alreadyToday) {
      btn.textContent = "✅ Check-In Hari Ini Sudah Diklaim (Hari " + prog.day + "/7)";
      btn.disabled = true;
      btn.style.opacity = '0.6';
    } else {
      var rewardAmt = WEEKLY_CHECKIN_REWARDS[nextDayIndex - 1];
      btn.textContent = "🎁 Klaim Check-In Hari " + nextDayIndex + " (+" + rewardAmt + " Koin)";
      btn.disabled = false;
      btn.style.opacity = '1';
    }
  }
}

async function claimWeeklyCheckin() {
  if (!currentUser) return;
  var prog = checkinProgress[currentUser] || { day: 0, lastClaimDate: "" };
  var today = new Date().toDateString();
  if (prog.lastClaimDate === today) {
    alert("Kamu sudah check-in hari ini!");
    return;
  }
  var nextDay = prog.day >= 7 ? 1 : prog.day + 1;
  var reward = WEEKLY_CHECKIN_REWARDS[nextDay - 1];
  userCoins += reward;
  checkinProgress[currentUser] = { day: nextDay, lastClaimDate: today };

  updateCoinsDisplay();
  renderWeeklyCheckinUI();
  await pushGitHubState({
    coins: { [currentUser]: userCoins },
    checkinProgress: checkinProgress
  });
  alert("🎉 Check-in Hari " + nextDay + " berhasil! Kamu dapat +" + reward + " Koin!");
}

async function toggleMyPrivacyMode() {
  if (!currentUser) return;
  accountPrivacy[currentUser] = !accountPrivacy[currentUser];
  updateProfileView();
  await pushGitHubState({ accountPrivacy: accountPrivacy });
  alert(accountPrivacy[currentUser]
    ? "🔒 Mode Akun PRIVAT aktif! User lain harus follow & nunggu di-ACC untuk lihat foto profil & galeri."
    : "🌐 Mode Akun PUBLIK aktif! Semua user bisa melihat foto profil & galeri.");
}

function renderInboxNotifications() {
  var container = document.getElementById('inbox-notifications-list');
  if (!container || !currentUser) return;
  container.innerHTML = '';

  var reqList = (followRequests[currentUser] || []);
  reqList.forEach(function(reqUser) {
    container.innerHTML +=
      '<div class="card-box" style="display:flex; justify-content:space-between; align-items:center; padding:10px; margin-bottom:0;">' +
        '<div style="font-size:12px;">🔒 <b>@' + sanitizeHTML(reqUser) + '</b> meminta mengikuti akun privatmu.</div>' +
        '<div style="display:flex; gap:4px;">' +
          '<button onclick="respondFollowRequest(\'' + reqUser + '\', true)" style="background:#10b981; border:none; color:white; padding:4px 8px; border-radius:6px; font-size:10px; font-weight:bold; cursor:pointer;">ACC</button>' +
          '<button onclick="respondFollowRequest(\'' + reqUser + '\', false)" style="background:#ef4444; border:none; color:white; padding:4px 8px; border-radius:6px; font-size:10px; font-weight:bold; cursor:pointer;">Tolak</button>' +
        '</div>' +
      '</div>';
  });

  var notifs = inboxNotifications[currentUser] || [];
  if (reqList.length === 0 && notifs.length === 0) {
    container.innerHTML = '<div style="font-size:12px; color:rgba(255,255,255,0.4); text-align:center; margin-top:20px;">Belum ada notifikasi di kotak masuk.</div>';
    return;
  }

  notifs.forEach(function(n) {
    var timeStr = new Date(n.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    container.innerHTML +=
      '<div class="card-box" style="padding:10px; margin-bottom:0; font-size:12px;">' +
        '<div>' + sanitizeHTML(n.text) + '</div>' +
        '<div style="font-size:9px; color:rgba(255,255,255,0.5); margin-top:3px;">' + timeStr + '</div>' +
      '</div>';
  });
}

async function respondFollowRequest(reqUser, accepted) {
  if (!currentUser) return;
  followRequests[currentUser] = (followRequests[currentUser] || []).filter(function(u) { return u !== reqUser; });
  if (accepted) {
    if (!userFollowers[currentUser]) userFollowers[currentUser] = [];
    if (!userFollowers[currentUser].includes(reqUser)) {
      userFollowers[currentUser].push(reqUser);
    }
    if (!inboxNotifications[reqUser]) inboxNotifications[reqUser] = [];
    inboxNotifications[reqUser].unshift({
      id: 'notif_' + Date.now(),
      from: currentUser,
      text: "✅ @" + currentUser + " menerima permintaan follow kamu!",
      time: Date.now()
    });
  }
  renderInboxNotifications();
  renderInboxBadge();
  updateProfileView();
  await pushGitHubState({ followRequests: followRequests, userFollowers: userFollowers, inboxNotifications: inboxNotifications });
}

async function clearMyInbox() {
  if (!currentUser) return;
  inboxNotifications[currentUser] = [];
  renderInboxNotifications();
  renderInboxBadge();
  await pushGitHubState({ inboxNotifications: inboxNotifications });
}

let newPostImageBase64 = "";

function openCreatePostModal() {
  newPostImageBase64 = "";
  document.getElementById('new-post-preview-img').style.display = 'none';
  document.getElementById('new-post-preview-label').style.display = 'block';
  document.getElementById('new-post-caption-input').value = "";
  document.getElementById('create-post-modal').style.display = 'flex';
}

function loadNewPostImage(event) {
  var file = event.target.files[0];
  if (file) {
    if (file.size > 2 * 1024 * 1024) { alert("Ukuran gambar maksimal 2MB."); return; }
    var reader = new FileReader();
    reader.onload = function(ev) {
      newPostImageBase64 = ev.target.result;
      var img = document.getElementById('new-post-preview-img');
      img.src = newPostImageBase64;
      img.style.display = 'block';
      document.getElementById('new-post-preview-label').style.display = 'none';
    };
    reader.readAsDataURL(file);
  }
}

async function saveAndPublishGlobalPost() {
  if (!newPostImageBase64) { alert("Pilih gambar terlebih dahulu!"); return; }
  var caption = sanitizeHTML(document.getElementById('new-post-caption-input').value.trim());
  var newPost = {
    id: 'post_' + Date.now(),
    user: currentUser,
    avatar: currentAvatar,
    image: newPostImageBase64,
    caption: caption,
    likes: 0,
    likedBy: [],
    comments: [],
    time: Date.now()
  };
  globalPosts.unshift(newPost);
  document.getElementById('create-post-modal').style.display = 'none';
  renderGlobalPosts();
  await pushGitHubState({ posts: globalPosts });
  alert("✨ Live foto global berhasil dipublikasikan ke GitHub DB!");
}

function renderGlobalPosts() {
  var container = document.getElementById('global-posts-container');
  if (!container) return;
  container.innerHTML = '';
  if (globalPosts.length === 0) {
    container.innerHTML = '<div style="font-size:12px; color:rgba(255,255,255,0.4); text-align:center; margin-top:20px;">Belum ada postingan live foto.</div>';
    return;
  }
  globalPosts.forEach(function(post, pIdx) {
    var meta = userProfilesMeta[post.user] || {};
    var canView = canViewPrivateProfile(post.user);
    var avatarHTML = buildAvatarHTML(post.user, canView ? (post.avatar || meta.avatar || '') : '', meta.frame || '', meta.shape || 'shape_circle', meta.accessory || 'acc_none');
    var isLiked = (post.likedBy || []).includes(currentUser);
    var formattedCaption = post.caption.replace(/(#\w+)/g, '<span style="color:#38bdf8; font-weight:bold;">$1</span>');
    var commentsHTML = '';
    (post.comments || []).forEach(function(c) {
      commentsHTML += '<div style="font-size:11px; margin-bottom:3px;"><b>@' + sanitizeHTML(c.user) + ':</b> ' + sanitizeHTML(c.text) + '</div>';
    });
    container.innerHTML +=
      '<div class="global-post-card">' +
        '<div class="global-post-header">' +
          '<div style="display:flex; align-items:center; gap:8px;">' +
            '<div style="transform:scale(0.85); transform-origin:left center;" onclick="openUserProfile(\'' + post.user + '\')">' + avatarHTML + '</div>' +
            '<div>' +
              '<div style="font-weight:bold; color:#f8fafc; font-size:13px; cursor:pointer;" onclick="openUserProfile(\'' + post.user + '\')">' + sanitizeHTML(post.user) + ' ' + (accountPrivacy[post.user] ? '🔒' : '') + '</div>' +
              '<div style="font-size:9px; color:rgba(255,255,255,0.5);">' + new Date(post.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + '</div>' +
            '</div>' +
          '</div>' +
        '</div>' +
        '<div class="global-post-img-wrap"><img src="' + post.image + '"></div>' +
        '<div class="global-post-actions">' +
          '<button class="action-btn" onclick="triggerGlobalPostLike(' + pIdx + ')">' + (isLiked ? '❤️' : '🤍') + ' <span>' + formatCompactNumber(post.likes) + '</span></button>' +
          '<button class="action-btn" onclick="alert(\'Logo Play dipicu!\')">▶️ Play</button>' +
        '</div>' +
        '<div style="font-size:12px; color:#f8fafc; margin-bottom:6px; word-break:break-word;"><b>@' + sanitizeHTML(post.user) + '</b> ' + formattedCaption + '</div>' +
        '<div style="background:rgba(0,0,0,0.3); border-radius:8px; padding:6px; margin-bottom:6px; max-height:80px; overflow-y:auto;">' + (commentsHTML || '<span style="font-size:10px; color:rgba(255,255,255,0.4);">Belum ada komentar.</span>') + '</div>' +
        '<div style="display:flex; gap:5px;">' +
          '<input type="text" id="global-comment-input-' + pIdx + '" placeholder="💬 Tulis komentar & hashtag..." style="flex:1; padding:6px; background:rgba(15,23,42,0.8); color:white; border:1px solid var(--glass-border); border-radius:6px; outline:none; font-size:11px;">' +
          '<button onclick="postGlobalComment(' + pIdx + ')" style="background:#0284c7; border:none; color:white; padding:6px 10px; border-radius:6px; font-weight:bold; cursor:pointer; font-size:11px;">Kirim</button>' +
        '</div>' +
      '</div>';
  });
}

async function triggerGlobalPostLike(pIdx) {
  var post = globalPosts[pIdx];
  if (!post.likedBy) post.likedBy = [];
  var likedIdx = post.likedBy.indexOf(currentUser);
  if (likedIdx > -1) {
    post.likedBy.splice(likedIdx, 1);
    post.likes--;
  } else {
    post.likedBy.push(currentUser);
    post.likes++;
    await pushInboxNotification(post.user, {
      text: "❤️ @" + currentUser + " menyukai postingan live foto kamu!"
    });
  }
  renderGlobalPosts();
  await pushGitHubState({ posts: globalPosts });
}

async function postGlobalComment(pIdx) {
  var input = document.getElementById('global-comment-input-' + pIdx);
  var text = sanitizeHTML(input.value.trim());
  if (!text) return;
  var post = globalPosts[pIdx];
  if (!post.comments) post.comments = [];
  post.comments.push({ user: currentUser, text: text });
  input.value = '';
  renderGlobalPosts();
  await pushGitHubState({ posts: globalPosts });
}

function openFollowListModal(targetUsername, mode) {
  var modal = document.getElementById('follow-list-modal');
  var titleEl = document.getElementById('follow-list-modal-title');
  var bodyEl = document.getElementById('follow-list-modal-body');
  if (!modal || !titleEl || !bodyEl) return;

  bodyEl.innerHTML = '';
  var usersList = [];
  if (mode === 'followers') {
    titleEl.textContent = "👥 Pengikut @" + targetUsername;
    usersList = userFollowers[targetUsername] || [];
  } else {
    titleEl.textContent = "➡️ Mengikuti oleh @" + targetUsername;
    usersList = getFollowingUsers(targetUsername);
  }

  if (usersList.length === 0) {
    bodyEl.innerHTML = '<span style="font-size:11px; color:rgba(255,255,255,0.4); text-align:center;">Belum ada daftar.</span>';
  } else {
    usersList.forEach(function(u) {
      var meta = userProfilesMeta[u] || {};
      var canView = canViewPrivateProfile(u);
      var avSnippet = buildAvatarHTML(u, canView ? (meta.avatar || '') : '', meta.frame || '', meta.shape || 'shape_circle', meta.accessory || 'acc_none');
      bodyEl.innerHTML +=
        '<div style="display:flex; align-items:center; justify-content:space-between; background:rgba(30,41,59,0.6); padding:6px 8px; border-radius:8px;">' +
          '<div style="display:flex; align-items:center; gap:8px;">' +
            '<div style="transform:scale(0.7); transform-origin:left center;" onclick="openUserProfile(\'' + u + '\')">' + avSnippet + '</div>' +
            '<span style="font-size:12px; font-weight:bold; color:#38bdf8; cursor:pointer;" onclick="openUserProfile(\'' + u + '\')">@' + sanitizeHTML(u) + ' ' + (accountPrivacy[u] ? '🔒' : '') + '</span>' +
          '</div>' +
          '<button onclick="openUserProfile(\'' + u + '\')" style="background:#0284c7; border:none; color:white; padding:3px 8px; border-radius:6px; font-size:10px; cursor:pointer;">Profil</button>' +
        '</div>';
    });
  }
  modal.style.display = 'flex';
}

function openBugReportModal() {
  document.getElementById('bug-report-text-input').value = "";
  document.getElementById('bug-report-modal').style.display = 'flex';
}

async function submitBugReport() {
  var text = sanitizeHTML(document.getElementById('bug-report-text-input').value.trim());
  if (!text) { alert("Tuliskan deskripsi bug terlebih dahulu!"); return; }
  bugReports.push({ id: 'bug_' + Date.now(), user: currentUser, text: text, time: Date.now() });
  document.getElementById('bug-report-modal').style.display = 'none';
  await pushGitHubState({ bugReports: bugReports });
  alert("✅ Laporan bug berhasil dikirim ke GitHub DB!");
}

function openLostAccountModal() {
  document.getElementById('lost-username-input').value = "";
  document.getElementById('lost-details-input').value = "";
  document.getElementById('lost-account-modal').style.display = 'flex';
}

async function submitLostAccountReport() {
  var uName = sanitizeHTML(document.getElementById('lost-username-input').value.trim());
  var details = sanitizeHTML(document.getElementById('lost-details-input').value.trim());
  if (!uName || !details) { alert("Harap isi perkiraan username dan detail akun!"); return; }
  lostReports.push({ id: 'lost_' + Date.now(), username: uName, details: details, time: Date.now() });
  document.getElementById('lost-account-modal').style.display = 'none';
  await pushGitHubState({ lostReports: lostReports });
  alert("⚠️ Laporan kehilangan akun terkirim ke GitHub DB!");
}

async function clearGlobalChat() {
  if (currentUser !== DEV_NAME) { alert("Hanya Developer!"); return; }
  if (confirm("Yakin ingin menghapus seluruh riwayat chat global secara permanen?")) {
    messages = [];
    renderMessages();
    await pushGitHubState({ messages: messages });
    alert("Semua riwayat chat global berhasil dibersihkan!");
  }
}

let currentShopCat = 'vip';

function renderShopCategory(category, btnEl) {
  currentShopCat = category;
  if (btnEl) {
    document.querySelectorAll('.shop-cat-btn').forEach(function(b) { b.classList.remove('active'); });
    btnEl.classList.add('active');
  }
  var list = document.getElementById('shop-items-list');
  if (!list) return;
  list.innerHTML = '';

  if (category === 'vip') {
    var topupPacks = [
      { name: "💰 Paket 100 Koin", price: "Rp 15.000 / $1.5", coins: 100 },
      { name: "💰 Paket 550 Koin + Bonus", price: "Rp 70.000 / $6", coins: 550 },
      { name: "💰 Paket 1.200 Koin VIP", price: "Rp 140.000 / $12", coins: 1200 },
      { name: "👑 Premium Pass 2 Hari", price: "Rp 25.000", desc: "Akses Fitur VIP Uji Coba 2 Hari" },
      { name: "👑 Premium Pass 1 Bulan", price: "Rp 55.000", desc: "Akses VIP 30 Hari Penuh" },
      { name: "👑 Premium Pass 3 Bulan", price: "Rp 135.000", desc: "Akses VIP 90 Hari + Bonus" },
      { name: "👑 Premium Permanen", price: "Rp 299.000", desc: "Status VIP Selamanya di Server" }
    ];
    topupPacks.forEach(function(pack) {
      var descText = pack.coins ? ("Dapatkan " + pack.coins + " Koin Instan • " + pack.price) : (pack.desc + " • " + pack.price);
      list.innerHTML += '<div class="shop-item"><div><b>' + pack.name + '</b><br><small style="color:rgba(255,255,255,0.6);">' + descText + '</small></div><button class="buy-btn topup" onclick="buyVipTopUp(\'' + pack.name + '\', \'' + pack.price + '\')">Beli via DM 📩</button></div>';
    });
  } else if (category === 'shape') {
    BORDER_SHAPES.forEach(function(shape) {
      var isOwned = (shape.price === 0) || ownedItems.includes(shape.id);
      var isEquipped = (activeBorderShape === shape.id);
      var btnClass = isEquipped ? 'buy-btn equipped' : (isOwned ? 'buy-btn owned' : 'buy-btn');
      var btnText = isEquipped ? 'Dipakai ✓' : (isOwned ? 'Pakai' : ("Beli " + shape.price + " 💰"));
      list.innerHTML +=
        '<div class="shop-item">' +
          '<div style="display:flex; align-items:center; gap:8px;">' +
            '<div style="width:28px; height:28px; position:relative; display:flex; align-items:center; justify-content:center;">' +
              '<div style="width:20px; height:20px; border-radius:50%; background:#0f172a; z-index:2;"></div>' +
              '<div class="border-shape-ring ' + shape.class + '" style="z-index:3;"></div>' +
            '</div>' +
            '<div><b style="font-size:12px;">' + shape.name + '</b><br><small style="color:rgba(255,255,255,0.6); font-size:10px;">Bentuk Garis • ' + (shape.price === 0 ? 'Gratis' : shape.price + ' 💰') + '</small></div>' +
          '</div>' +
          '<button class="' + btnClass + '" onclick="buyBorderShape(\'' + shape.id + '\', ' + shape.price + ')">' + btnText + '</button>' +
        '</div>';
    });
  } else if (category === 'accessory') {
    BORDER_ACCESSORIES.forEach(function(acc) {
      var isOwned = (acc.price === 0) || ownedItems.includes(acc.id);
      var isEquipped = (activeAccessory === acc.id);
      var btnClass = isEquipped ? 'buy-btn equipped' : (isOwned ? 'buy-btn owned' : 'buy-btn');
      var btnText = isEquipped ? 'Dipakai ✓' : (isOwned ? 'Pakai' : ("Beli " + acc.price + " 💰"));
      list.innerHTML +=
        '<div class="shop-item">' +
          '<div style="display:flex; align-items:center; gap:8px;">' +
            '<div style="font-size:16px; width:28px; height:28px; display:flex; align-items:center; justify-content:center; background:rgba(0,0,0,0.4); border-radius:6px;">' + (acc.emoji || '✨') + '</div>' +
            '<div><b style="font-size:12px;">' + acc.name + '</b><br><small style="color:rgba(255,255,255,0.6); font-size:10px;">Aksesoris Emoji • ' + (acc.price === 0 ? 'Gratis' : acc.price + ' 💰') + '</small></div>' +
          '</div>' +
          '<button class="' + btnClass + '" onclick="buyBorderAccessory(\'' + acc.id + '\', ' + acc.price + ')">' + btnText + '</button>' +
        '</div>';
    });
  } else if (category === 'font') {
    FONT_STYLES.forEach(function(base, i) {
      var itemId = "font_" + i;
      var price = 250 + (i * 35);
      var isOwned = ownedItems.includes(itemId);
      var isEquipped = (activeFontEffect === itemId);
      var btnClass = isEquipped ? 'buy-btn equipped' : (isOwned ? 'buy-btn owned' : 'buy-btn');
      var btnText = isEquipped ? 'Dipakai ✓' : (isOwned ? 'Pakai' : ("Beli " + price + " 💰"));
      list.innerHTML +=
        '<div class="shop-item">' +
          '<div><b style="font-size:12px; ' + base.style + '">' + base.name + '</b><br><small style="color:rgba(255,255,255,0.6); font-size:10px;">Gaya Huruf • ' + price + ' 💰</small></div>' +
          '<button class="' + btnClass + '" onclick="buyItem(\'' + itemId + '\', ' + price + ')">' + btnText + '</button>' +
        '</div>';
    });
  } else {
    if (category === 'frame' && currentUser === DEV_NAME) {
      var isEq = (activeFrame === 'admin_galaxy');
      list.innerHTML += '<div class="shop-item"><div><b>👑 Bingkai Galaksi Supreme RGB</b><br><small style="color:#fbbf24;">Eksklusif Developer</small></div><button class="buy-btn ' + (isEq ? 'equipped' : 'owned') + '" onclick="setActiveItem(\'admin_galaxy\')">' + (isEq ? 'Dipakai ✓' : 'Pakai') + '</button></div>';
    }
    for (var i = 0; i < 50; i++) {
      var itemId = category + "_" + i;
      var data = getEffectStyleData(itemId);
      var isOwned = ownedItems.includes(itemId);
      var isEquipped = (activeFrame === itemId || activeBubble === itemId || activeNameEffect === itemId || activeTextEffect === itemId);
      var previewStyle = "background: linear-gradient(45deg, " + data.c1 + ", " + data.c2 + "); filter: hue-rotate(" + data.hue + "deg);";
      var btnClass = isEquipped ? 'buy-btn equipped' : (isOwned ? 'buy-btn owned' : 'buy-btn');
      var btnText = isEquipped ? 'Dipakai ✓' : (isOwned ? 'Pakai' : ("Beli " + formatCompactNumber(data.price) + " 💰"));
      list.innerHTML +=
        '<div class="shop-item">' +
          '<div style="display:flex; align-items:center; gap:8px;">' +
            '<div style="width:20px; height:20px; border-radius:50%; ' + previewStyle + ' box-shadow:0 0 6px ' + data.c1 + ';"></div>' +
            '<div><b style="font-size:12px;">' + data.name + '</b><br><small style="color:rgba(255,255,255,0.6); font-size:10px;">Efek RGB • ' + formatCompactNumber(data.price) + ' 💰</small></div>' +
          '</div>' +
          '<button class="' + btnClass + '" onclick="buyItem(\'' + itemId + '\', ' + data.price + ')">' + btnText + '</button>' +
        '</div>';
    }
  }
}

async function buyBorderShape(shapeId, price) {
  var shapeObj = BORDER_SHAPES.find(function(s) { return s.id === shapeId; });
  if (!shapeObj) return;
  if (shapeObj.price > 0 && !ownedItems.includes(shapeId)) {
    if (userCoins < price) { alert("Koin tidak cukup!"); return; }
    userCoins -= price;
    ownedItems.push(shapeId);
    updateCoinsDisplay();
  }
  activeBorderShape = shapeId;
  localStorage.setItem('chat_active_shape', activeBorderShape);
  syncUserMeta();
  renderShopCategory('shape', document.querySelector('.shop-cat-btn.active'));
  updateProfileView();
  alert("✨ Bentuk border garis berhasil dipasang!");
}

async function buyBorderAccessory(accId, price) {
  var accObj = BORDER_ACCESSORIES.find(function(a) { return a.id === accId; });
  if (!accObj) return;
  if (accObj.price > 0 && !ownedItems.includes(accId)) {
    if (userCoins < price) { alert("Koin tidak cukup!"); return; }
    userCoins -= price;
    ownedItems.push(accId);
    updateCoinsDisplay();
  }
  activeAccessory = accId;
  localStorage.setItem('chat_active_accessory', activeAccessory);
  syncUserMeta();
  renderShopCategory('accessory', document.querySelector('.shop-cat-btn.active'));
  updateProfileView();
  alert("✨ Aksesoris emoji melayang dari toko berhasil dipasang!");
}

async function buyVipTopUp(planName, priceTag) {
  var dmText = "Developer @pito, saya @" + currentUser + " ingin membeli " + planName + " seharga " + priceTag + ". Tolong diproses ya!";
  dmMessages.push({ id: 'dm_' + Date.now(), from: currentUser, to: DEV_NAME, text: dmText, time: Date.now() });
  await pushGitHubState({ dms: dmMessages });
  alert("📩 Permintaan pesanan terkirim ke DM Developer @pito!");
  openDMChat(DEV_NAME);
}

async function claimDailyCoins() {
  var today = new Date().toDateString();
  if (userDailyClaim[currentUser] === today) { alert("Sudah diklaim hari ini!"); return; }
  userCoins += 100;
  userDailyClaim[currentUser] = today;
  updateCoinsDisplay();
  updateProfileView();
  await pushGitHubState({
    coins: { [currentUser]: userCoins },
    dailyClaim: userDailyClaim
  });
  alert("🎁 Berhasil klaim +100 Koin Harian!");
}

async function buyItem(itemId, price) {
  if (ownedItems.includes(itemId)) { setActiveItem(itemId); return; }
  if (userCoins < price) { alert("Koin tidak cukup!"); return; }
  userCoins -= price;
  ownedItems.push(itemId);
  setActiveItem(itemId);
  updateCoinsDisplay();
}

function setActiveItem(itemId) {
  if (itemId.startsWith('frame_') || itemId === 'admin_galaxy') {
    activeFrame = (activeFrame === itemId) ? "" : itemId;
    localStorage.setItem('chat_active_frame', activeFrame);
  } else if (itemId.startsWith('bubble_')) {
    activeBubble = (activeBubble === itemId) ? "" : itemId;
    localStorage.setItem('chat_active_bubble', activeBubble);
  } else if (itemId.startsWith('name_')) {
    activeNameEffect = (activeNameEffect === itemId) ? "" : itemId;
    localStorage.setItem('chat_active_name', activeNameEffect);
  } else if (itemId.startsWith('text_')) {
    activeTextEffect = (activeTextEffect === itemId) ? "" : itemId;
    localStorage.setItem('chat_active_text', activeTextEffect);
  } else if (itemId.startsWith('font_')) {
    activeFontEffect = (activeFontEffect === itemId) ? "" : itemId;
    localStorage.setItem('chat_active_font', activeFontEffect);
  }
  syncUserMeta();
  renderShopCategory(currentShopCat, null);
  updateProfileView();
}

async function saveMyBio(bioText) {
  userBios[currentUser] = sanitizeHTML(bioText);
  await pushGitHubState({ bios: userBios });
}

async function uploadGalleryPhoto(event) {
  var file = event.target.files[0];
  if (file) {
    if (file.size > 2 * 1024 * 1024) { alert("Maksimal ukuran foto 2MB."); return; }
    var reader = new FileReader();
    reader.onload = async function(ev) {
      if (!userGalleries[currentUser]) userGalleries[currentUser] = [];
      userGalleries[currentUser].push({ img: ev.target.result, likes: 0, likedBy: [], comments: [] });
      updateProfileView();
      await pushGitHubState({ galleries: userGalleries });
    };
    reader.readAsDataURL(file);
  }
}

function buildAvatarHTML(username, avatarImg, frameId, shapeId, accessoryId) {
  var initial = username ? username.charAt(0).toUpperCase() : 'U';
  var picContent = avatarImg ? ('<img src="' + avatarImg + '">') : ('<span>' + initial + '</span>');
  var shapeClass = "border-circle";
  if (shapeId) {
    var s = BORDER_SHAPES.find(function(x) { return x.id === shapeId; });
    if (s) shapeClass = s.class;
  }
  var ringClass = "border-shape-ring " + shapeClass;
  var ringStyle = "";
  var accessoryEmoji = "";
  var isSupremeAcc = false;

  if (username === DEV_NAME || frameId === 'admin_galaxy') {
    ringClass += " dev-supreme-ring";
  }
  if (frameId && frameId.startsWith('frame_')) {
    var d = getEffectStyleData(frameId);
    if (d) {
      ringClass += " dyn-ring-live";
      ringStyle = "border-color: " + d.c1 + "; box-shadow: 0 0 10px " + d.c1 + ", inset 0 0 4px " + d.c1 + "; filter: hue-rotate(" + d.hue + "deg);";
    }
  } else if (!ringClass.includes('dev-supreme-ring')) {
    ringStyle = "border-color: #38bdf8;";
  }
  if (accessoryId && accessoryId !== 'acc_none') {
    if (DEV_SUPREME_ACCESSORIES[accessoryId]) {
      accessoryEmoji = DEV_SUPREME_ACCESSORIES[accessoryId].emoji;
      isSupremeAcc = true;
    } else {
      var accObj = BORDER_ACCESSORIES.find(function(a) { return a.id === accessoryId; });
      if (accObj) accessoryEmoji = accObj.emoji;
    }
  }
  var accessoryHTML = accessoryEmoji
    ? ('<div class="' + (isSupremeAcc ? 'frame-accessory-supreme' : 'frame-accessory-badge') + '">' + accessoryEmoji + '</div>')
    : "";

  return '<div class="avatar-container"><div class="profile-pic-circle">' + picContent + '</div><div class="' + ringClass + '" style="' + ringStyle + '"></div>' + accessoryHTML + '</div>';
}

function updateProfileView() {
  var pName = document.getElementById('profile-name');
  if (pName) pName.textContent = currentUser;
  var uCoins = document.getElementById('user-coins');
  if (uCoins) uCoins.textContent = formatCompactNumber(userCoins);
  var sCoins = document.getElementById('shop-coins');
  if (sCoins) sCoins.textContent = formatCompactNumber(userCoins);
  var pBio = document.getElementById('profile-bio-input');
  if (pBio) pBio.value = userBios[currentUser] || "";

  var privBtn = document.getElementById('privacy-toggle-btn');
  if (privBtn) {
    privBtn.textContent = accountPrivacy[currentUser] ? "🔒 Akun: Privat" : "🌐 Akun: Publik";
  }

  var fCount = document.getElementById('my-followers-count');
  if (fCount) fCount.textContent = formatCompactNumber(getFollowerDisplayCount(currentUser));
  var fgCount = document.getElementById('my-following-count');
  if (fgCount) fgCount.textContent = formatCompactNumber(getFollowingUsers(currentUser).length);

  renderWeeklyCheckinUI();

  var today = new Date().toDateString();
  var canClaim = (isUserPass(currentUser) || isUserVip(currentUser)) && (userDailyClaim[currentUser] !== today);
  var dClaim = document.getElementById('daily-claim-box');
  if (dClaim) dClaim.style.display = canClaim ? 'block' : 'none';

  var avatarBox = document.getElementById('profile-avatar-box');
  if (avatarBox) {
    var fId = activeFrame || (currentUser === DEV_NAME ? 'admin_galaxy' : '');
    avatarBox.innerHTML = buildAvatarHTML(currentUser, currentAvatar, fId, activeBorderShape, activeAccessory);
  }

  var grid = document.getElementById('my-gallery-grid');
  if (grid) {
    grid.innerHTML = '';
    var myPhotos = userGalleries[currentUser] || [];
    if (myPhotos.length === 0) {
      grid.innerHTML = '<span style="font-size:11px; color:rgba(255,255,255,0.4); grid-column:span 3; text-align:center;">Belum ada foto galeri.</span>';
    } else {
      myPhotos.forEach(function(photo, idx) {
        grid.innerHTML += '<div class="gallery-item" onclick="openPhotoDetail(\'' + currentUser + '\', ' + idx + ')"><img src="' + photo.img + '"><div class="gallery-like-badge">❤️ ' + formatCompactNumber(photo.likes) + '</div></div>';
      });
    }
  }
}

let viewingUser = "";
function openUserProfile(username) {
  viewingUser = username;
  document.getElementById('modal-username').textContent = username;
  document.getElementById('modal-user-bio').textContent = userBios[username] || "Tidak ada bio.";
  var vipContainer = document.getElementById('modal-vip-badge-container');
  vipContainer.innerHTML = (isUserVip(username) || isUserPass(username) || username === DEV_NAME) ? '<span class="vip-badge">🌟 VIP PASS</span>' : '';

  var canView = canViewPrivateProfile(username);
  var privTag = document.getElementById('modal-privacy-tag');
  if (privTag) {
    privTag.textContent = accountPrivacy[username]
      ? (canView ? "🔒 Akun Privat (Sudah Diikuti)" : "🔒 Akun Privat — Ikuti & tunggu ACC untuk lihat foto")
      : "🌐 Akun Publik";
  }

  var meta = userProfilesMeta[username] || {};
  document.getElementById('modal-user-avatar').innerHTML = buildAvatarHTML(
    username,
    canView ? (meta.avatar || '') : '',
    meta.frame || '',
    meta.shape || 'shape_circle',
    meta.accessory || 'acc_none'
  );

  document.getElementById('modal-followers-num').textContent = formatCompactNumber(getFollowerDisplayCount(username));
  document.getElementById('modal-following-num').textContent = formatCompactNumber(getFollowingUsers(username).length);

  var followBtn = document.getElementById('modal-follow-btn');
  var blockBtn = document.getElementById('modal-block-btn');
  if (username === currentUser) {
    followBtn.style.display = 'none';
    blockBtn.style.display = 'none';
  } else {
    followBtn.style.display = 'block';
    blockBtn.style.display = 'block';
    var followers = userFollowers[username] || [];
    var pendingReqs = followRequests[username] || [];
    if (followers.includes(currentUser)) {
      followBtn.textContent = "✅ Mengikuti";
      followBtn.style.background = "#475569";
    } else if (pendingReqs.includes(currentUser)) {
      followBtn.textContent = "⏳ Menunggu ACC";
      followBtn.style.background = "#d97706";
    } else {
      followBtn.textContent = accountPrivacy[username] ? "🔒 Minta Ikuti" : "➕ Ikuti";
      followBtn.style.background = "#10b981";
    }
    var blockedList = userBlocks[currentUser] || [];
    if (blockedList.includes(username)) {
      blockBtn.textContent = "🔓 Buka Blokir";
      blockBtn.style.background = "#0284c7";
    } else {
      blockBtn.textContent = "🚫 Blokir";
      blockBtn.style.background = "#ef4444";
    }
  }

  var grid = document.getElementById('modal-user-gallery');
  grid.innerHTML = '';
  if (!canView) {
    grid.innerHTML = '<span style="font-size:11px; color:#fbbf24; grid-column:span 3; text-align:center; padding:10px;">🔒 Galeri terkunci. Ikuti akun ini dulu!</span>';
  } else {
    (userGalleries[username] || []).forEach(function(photo, idx) {
      grid.innerHTML += '<div class="gallery-item" onclick="openPhotoDetail(\'' + username + '\', ' + idx + ')"><img src="' + photo.img + '"><div class="gallery-like-badge">❤️ ' + formatCompactNumber(photo.likes) + '</div></div>';
    });
  }
  document.getElementById('user-profile-modal').style.display = 'flex';
}

async function toggleBlockUser() {
  if (!userBlocks[currentUser]) userBlocks[currentUser] = [];
  var idx = userBlocks[currentUser].indexOf(viewingUser);
  if (idx > -1) userBlocks[currentUser].splice(idx, 1);
  else userBlocks[currentUser].push(viewingUser);
  await pushGitHubState({ blocks: userBlocks });
  openUserProfile(viewingUser);
}

async function toggleFollowUser() {
  if (!userFollowers[viewingUser]) userFollowers[viewingUser] = [];
  if (!followRequests[viewingUser]) followRequests[viewingUser] = [];

  var idx = userFollowers[viewingUser].indexOf(currentUser);
  if (idx > -1) {
    userFollowers[viewingUser].splice(idx, 1);
    await pushGitHubState({ userFollowers: userFollowers });
    openUserProfile(viewingUser);
    return;
  }

  var reqIdx = followRequests[viewingUser].indexOf(currentUser);
  if (reqIdx > -1) {
    followRequests[viewingUser].splice(reqIdx, 1);
    await pushGitHubState({ followRequests: followRequests });
    openUserProfile(viewingUser);
    return;
  }

  if (accountPrivacy[viewingUser] && currentUser !== DEV_NAME) {
    followRequests[viewingUser].push(currentUser);
    await pushGitHubState({ followRequests: followRequests });
    alert("🔒 Permintaan follow terkirim! Tunggu di-ACC di Kotak Masuk mereka.");
    openUserProfile(viewingUser);
    return;
  }

  userFollowers[viewingUser].push(currentUser);
  await pushInboxNotification(viewingUser, {
    text: "👤 @" + currentUser + " mulai mengikuti kamu!"
  });
  await pushGitHubState({ userFollowers: userFollowers });
  openUserProfile(viewingUser);
}

function closeUserProfileModal() {
  document.getElementById('user-profile-modal').style.display = 'none';
}

let activePhotoContext = { username: "", index: -1 };
function openPhotoDetail(username, index) {
  if (!canViewPrivateProfile(username)) {
    alert("🔒 Akun ini privat! Ikuti dan tunggu di-ACC dulu.");
    return;
  }
  activePhotoContext = { username: username, index: index };
  var photo = (userGalleries[username] || [])[index];
  if (!photo) return;
  document.getElementById('detail-photo-img').src = photo.img;
  document.getElementById('detail-like-count').textContent = formatCompactNumber(photo.likes);
  var isLiked = (photo.likedBy || []).includes(currentUser);
  document.getElementById('detail-like-btn').style.background = isLiked ? 'rgba(239, 68, 68, 0.3)' : 'rgba(255,255,255,0.1)';
  renderPhotoComments();
  document.getElementById('photo-detail-modal').style.display = 'flex';
}

async function triggerDetailLike() {
  var username = activePhotoContext.username;
  var index = activePhotoContext.index;
  var photos = userGalleries[username];
  if (!photos || !photos[index]) return;
  if (!photos[index].likedBy) photos[index].likedBy = [];
  var likedIdx = photos[index].likedBy.indexOf(currentUser);
  if (likedIdx > -1) {
    photos[index].likedBy.splice(likedIdx, 1);
    photos[index].likes--;
  } else {
    photos[index].likedBy.push(currentUser);
    photos[index].likes++;
    await pushInboxNotification(username, {
      text: "❤️ @" + currentUser + " menyukai foto galeri kamu!"
    });
  }
  document.getElementById('detail-like-count').textContent = formatCompactNumber(photos[index].likes);
  updateProfileView();
  await pushGitHubState({ galleries: userGalleries });
}

function sharePhotoLink() {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(window.location.href).catch(function() {});
  }
  alert("Tautan foto berhasil disalin!");
}

function renderPhotoComments() {
  var username = activePhotoContext.username;
  var index = activePhotoContext.index;
  var photo = userGalleries[username][index];
  var commentContainer = document.getElementById('detail-comments-list');
  commentContainer.innerHTML = '';
  var comments = photo.comments || [];
  if (comments.length === 0) {
    commentContainer.innerHTML = '<span style="color:rgba(255,255,255,0.4); text-align:center;">Belum ada komentar.</span>';
    return;
  }
  comments.forEach(function(c) {
    commentContainer.innerHTML += '<div><b>' + sanitizeHTML(c.user) + ':</b> ' + sanitizeHTML(c.text) + '</div>';
  });
}

async function postPhotoComment() {
  var input = document.getElementById('detail-comment-input');
  var text = sanitizeHTML(input.value.trim());
  if (!text) return;
  var username = activePhotoContext.username;
  var index = activePhotoContext.index;
  var photo = userGalleries[username][index];
  if (!photo.comments) photo.comments = [];
  photo.comments.push({ user: currentUser, text: text });
  input.value = '';
  renderPhotoComments();
  await pushGitHubState({ galleries: userGalleries });
}

function setReply(username, text) {
  currentReplyData = { replyToUser: username, replyToText: text };
  var bar = document.getElementById('chat-reply-preview');
  var dmBar = document.getElementById('dm-reply-preview');
  if (document.getElementById('tab-chat').classList.contains('active')) {
    if (bar) bar.style.display = 'flex';
    document.getElementById('chat-reply-target-user').textContent = username;
    document.getElementById('chat-reply-target-text').textContent = text;
    document.getElementById('message-input').focus();
  } else if (activeDMTarget) {
    if (dmBar) dmBar.style.display = 'flex';
    document.getElementById('dm-reply-target-user').textContent = username;
    document.getElementById('dm-reply-target-text').textContent = text;
    document.getElementById('dm-input').focus();
  }
}

function cancelReply() {
  currentReplyData = null;
  var bar = document.getElementById('chat-reply-preview');
  var dmBar = document.getElementById('dm-reply-preview');
  if (bar) bar.style.display = 'none';
  if (dmBar) dmBar.style.display = 'none';
}

async function sendMessage() {
  var input = document.getElementById('message-input');
  if (!input) return;
  var text = sanitizeHTML(input.value.trim());
  if (!text) return;
  var isDev = (currentUser === DEV_NAME);

  var newMsg = {
    id: 'msg_' + Date.now() + "_" + Math.random(),
    user: currentUser,
    avatar: currentAvatar,
    text: text,
    replyTo: currentReplyData ? { user: currentReplyData.replyToUser, text: currentReplyData.replyToText } : null,
    frame: activeFrame || (isDev ? 'admin_galaxy' : ''),
    bubble: activeBubble || (isDev ? 'dev_supreme_bubble' : ''),
    nameEffect: activeNameEffect || (isDev ? 'supreme' : ''),
    textEffect: activeTextEffect || '',
    fontEffect: activeFontEffect || '',
    shape: activeBorderShape || 'shape_circle',
    accessory: activeAccessory || 'acc_none'
  };

  messages.push(newMsg);
  userCoins += isUserVip(currentUser) ? 20 : 10;
  input.value = '';
  cancelReply();
  updateCoinsDisplay();
  renderMessages();

  await pushGitHubState({
    messages: messages,
    coins: { [currentUser]: userCoins }
  });
}

function checkEnter(event) {
  if (event.key === 'Enter') sendMessage();
}

function renderMessageElement(msg, container) {
  var isDevUser = (msg.user === DEV_NAME);
  var isVipUser = isUserVip(msg.user) || isUserPass(msg.user) || isDevUser;
  var isMe = (msg.user === currentUser);

  var div = document.createElement('div');
  div.className = "message " + (isMe ? "my-message" : "other-message");
  div.onclick = function() { setReply(msg.user, msg.text); };

  if (msg.bubble === 'dev_supreme_bubble' || (isDevUser && !msg.bubble)) {
    div.classList.add('dev-supreme-bubble');
  } else if (msg.bubble && msg.bubble.startsWith('bubble_')) {
    var bd = getEffectStyleData(msg.bubble);
    if (bd) {
      div.classList.add('dyn-bubble-live');
      div.style.setProperty('--bub-bg', bd.bg);
      div.style.setProperty('--bub-border', bd.c1);
      div.style.setProperty('--bub-glow', bd.c1);
      div.style.filter = "hue-rotate(" + bd.hue + "deg)";
    }
  }

  var headerDiv = document.createElement('div');
  headerDiv.className = 'message-header';

  var avatarWrapper = document.createElement('div');
  var fId = msg.frame || (isDevUser ? 'admin_galaxy' : '');
  var accId = msg.accessory || 'acc_none';
  var canView = canViewPrivateProfile(msg.user);
  avatarWrapper.innerHTML = buildAvatarHTML(msg.user, canView ? msg.avatar : '', fId, msg.shape || 'shape_circle', accId);
  avatarWrapper.onclick = function(e) { e.stopPropagation(); openUserProfile(msg.user); };

  var nameSpan = document.createElement('span');
  nameSpan.textContent = msg.user;
  nameSpan.style.cursor = 'pointer';
  nameSpan.onclick = function(e) { e.stopPropagation(); openUserProfile(msg.user); };

  if (msg.nameEffect === 'supreme' || (isDevUser && !msg.nameEffect)) {
    nameSpan.className = 'dev-supreme-name';
    var themeInfo = getDevThemeCSS(activeDevTheme);
    nameSpan.style.backgroundImage = themeInfo.nameGrad;
  } else if (msg.nameEffect && msg.nameEffect.startsWith('name_')) {
    var nd = getEffectStyleData(msg.nameEffect);
    if (nd) {
      nameSpan.className = 'dyn-name-live';
      nameSpan.style.setProperty('--name-grad', "linear-gradient(45deg, " + nd.c1 + ", " + nd.c2 + ", #ffffff, " + nd.c1 + ")");
    }
  } else {
    nameSpan.style.color = '#38bdf8';
    nameSpan.style.fontWeight = 'bold';
  }

  headerDiv.appendChild(avatarWrapper);
  headerDiv.appendChild(nameSpan);

  if (isVipUser) {
    var badge = document.createElement('span');
    badge.className = isDevUser ? 'dev-badge' : 'vip-badge';
    badge.textContent = isDevUser ? 'DEVELOPER' : 'VIP';
    if (isDevUser) {
      var devThemeInfo = getDevThemeCSS(activeDevTheme);
      badge.style.backgroundImage = devThemeInfo.badgeBg;
    }
    headerDiv.appendChild(badge);
  }

  div.appendChild(headerDiv);

  if (msg.replyTo) {
    var replyBox = document.createElement('div');
    replyBox.className = 'reply-quote-box';
    replyBox.innerHTML = '<b>@' + sanitizeHTML(msg.replyTo.user) + '</b><br>' + sanitizeHTML(msg.replyTo.text);
    div.appendChild(replyBox);
  }

  var textDiv = document.createElement('div');
  textDiv.className = 'text';
  textDiv.textContent = msg.text;
  if (msg.fontEffect && msg.fontEffect.startsWith('font_')) {
    var fd = getFontStyleData(msg.fontEffect);
    if (fd) textDiv.style.cssText = fd.style;
  }
  if (msg.textEffect && msg.textEffect.startsWith('text_')) {
    var td = getEffectStyleData(msg.textEffect);
    if (td) {
      textDiv.classList.add('dyn-text-live');
      textDiv.style.setProperty('--txt-grad', "linear-gradient(45deg, " + td.c1 + ", " + td.c2 + ", #ffffff, " + td.c1 + ")");
    }
  }

  div.appendChild(textDiv);
  container.appendChild(div);
}

function renderMessages() {
  var container = document.getElementById('chat-container');
  if (!container) return;
  container.innerHTML = '';
  messages.forEach(function(msg) { renderMessageElement(msg, container); });
  container.scrollTop = container.scrollHeight;
}

function updateCoinsDisplay() {
  var uc = document.getElementById('user-coins');
  if (uc) uc.textContent = formatCompactNumber(userCoins);
  var sc = document.getElementById('shop-coins');
  if (sc) sc.textContent = formatCompactNumber(userCoins);
}

let activeDMTarget = "";

function renderDMProfileList() {
  var container = document.getElementById('dm-profiles-container');
  if (!container) return;
  container.innerHTML = '';
  var users = Object.keys(userDatabase).filter(function(u) { return u !== currentUser; });
  var activeOnline = getActiveOnlineMap();

  if (users.length === 0) {
    container.innerHTML = '<p style="font-size:11px; color:rgba(255,255,255,0.4); text-align:center;">Belum ada pengguna lain.</p>';
    return;
  }
  users.forEach(function(u) {
    var isOnline = Boolean(activeOnline[u]);
    var lastChat = "Belum ada percakapan...";
    var userDMs = dmMessages.filter(function(m) {
      return (m.from === currentUser && m.to === u) || (m.from === u && m.to === currentUser);
    });
    if (userDMs.length > 0) {
      var latest = userDMs[userDMs.length - 1];
      lastChat = (latest.from === currentUser ? "Anda: " : "") + latest.text;
    }
    var meta = userProfilesMeta[u] || {};
    var canView = canViewPrivateProfile(u);
    var avatarSnippet = buildAvatarHTML(u, canView ? (meta.avatar || '') : '', meta.frame || '', meta.shape || 'shape_circle', meta.accessory || 'acc_none');
    container.innerHTML +=
      '<div class="dm-user-card" onclick="openDMChat(\'' + u + '\')">' +
        '<div class="dm-user-info">' +
          avatarSnippet +
          '<div>' +
            '<div style="font-weight:bold; color:#38bdf8; font-size:13px;">' + sanitizeHTML(u) + ' ' + (accountPrivacy[u] ? '🔒' : '') + '</div>' +
            '<div style="font-size:10px; color:rgba(255,255,255,0.6); max-width:180px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">' + sanitizeHTML(lastChat) + '</div>' +
          '</div>' +
        '</div>' +
        '<div><span class="status-indicator-badge ' + (isOnline ? 'status-online' : 'status-offline') + '">' + (isOnline ? '🟢 Online' : '⚪ Offline') + '</span></div>' +
      '</div>';
  });
}

function openDMChat(username) {
  activeDMTarget = username;
  document.getElementById('dm-list-view').style.display = 'none';
  document.getElementById('dm-chat-view').style.display = 'flex';
  document.getElementById('active-dm-target-name').textContent = username;
  renderDM(username);
}

function backToDMList() {
  activeDMTarget = "";
  cancelReply();
  document.getElementById('dm-chat-view').style.display = 'none';
  document.getElementById('dm-list-view').style.display = 'flex';
  renderDMProfileList();
}

async function sendDM() {
  var input = document.getElementById('dm-input');
  if (!input) return;
  var text = sanitizeHTML(input.value.trim());
  if (!text || !activeDMTarget) return;
  var isDev = (currentUser === DEV_NAME);

  dmMessages.push({
    id: 'dm_' + Date.now() + "_" + Math.random(),
    from: currentUser,
    to: activeDMTarget,
    text: text,
    replyTo: currentReplyData ? { user: currentReplyData.replyToUser, text: currentReplyData.replyToText } : null,
    avatar: currentAvatar,
    frame: activeFrame || (isDev ? 'admin_galaxy' : ''),
    bubble: activeBubble || (isDev ? 'dev_supreme_bubble' : ''),
    nameEffect: activeNameEffect || (isDev ? 'supreme' : ''),
    textEffect: activeTextEffect || '',
    fontEffect: activeFontEffect || '',
    shape: activeBorderShape || 'shape_circle',
    accessory: activeAccessory || 'acc_none',
    time: Date.now()
  });

  input.value = '';
  cancelReply();
  renderDM(activeDMTarget);
  await pushGitHubState({ dms: dmMessages });
}

function checkDMPress(event) {
  if (event.key === 'Enter') sendDM();
}

async function deleteDMMessage(msgId) {
  if (confirm("Hapus pesan ini?")) {
    dmMessages = dmMessages.filter(function(m) { return m.id !== msgId; });
    renderDM(activeDMTarget);
    await pushGitHubState({ dms: dmMessages });
  }
}

function renderDM(targetUser) {
  var container = document.getElementById('dm-container');
  if (!container) return;
  container.innerHTML = '';
  var filtered = dmMessages.filter(function(m) {
    return (m.from === currentUser && m.to === targetUser) || (m.from === targetUser && m.to === currentUser);
  });
  if (filtered.length === 0) {
    container.innerHTML = '<div style="font-size:11px; color:rgba(255,255,255,0.4); text-align:center; margin-top:20px;">Mulai percakapan privat dengan mengirim pesan di bawah.</div>';
    return;
  }
  filtered.forEach(function(dm) {
    var senderMeta = userProfilesMeta[dm.from] || {};
    var msgObj = {
      user: dm.from,
      avatar: dm.avatar || senderMeta.avatar || "",
      text: dm.text,
      replyTo: dm.replyTo,
      frame: dm.frame || senderMeta.frame || "",
      bubble: dm.bubble || senderMeta.bubble || "",
      nameEffect: dm.nameEffect || senderMeta.nameEffect || "",
      textEffect: dm.textEffect || senderMeta.textEffect || "",
      fontEffect: dm.fontEffect || senderMeta.fontEffect || "",
      shape: dm.shape || senderMeta.shape || "shape_circle",
      accessory: dm.accessory || senderMeta.accessory || "acc_none"
    };
    renderMessageElement(msgObj, container);
    var lastChild = container.lastElementChild;
    if (dm.from === currentUser && lastChild) {
      var delBtn = document.createElement('button');
      delBtn.innerHTML = '🗑️ Hapus';
      delBtn.style.cssText = 'background:none; border:none; color:rgba(255,255,255,0.5); font-size:9px; cursor:pointer; align-self:flex-end; margin-top:2px;';
      delBtn.onclick = function() { deleteDMMessage(dm.id); };
      container.appendChild(delBtn);
    }
  });
  container.scrollTop = container.scrollHeight;
}

let selectedGiftPremTarget = "";
let selectedGiftCoinTarget = "";

function handleGiftSearchInput(kind, query) {
  var dropdownId = kind === 'prem' ? 'dev-gift-prem-dropdown' : 'dev-gift-coin-dropdown';
  var dropdown = document.getElementById(dropdownId);
  if (!dropdown) return;
  dropdown.innerHTML = '';
  var q = query.trim().toLowerCase();
  if (!q) { dropdown.style.display = 'none'; return; }
  var matched = Object.keys(userDatabase).filter(function(u) { return u.includes(q); });
  if (matched.length === 0) { dropdown.style.display = 'none'; return; }
  matched.forEach(function(u) {
    var item = document.createElement('div');
    item.className = 'autocomplete-item';
    item.innerHTML = '<span style="font-size:12px; font-weight:bold;">@' + sanitizeHTML(u) + '</span>';
    item.onclick = function() {
      if (kind === 'prem') {
        selectedGiftPremTarget = u;
        document.getElementById('dev-gift-prem-search').value = u;
        document.getElementById('dev-gift-prem-selected').textContent = u;
      } else {
        selectedGiftCoinTarget = u;
        document.getElementById('dev-gift-coin-search').value = u;
        document.getElementById('dev-gift-coin-selected').textContent = u;
      }
      dropdown.style.display = 'none';
    };
    dropdown.appendChild(item);
  });
  dropdown.style.display = 'block';
}

let selectedBotTarget = "";
let selectedBotPhotoIndex = -1;

async function loadSecurityAuditLogs() {
  if (currentUser !== DEV_NAME) return;
  try {
    var res = await fetch('/api/security/logs', { cache: 'no-store' });
    if (res.ok) {
      var logs = await res.json();
      var container = document.getElementById('security-logs-container');
      container.innerHTML = '';
      if (!logs || logs.length === 0) {
        container.innerHTML = '<span style="font-size:11px; color:rgba(255,255,255,0.4); text-align:center;">Belum ada percobaan serangan atau VPN tercatat.</span>';
      } else {
        logs.forEach(function(log) {
          var timeStr = new Date(log.time).toLocaleTimeString();
          container.innerHTML +=
            '<div style="background:rgba(239,68,68,0.15); border:1px solid rgba(239,68,68,0.4); padding:6px; border-radius:6px; font-size:11px; margin-bottom:4px;">' +
              '<div style="color:#fca5a5; font-weight:bold;">🚨 ' + log.toolUsed + ' (' + timeStr + ')</div>' +
              '<div><b>IP:</b> <code>' + log.ip + '</code></div>' +
              '<div><b>Perangkat/Alat:</b> ' + sanitizeHTML(log.device) + '</div>' +
              '<div><b>Detail:</b> ' + sanitizeHTML(log.attackVector) + '</div>' +
            '</div>';
        });
      }
    }
  } catch (e) {
    console.error("Gagal memuat log keamanan:", e);
  }
}

async function openDevModal() {
  if (currentUser !== DEV_NAME) { alert("Hanya Developer Pito!"); return; }
  await pullGitHubState();
  var activeOnline = getActiveOnlineMap();
  var stalkingList = document.getElementById('stalking-users-list');
  stalkingList.innerHTML = '';
  var count = 0;

  for (var u in userDatabase) {
    var isOnline = Boolean(activeOnline[u]);
    if (isOnline) count++;
    stalkingList.innerHTML +=
      '<div class="stalking-user-row">' +
        '<span>👤 <b>' + u + '</b> ' + (isOnline ? '🟢 (Online)' : '⚪ (Offline)') + '</span>' +
        '<button onclick="openUserProfile(\'' + u + '\')" style="background:#0284c7; border:none; color:white; padding:3px 6px; border-radius:4px; cursor:pointer; font-size:10px;">Stalk</button>' +
      '</div>';
  }
  document.getElementById('stalking-online-count').textContent = count;
  renderDevBugReports();
  renderDevLostReports();
  filterDevSearchAccounts("");
  loadSecurityAuditLogs();

  document.getElementById('dev-login-msg-input').value = devLoginNotificationText;
  filterDevBanUsers("");
  document.getElementById('dev-badge-style-select').value = activeDevTheme;
  document.getElementById('dev-accessory-select').value = activeDevAccessory;
  document.getElementById('dev-modal').style.display = 'flex';
}

function renderDevBugReports() {
  var listEl = document.getElementById('dev-bug-reports-list');
  var countEl = document.getElementById('bug-report-count');
  if (!listEl) return;
  listEl.innerHTML = '';
  if (countEl) countEl.textContent = bugReports.length;
  if (bugReports.length === 0) {
    listEl.innerHTML = '<span style="font-size:10px; color:rgba(255,255,255,0.4); text-align:center;">Belum ada laporan bug.</span>';
    return;
  }
  bugReports.forEach(function(bug, idx) {
    var dateStr = new Date(bug.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    listEl.innerHTML +=
      '<div style="background:rgba(30,41,59,0.7); padding:6px 8px; border-radius:6px; font-size:11px; margin-bottom:4px;">' +
        '<div style="display:flex; justify-content:space-between;"><b style="color:#f87171;">@' + sanitizeHTML(bug.user) + '</b><span style="font-size:9px;">' + dateStr + '</span></div>' +
        '<div style="margin:4px 0;">' + sanitizeHTML(bug.text) + '</div>' +
        '<button onclick="resolveBugReport(' + idx + ')" style="background:#10b981; border:none; color:white; padding:2px 6px; border-radius:4px; font-size:9px; font-weight:bold; cursor:pointer;">Selesai / Hapus</button>' +
      '</div>';
  });
}

function renderDevLostReports() {
  var listEl = document.getElementById('dev-lost-reports-list');
  var countEl = document.getElementById('lost-report-count');
  if (!listEl) return;
  listEl.innerHTML = '';
  if (countEl) countEl.textContent = lostReports.length;
  if (lostReports.length === 0) {
    listEl.innerHTML = '<span style="font-size:10px; color:rgba(255,255,255,0.4); text-align:center;">Belum ada laporan kehilangan akun.</span>';
    return;
  }
  lostReports.forEach(function(rep, idx) {
    var dateStr = new Date(rep.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    listEl.innerHTML +=
      '<div style="background:rgba(30,41,59,0.7); padding:6px 8px; border-radius:6px; font-size:11px; margin-bottom:4px;">' +
        '<div style="display:flex; justify-content:space-between;"><b style="color:#fbbf24;">Akun: @' + sanitizeHTML(rep.username) + '</b><span style="font-size:9px;">' + dateStr + '</span></div>' +
        '<div style="margin:4px 0;">' + sanitizeHTML(rep.details) + '</div>' +
        '<button onclick="resolveLostReport(' + idx + ')" style="background:#10b981; border:none; color:white; padding:2px 6px; border-radius:4px; font-size:9px; font-weight:bold; cursor:pointer;">Selesai / Hapus</button>' +
      '</div>';
  });
}

async function resolveBugReport(index) {
  bugReports.splice(index, 1);
  renderDevBugReports();
  await pushGitHubState({ bugReports: bugReports });
}

async function resolveLostReport(index) {
  lostReports.splice(index, 1);
  renderDevLostReports();
  await pushGitHubState({ lostReports: lostReports });
}

function filterDevSearchAccounts(query) {
  var listEl = document.getElementById('dev-search-acc-list');
  if (!listEl) return;
  listEl.innerHTML = '';
  var q = query.trim().toLowerCase();
  for (var u in userDatabase) {
    if (!q || u.includes(q)) {
      listEl.innerHTML += '<div style="background:rgba(30,41,59,0.6); padding:5px 8px; border-radius:6px; font-size:11px;">👤 <b>' + u + '</b> | Pass: <code style="color:#38bdf8;">' + userDatabase[u] + '</code></div>';
    }
  }
}

function closeDevModal() {
  document.getElementById('dev-modal').style.display = 'none';
}

async function devExecuteGivePremium() {
  if (currentUser !== DEV_NAME) return;
  var targetUser = (selectedGiftPremTarget || document.getElementById('dev-gift-prem-search').value || "").trim().toLowerCase();
  if (!targetUser || !userDatabase[targetUser]) {
    alert("Pilih username target yang valid lewat search!");
    return;
  }
  var tier = document.getElementById('dev-give-tier').value;
  var now = Date.now();
  var expireTime = now;
  var tierName = "";
  if (tier === '2days') { expireTime = now + (2 * 86400000); tierName = "Premium 2 Hari"; }
  else if (tier === '1month') { expireTime = now + (30 * 86400000); tierName = "Premium 1 Bulan"; }
  else if (tier === '3months') { expireTime = now + (90 * 86400000); tierName = "Premium 3 Bulan"; }
  else { expireTime = 0; tierName = "Premium Permanen"; }

  userVipStatus[targetUser] = { expireTime: expireTime };
  await pushGitHubState({ vipStatus: userVipStatus });
  alert("👑 Berhasil memberikan " + tierName + " kepada @" + targetUser + "!");
  closeDevModal();
}

function handleBotSearchInput(query) {
  var dropdown = document.getElementById('bot-autocomplete-dropdown');
  dropdown.innerHTML = '';
  var q = query.trim().toLowerCase();
  if (!q) { dropdown.style.display = 'none'; return; }
  var matchedUsers = Object.keys(userDatabase).filter(function(u) { return u.includes(q); });
  if (matchedUsers.length === 0) { dropdown.style.display = 'none'; return; }
  matchedUsers.forEach(function(u) {
    var item = document.createElement('div');
    item.className = 'autocomplete-item';
    item.innerHTML = '<span style="font-size:12px; font-weight:bold;">' + u + '</span>';
    item.onclick = function() { selectBotTarget(u); };
    dropdown.appendChild(item);
  });
  dropdown.style.display = 'block';
}

function selectBotTarget(username) {
  selectedBotTarget = username;
  document.getElementById('dev-bot-search').value = username;
  document.getElementById('bot-autocomplete-dropdown').style.display = 'none';
  document.getElementById('selected-bot-target-text').textContent = username;
  selectedBotPhotoIndex = -1;
  var pickerContainer = document.getElementById('bot-photo-picker-container');
  pickerContainer.innerHTML = '';
  var photos = userGalleries[username] || [];
  if (photos.length === 0) {
    pickerContainer.innerHTML = '<span style="font-size:10px; color:rgba(255,255,255,0.4); grid-column:span 3; text-align:center; padding:10px;">User ini belum memiliki foto di galeri.</span>';
    return;
  }
  photos.forEach(function(photo, idx) {
    pickerContainer.innerHTML += '<div class="bot-photo-picker-item" id="bot-picker-photo-' + idx + '" onclick="selectBotPhoto(' + idx + ')"><img src="' + photo.img + '"></div>';
  });
}

function selectBotPhoto(idx) {
  selectedBotPhotoIndex = idx;
  document.querySelectorAll('.bot-photo-picker-item').forEach(function(el) { el.classList.remove('selected'); });
  var targetEl = document.getElementById('bot-picker-photo-' + idx);
  if (targetEl) targetEl.classList.add('selected');
}

function getCustomBotAmount() {
  var val = parseInt(document.getElementById('dev-bot-custom-amount').value, 10);
  if (isNaN(val) || val <= 0) return 50;
  if (val > 100000000) return 100000000;
  return val;
}

async function runBotAddFollowers() {
  if (currentUser !== DEV_NAME || !selectedBotTarget) return;
  var amount = getCustomBotAmount();
  botFollowerBoost[selectedBotTarget] = Number(botFollowerBoost[selectedBotTarget] || 0) + amount;
  await pushGitHubState({ botFollowerBoost: botFollowerBoost });
  updateProfileView();
  alert("🤖 Berhasil menambahkan +" + formatCompactNumber(amount) + " followers visual ke @" + selectedBotTarget + "!");
}

async function runBotAddLikesToTargetPhoto() {
  if (currentUser !== DEV_NAME || !selectedBotTarget || selectedBotPhotoIndex === -1) return;
  var photos = userGalleries[selectedBotTarget];
  if (!photos || !photos[selectedBotPhotoIndex]) return;
  var amount = getCustomBotAmount();
  photos[selectedBotPhotoIndex].likes = (photos[selectedBotPhotoIndex].likes || 0) + amount;
  await pushGitHubState({ galleries: userGalleries });
  alert("🤖 Berhasil menambahkan " + formatCompactNumber(amount) + " likes bot!");
}

async function sendGlobalAnnouncement() {
  if (currentUser !== DEV_NAME) return;
  var text = document.getElementById('dev-announcement-input').value.trim();
  var duration = parseInt(document.getElementById('dev-announcement-duration').value, 10) || 10000;
  if (!text) { alert("Masukkan teks pengumuman!"); return; }
  var annObj = { text: text, duration: duration, time: Date.now() };
  showAnnouncementBanner(text, duration);
  document.getElementById('dev-announcement-input').value = '';
  await pushGitHubState({ announcement: annObj });
  alert("Pengumuman berhasil disiarkan ke GitHub DB!");
}

function filterDevBanUsers(query) {
  var list = document.getElementById('dev-ban-list');
  if (!list) return;
  list.innerHTML = '';
  for (var u in userDatabase) {
    if (u === DEV_NAME) continue;
    if (u.includes(query.toLowerCase())) {
      var isBanned = bannedUsers.includes(u);
      list.innerHTML +=
        '<div class="user-item">' +
          '<span>' + sanitizeHTML(u) + ' ' + (isBanned ? '(BANNED)' : '') + '</span>' +
          '<button class="ban-btn" onclick="toggleBanUser(\'' + u + '\')">' + (isBanned ? 'Unban' : 'Ban') + '</button>' +
        '</div>';
    }
  }
}

async function toggleBanUser(username) {
  if (currentUser !== DEV_NAME) return;
  var reason = document.getElementById('dev-ban-reason-input').value.trim() || "Melanggar aturan komunitas.";
  if (bannedUsers.includes(username)) {
    bannedUsers = bannedUsers.filter(function(u) { return u !== username; });
    alert("User " + username + " di-unban.");
  } else {
    bannedUsers.push(username);
    playSoundEffect('ban');
    messages.push({
      id: 'msg_' + Date.now(),
      user: "SYSTEM",
      avatar: "",
      text: "⚠️ PENGUMUMAN BAN: Akun @" + username + " dibanned karena: \"" + reason + "\".",
      frame: "",
      bubble: "",
      nameEffect: "",
      textEffect: "",
      fontEffect: "",
      shape: "shape_circle",
      accessory: "acc_none"
    });
    renderMessages();
    alert("User " + username + " berhasil dibanned!");
  }
  await pushGitHubState({ banned: bannedUsers, messages: messages });
  filterDevBanUsers(document.getElementById('search-ban-input').value);
}

function uploadDevBackground(event) {
  if (currentUser !== DEV_NAME) return;
  var file = event.target.files[0];
  if (file) {
    var reader = new FileReader();
    reader.onload = function(ev) {
      customBgImage = ev.target.result;
      document.body.style.setProperty('background-image', 'url(' + customBgImage + ')');
      localStorage.setItem('chat_bg_image', customBgImage);
      alert("Wallpaper diperbarui!");
    };
    reader.readAsDataURL(file);
  }
}

function resetBackground() {
  if (currentUser !== DEV_NAME) return;
  customBgImage = "";
  document.body.style.removeProperty('background-image');
  localStorage.removeItem('chat_bg_image');
  alert("Wallpaper dikembalikan ke default.");
}

function uploadDevAudio(event) {
  if (currentUser !== DEV_NAME) return;
  var file = event.target.files[0];
  if (file) {
    var fileURL = URL.createObjectURL(file);
    var audio = document.getElementById('global-bg-audio');
    audio.src = fileURL;
    audio.play().catch(function() {});
    document.getElementById('now-playing-label').textContent = "Memutar lagu: " + file.name;
  }
}

function toggleMuteGlobalAudio() {
  if (currentUser !== DEV_NAME) return;
  var audio = document.getElementById('global-bg-audio');
  audio.muted = !audio.muted;
  var muteBtn = document.getElementById('mute-global-btn');
  muteBtn.textContent = audio.muted ? "🔊 Unmute Musik untuk Semua" : "🔇 Mute Musik untuk Semua";
  muteBtn.style.background = audio.muted ? "#10b981" : "#ef4444";
}

async function devGiveCoins() {
  if (currentUser !== DEV_NAME) return;
  var targetUser = (selectedGiftCoinTarget || document.getElementById('dev-gift-coin-search').value || "").trim().toLowerCase();
  if (!targetUser || !userDatabase[targetUser]) {
    alert("Pilih username target koin yang valid lewat search!");
    return;
  }
  var amount = parseInt(document.getElementById('dev-coin-amount').value, 10);
  if (isNaN(amount) || amount <= 0) { alert("Jumlah koin tidak valid!"); return; }
  if (targetUser === currentUser) {
    userCoins += amount;
    updateCoinsDisplay();
  }
  await pushGitHubState({ coins: { [targetUser]: amount } });
  alert("Berhasil mengirim " + formatCompactNumber(amount) + " koin ke " + targetUser + "!");
}
</script>
</body>
</html>`;

    return new Response(html, {
      headers: {
        "Content-Type": "text/html;charset=UTF-8",
        "Cache-Control": "no-store"
      }
    });
  }
};
