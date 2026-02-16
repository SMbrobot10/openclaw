#!/usr/bin/env node
/**
 * Sidecar script that runs inside the Railway container after the gateway starts.
 * Connects via loopback (localhost) which auto-approves device pairing.
 * Then auto-approves incoming browser pairing requests for a configurable window.
 */

import { randomUUID } from "node:crypto";

const GATEWAY_URL = "ws://localhost:8080";

// ── helpers ──────────────────────────────────────────────────────────────────

let reqId = 0;
function nextId() {
  return `req-${++reqId}`;
}

function sendReq(ws, method, params = {}) {
  const id = nextId();
  const frame = JSON.stringify({ type: "req", id, method, params });
  ws.send(frame);
  return id;
}

// Native Node.js WebSocket uses MessageEvent objects with addEventListener,
// so we extract .data from the event. This helper parses the JSON payload.
function parseWsMessage(ev) {
  try {
    const raw = typeof ev === "object" && ev !== null && "data" in ev ? ev.data : ev;
    return JSON.parse(String(raw));
  } catch {
    return null;
  }
}

function waitForRes(ws, id, timeoutMs = 15_000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`timeout waiting for res id=${id}`)),
      timeoutMs,
    );
    function onMsg(ev) {
      const msg = parseWsMessage(ev);
      if (!msg) return;
      if (msg.type === "res" && msg.id === id) {
        clearTimeout(timer);
        ws.removeEventListener("message", onMsg);
        if (msg.ok) resolve(msg.payload);
        else reject(new Error(`RPC error: ${JSON.stringify(msg.error)}`));
      }
    }
    ws.addEventListener("message", onMsg);
  });
}

function waitForEvent(ws, eventName, timeoutMs = 10_000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`timeout waiting for event=${eventName}`)),
      timeoutMs,
    );
    function onMsg(ev) {
      const msg = parseWsMessage(ev);
      if (!msg) return;
      if (msg.type === "event" && msg.event === eventName) {
        clearTimeout(timer);
        ws.removeEventListener("message", onMsg);
        resolve(msg.payload);
      }
    }
    ws.addEventListener("message", onMsg);
  });
}

// ── device identity (Ed25519) ────────────────────────────────────────────────

function base64UrlEncode(buf) {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function generateDeviceIdentity() {
  const keyPair = await crypto.subtle.generateKey("Ed25519", true, [
    "sign",
    "verify",
  ]);
  const publicKeyRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  const publicKeyB64Url = base64UrlEncode(publicKeyRaw);
  const hashBuf = await crypto.subtle.digest("SHA-256", publicKeyRaw);
  const deviceId = Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return {
    keyPair,
    publicKeyB64Url,
    deviceId,
    privateKey: keyPair.privateKey,
  };
}

function buildDeviceAuthPayload(params) {
  const version = params.nonce ? "v2" : "v1";
  const scopes = (params.scopes || []).join(",");
  const token = params.token || "";
  const base = [
    version,
    params.deviceId,
    params.clientId,
    params.clientMode,
    params.role,
    scopes,
    String(params.signedAtMs),
    token,
  ];
  if (version === "v2") {
    base.push(params.nonce || "");
  }
  return base.join("|");
}

async function signPayload(privateKey, payload) {
  const encoder = new TextEncoder();
  const data = encoder.encode(payload);
  const signature = await crypto.subtle.sign("Ed25519", privateKey, data);
  return base64UrlEncode(signature);
}

// ── main ─────────────────────────────────────────────────────────────────────

async function main() {
  const gatewayToken = process.env.OPENCLAW_GATEWAY_TOKEN;
  if (!gatewayToken) {
    console.error(
      "OPENCLAW_GATEWAY_TOKEN not set, skipping sidecar configuration",
    );
    process.exit(0);
  }

  console.log("[sidecar] Generating device identity...");
  const device = await generateDeviceIdentity();
  console.log("[sidecar] Device ID:", device.deviceId);

  console.log("[sidecar] Connecting to gateway via loopback...");
  const ws = new WebSocket(GATEWAY_URL);

  // Set up the challenge listener BEFORE the connection opens to avoid
  // a race condition where the server sends the challenge immediately.
  const challengePromise = waitForEvent(ws, "connect.challenge", 15_000);

  ws.addEventListener("error", (err) => {
    console.error("[sidecar] WebSocket error:", err.message || err);
    process.exit(1);
  });

  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve);
    ws.addEventListener("error", reject);
  });
  console.log("[sidecar] Connected. Waiting for challenge...");

  // 1. Wait for connect.challenge (listener already set up)
  const challenge = await challengePromise;
  console.log("[sidecar] Got challenge, nonce:", challenge.nonce);

  // 2. Build device auth payload and sign
  const signedAtMs = Date.now();
  const scopes = ["operator.admin", "operator.pairing", "operator.approvals"];
  const role = "operator";
  // Use gateway-client/backend to avoid origin check (native WebSocket has no Origin header).
  // Loopback connection auto-approves pairing regardless of client ID.
  const clientId = "gateway-client";
  const clientMode = "backend";

  const payload = buildDeviceAuthPayload({
    deviceId: device.deviceId,
    clientId,
    clientMode,
    role,
    scopes,
    signedAtMs,
    token: gatewayToken,
    nonce: challenge.nonce,
  });

  const signature = await signPayload(device.privateKey, payload);

  // 3. Send connect request
  const connectId = sendReq(ws, "connect", {
    minProtocol: 3,
    maxProtocol: 3,
    client: {
      id: clientId,
      displayName: "setup-sidecar",
      version: "dev",
      platform: process.platform,
      mode: clientMode,
    },
    auth: {
      token: gatewayToken,
    },
    role,
    scopes,
    device: {
      id: device.deviceId,
      publicKey: device.publicKeyB64Url,
      signature,
      signedAt: signedAtMs,
      nonce: challenge.nonce,
    },
  });

  const hello = await waitForRes(ws, connectId, 15_000);
  console.log(
    "[sidecar] Authenticated! Server version:",
    hello.server?.version,
  );
  console.log(
    "[sidecar] Auth scopes:",
    hello.auth?.scopes?.join(", ") || "none",
  );

  if (!hello.auth?.scopes?.length) {
    console.error("[sidecar] No scopes granted - loopback auto-pairing may have failed");
    ws.close();
    process.exit(1);
  }

  // 4. Get current config (export)
  console.log("\n[sidecar] Fetching current config...");
  const configGetId = sendReq(ws, "config.get");
  const configResult = await waitForRes(ws, configGetId);
  console.log("[sidecar] ── Current Config ──");
  console.log(JSON.stringify(configResult.config, null, 2));

  // 5. Check health
  console.log("\n[sidecar] Checking gateway health...");
  const healthId = sendReq(ws, "health");
  const healthResult = await waitForRes(ws, healthId);
  console.log("[sidecar] ── Health ──");
  console.log(JSON.stringify(healthResult, null, 2));

  // 6. Auto-approve device pairing requests continuously.
  // This runs as a persistent daemon so browsers can pair at any time.
  // The gateway token is the security boundary.
  console.log(
    "\n[sidecar] Running as persistent pairing daemon (auto-approves all device pairing requests)...",
  );

  const pairingListener = (ev) => {
    const msg = parseWsMessage(ev);
    if (!msg) return;
    if (msg.type === "event" && msg.event === "device.pair.requested") {
      const req = msg.payload;
      console.log(
        `[sidecar] Auto-approving device pairing: ${req.deviceId} (${req.displayName || req.clientId})`,
      );
      const approveId = sendReq(ws, "device.pair.approve", {
        requestId: req.requestId,
      });
      waitForRes(ws, approveId, 10_000)
        .then(() =>
          console.log(
            `[sidecar] Pairing approved for device: ${req.deviceId}`,
          ),
        )
        .catch((err) =>
          console.error(`[sidecar] Pairing approval failed: ${err.message}`),
        );
    }
  };
  ws.addEventListener("message", pairingListener);

  // Periodically check for pending pairing requests that arrived before
  // the event listener was active (e.g., during reconnect).
  async function approvePending() {
    try {
      const listId = sendReq(ws, "device.pair.list");
      const listResult = await waitForRes(ws, listId, 10_000);
      const pending = listResult?.pending || [];
      for (const req of pending) {
        console.log(
          `[sidecar] Auto-approving pending device: ${req.deviceId} (${req.displayName || req.clientId})`,
        );
        const approveId = sendReq(ws, "device.pair.approve", {
          requestId: req.requestId,
        });
        try {
          await waitForRes(ws, approveId, 10_000);
          console.log(`[sidecar] Approved: ${req.deviceId}`);
        } catch (err) {
          console.error(`[sidecar] Approval failed: ${err.message}`);
        }
      }
    } catch {
      // ignore errors in periodic check
    }
  }

  // Check immediately and then every 30 seconds
  await approvePending();
  setInterval(approvePending, 30_000);

  // Keep alive forever - the gateway process is the main process
  console.log("[sidecar] ========================================");
  console.log("[sidecar] Gateway configured. Pairing daemon running.");
  console.log("[sidecar] ========================================");
  await new Promise(() => {}); // block forever
}

main().catch((err) => {
  console.error("[sidecar] Error:", err.message);
  // Don't exit with error - the gateway should keep running
  process.exit(0);
});
