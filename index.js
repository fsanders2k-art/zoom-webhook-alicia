// index.js — Multi-rep Zoom webhook → Zapier forwarder
// One Render app for many reps (Alicia, Rene, ...)

const express = require("express");
const crypto = require("crypto");
const fetch = (...args) => import("node-fetch").then(({ default: f }) => f(...args));

const app = express();
const PORT = process.env.PORT || 10000;

/**
 * Important: capture the RAW JSON body so the HMAC signature matches Zoom's.
 */
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString("utf8");
    },
  })
);

/**
 * Configure your reps via env vars.
 * - Alicia keeps the original names so you don't have to change existing env.
 * - Rene uses RENE_* vars.
 * - You can add more reps by copying the object pattern below.
 */
const REPS = [
  {
    name: "ALICIA",
    secret: process.env.ZOOM_WEBHOOK_SECRET_TOKEN, // Alicia's Zoom Secret Token
    zapUrl: process.env.ZAPIER_HOOK_URL,           // Alicia's Zapier Catch Hook
  },
  {
    name: "RENE",
    secret: process.env.RENE_ZOOM_SECRET_TOKEN,    // Rene's Zoom Secret Token
    zapUrl: process.env.RENE_ZAPIER_HOOK_URL,      // Rene's Zapier Catch Hook
  },
].filter((r) => r.secret && r.zapUrl); // keep only fully configured reps

if (REPS.length === 0) {
  console.warn("WARNING: No reps configured. Add env vars before going live.");
}

app.get("/", (_req, res) => {
  res
    .status(200)
    .send(
      "Zoom webhook server is running. POST to /webhook (Alicia + Rene supported)."
    );
});

/**
 * POST /webhook
 * - Verifies Zoom signature (HMAC SHA256 with the rep's Secret Token)
 * - Handles endpoint.url_validation
 * - Forwards the full JSON body to the matched rep's Zapier hook
 */
app.post("/webhook", async (req, res) => {
  try {
    const raw = req.rawBody || "";
    const ts = req.get("x-zm-request-timestamp") || "";
    const sig = req.get("x-zm-signature") || "";
    const base = `v0:${ts}:${raw}`;

    // Find which rep's secret matches the signature
    const matched = REPS.find((r) => {
      const hash = crypto.createHmac("sha256", r.secret).update(base).digest("hex");
      return `v0=${hash}` === sig;
    });

    if (!matched) {
      console.log("No matching rep for signature. Rejecting.");
      return res.status(401).send("Invalid signature");
    }

    const body = req.body || {};

    // 1) Zoom URL validation (challenge)
    if (body?.event === "endpoint.url_validation") {
      const plainToken = body?.payload?.plainToken || "";
      const encryptedToken = crypto
        .createHmac("sha256", matched.secret)
        .update(plainToken)
        .digest("hex");

      console.log(`[${matched.name}] URL validation`);
      return res.json({ plainToken, encryptedToken });
    }

    // 2) Forward to the matched rep's Zapier hook
    try {
      console.log(`[${matched.name}] Posting to: ${matched.zapUrl}`);
      const resp = await fetch(matched.zapUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const text = await resp.text();
      console.log(`[${matched.name}] Zapier response:`, resp.status, text);
    } catch (err) {
      console.error(`[${matched.name}] Error posting to Zapier:`, err);
    }

    // 3) Ack Zoom quickly
    res.status(200).send("OK");
  } catch (err) {
    console.error("Webhook handler error:", err);
    res.status(500).send("Server error");
  }
});

app.listen(PORT, () => {
  console.log(`Zoom webhook listening on port ${PORT}`);
});
