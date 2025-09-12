// index.js — Multi-rep Zoom webhook → Zapier forwarder

const express = require("express");
const crypto = require("crypto");
const fetch = (...args) => import("node-fetch").then(({ default: f }) => f(...args));

const app = express();
const PORT = process.env.PORT || 10000;

// Capture RAW body for signature validation
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString("utf8");
    },
  })
);

// Define reps and their secrets/hooks via env vars
const REPS = [
  {
    name: "ALICIA",
    secret: process.env.ZOOM_WEBHOOK_SECRET_TOKEN,
    zapUrl: process.env.ZAPIER_HOOK_URL,
  },
  {
    name: "RENE",
    secret: process.env.RENE_ZOOM_SECRET_TOKEN,
    zapUrl: process.env.RENE_ZAPIER_HOOK_URL,
  },
].filter((r) => r.secret && r.zapUrl);

app.get("/", (_req, res) => {
  res.status(200).send("Zoom webhook server is running. POST to /webhook");
});

app.post("/webhook", async (req, res) => {
  try {
    const raw = req.rawBody || "";
    const ts = req.get("x-zm-request-timestamp") || "";
    const sig = req.get("x-zm-signature") || "";
    const base = `v0:${ts}:${raw}`;

    // Find which rep this event belongs to
    const matched = REPS.find((r) => {
      const hash = crypto.createHmac("sha256", r.secret).update(base).digest("hex");
      return `v0=${hash}` === sig;
    });

    if (!matched) {
      console.log("No matching rep for signature. Rejecting.");
      return res.status(401).send("Invalid signature");
    }

    const body = req.body || {};

    // Handle Zoom URL validation challenge
    if (body?.event === "endpoint.url_validation") {
      const plainToken = body?.payload?.plainToken || "";
      const encryptedToken = crypto
        .createHmac("sha256", matched.secret)
        .update(plainToken)
        .digest("hex");
      return res.json({ plainToken, encryptedToken });
    }

    // Forward payload to the rep's Zapier hook
    if (matched.zapUrl) {
      const resp = await fetch(matched.zapUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const text = await resp.text();
      console.log(`[${matched.name]()
