// Minimal Zoom webhook → Zapier forwarder
const express = require("express");
const crypto = require("crypto");
const fetch = (...args) => import("node-fetch").then(({ default: f }) => f(...args));

const app = express();
const PORT = process.env.PORT || 10000;

// capture RAW body so Zoom signature matches
app.use(express.json({
  verify: (req, _res, buf) => { req.rawBody = buf.toString("utf8"); }
}));

const ZOOM_SECRET = process.env.ZOOM_WEBHOOK_SECRET_TOKEN;
const ZAPIER_HOOK_URL = process.env.ZAPIER_HOOK_URL;

app.get("/", (_req, res) => {
  res.status(200).send("Zoom webhook server is running. POST to /webhook");
});

app.post("/webhook", async (req, res) => {
  try {
    const body = req.body || {};

    // 1) Zoom URL validation
    if (body?.event === "endpoint.url_validation") {
      const plainToken = body?.payload?.plainToken || "";
      const encryptedToken = crypto.createHmac("sha256", ZOOM_SECRET).update(plainToken).digest("hex");
      return res.json({ plainToken, encryptedToken });
    }

    // 2) Verify Zoom signature
    const ts = req.get("x-zm-request-timestamp") || "";
    const sig = req.get("x-zm-signature") || "";
    const base = `v0:${ts}:${req.rawBody || ""}`;
    const expected = `v0=${crypto.createHmac("sha256", ZOOM_SECRET).update(base).digest("hex")}`;
    if (!sig || sig !== expected) return res.status(401).send("Invalid signature");

    // 3) Forward full JSON to Zapier
    if (ZAPIER_HOOK_URL) {
      const resp = await fetch(ZAPIER_HOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const text = await resp.text();
      console.log("Posting to:", ZAPIER_HOOK_URL);
      console.log("Zapier response:", resp.status, text);
    } else {
      console.log("No ZAPIER_HOOK_URL set; skipping forward.");
    }

    res.status(200).send("OK");
  } catch (e) {
    console.error("Handler error:", e);
    res.status(500).send("Server error");
  }
});

app.listen(PORT, () => console.log(`Zoom webhook listening on ${PORT}`));
