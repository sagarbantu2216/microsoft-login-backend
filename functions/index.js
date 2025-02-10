const { onRequest } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");
const functions = require("firebase-functions"); // ✅ Ensure Firebase functions are loaded
const express = require("express");
const session = require("express-session");
const FirestoreStore = require("firestore-store")(session);
const cors = require("cors");
const msal = require("@azure/msal-node");
const crypto = require("crypto");

// Initialize Firebase Admin SDK
initializeApp();
const db = getFirestore();

const app = express();

// ✅ Ensure Firebase Config is read properly
const frontendUrl = functions.config().frontend?.url || "http://localhost:5173";
const sessionSecret = functions.config().session?.secret || "supersecretkey";

// Enable CORS for Firebase hosted frontend
app.use(cors({
  origin: [frontendUrl, "http://localhost:5173"], // Allow localhost for testing
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Cookie"],
}));

app.use(express.json());

// Configure Session Middleware using Firestore
const sessionMiddleware = session({
  secret: sessionSecret,
  store: new FirestoreStore({
    database: db,
    collection: "sessions",
  }),
  resave: false,
  saveUninitialized: false,
  name: "sessionId",
  cookie: {
    secure: process.env.NODE_ENV === "production", // Secure in production
    httpOnly: true,
    sameSite: "none",
    maxAge: 24 * 60 * 60 * 1000, // 1 day
    domain: ".web.app",
  },
});
app.use(sessionMiddleware);

// MSAL Configuration
const msalConfig = {
  auth: {
    clientId: functions.config().auth?.client_id,
    authority: `https://login.microsoftonline.com/${functions.config().auth?.tenant_id}`,
    clientSecret: functions.config().auth?.client_secret,
    redirectUri: frontendUrl + "/auth/callback",
  },
};
const msalClient = new msal.ConfidentialClientApplication(msalConfig);

// Login Route
app.get("/auth/login", async (req, res) => {
  try {
    const state = crypto.randomBytes(16).toString("hex");
    const nonce = crypto.randomBytes(16).toString("hex");

    req.session.state = state;
    req.session.nonce = nonce;

    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) reject(err);
        resolve();
      });
    });

    const authCodeUrlParameters = {
      scopes: ["User.Read", "profile", "email"],
      state: state,
      nonce: nonce,
      responseMode: "query",
      prompt: "select_account",
    };

    const url = await msalClient.getAuthCodeUrl(authCodeUrlParameters);
    res.json({ loginUrl: url });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      error: "Failed to generate login URL",
      details: error.message,
    });
  }
});

// Callback Route
app.get("/auth/callback", async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!req.session.state || req.session.state !== state) {
      throw new Error("State mismatch - possible CSRF attack");
    }

    const tokenRequest = {
      code: code,
      scopes: ["User.Read", "profile", "email"],
      redirectUri: frontendUrl + "/auth/callback",
    };

    const response = await msalClient.acquireTokenByCode(tokenRequest);

    delete req.session.state;
    delete req.session.nonce;

    req.session.userInfo = {
      username: response.account.username,
      name: response.account.name,
      id: response.account.homeAccountId,
    };

    await new Promise((resolve) => req.session.save(resolve));

    res.redirect(frontendUrl + "/auth-success");
  } catch (error) {
    console.error("Callback error:", error);
    res.redirect(`${frontendUrl}/auth-error?error=${encodeURIComponent(error.message)}`);
  }
});

// User Info Route
app.get("/auth/me", (req, res) => {
  if (req.session.userInfo) {
    res.json(req.session.userInfo);
  } else {
    res.status(401).json({ error: "Not authenticated" });
  }
});

// Logout Route
app.post("/auth/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      res.status(500).json({ error: "Failed to logout" });
    } else {
      res.json({ message: "Logged out successfully" });
    }
  });
});

// ✅ Deploy Firebase Cloud Function using v2 API
exports.auth = onRequest({ region: "us-central1", timeoutSeconds: 60 }, (req, res) => {
  app(req, res);
});
