require("dotenv").config();
const express = require("express");
const { RedisStore } = require("connect-redis");
const session = require("express-session");
const { createClient } = require("redis");
const cors = require("cors");
const msal = require("@azure/msal-node");
const crypto = require("crypto");

const app = express();

// Enable CORS with credentials
app.use(cors({
    origin: process.env.FRONTEND_URL || "http://localhost:5173",
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "Cookie"]
}));

app.use(express.json());

// Redis Connection
const redisClient = createClient({
    url: process.env.REDIS_URL,
    socket: {
        tls: false // Enable TLS if required by Redis Cloud
    }
});

redisClient.on("error", (err) => {
    console.error("❌ Redis connection error:", err);
});

redisClient.connect()
    .then(() => console.log("✅ Connected to Redis Cloud"))
    .catch(console.error);

// Configure Redis Session Store
const sessionStore = new RedisStore({
    client: redisClient,
    prefix: "myapp:", // Optional prefix for keys
});

// Configure Session Middleware
const sessionMiddleware = session({
    secret: process.env.SESSION_SECRET || "supersecretkey",
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    name: 'sessionId',
    cookie: {
        secure: process.env.NODE_ENV === "production",
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
});

app.use(sessionMiddleware);

// MSAL Configuration
const msalConfig = {
    auth: {
        clientId: process.env.CLIENT_ID,
        authority: `https://login.microsoftonline.com/${process.env.TENANT_ID}`,
        clientSecret: process.env.CLIENT_SECRET,
    }
};

const msalClient = new msal.ConfidentialClientApplication(msalConfig);

// Login Route
app.get("/auth/login", async (req, res) => {
    try {
        const codeVerifier = crypto.randomBytes(32).toString("hex");
        const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
        const state = crypto.randomBytes(16).toString("hex");
        
        req.session.codeVerifier = codeVerifier;
        req.session.state = state;
        
        await new Promise((resolve, reject) => {
            req.session.save((err) => {
                if (err) reject(err);
                resolve();
            });
        });

        const authCodeUrlParameters = {
            scopes: ["User.Read"],
            redirectUri: process.env.REDIRECT_URI,
            codeChallenge: codeChallenge,
            codeChallengeMethod: "S256",
            state: state
        };

        const url = await msalClient.getAuthCodeUrl(authCodeUrlParameters);
        res.json({ loginUrl: url });

    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: "Failed to generate login URL" });
    }
});

// Callback Route
app.get("/auth/callback", async (req, res) => {
    try {
        const { code, state } = req.query;

        if (!req.session.state || req.session.state !== state) {
            throw new Error("State mismatch - possible CSRF attack");
        }

        const codeVerifier = req.session.codeVerifier;
        if (!codeVerifier) {
            throw new Error("Code verifier not found in session");
        }

        const tokenRequest = {
            code: code,
            scopes: ["User.Read"],
            redirectUri: process.env.REDIRECT_URI,
            codeVerifier: codeVerifier
        };

        const response = await msalClient.acquireTokenByCode(tokenRequest);
        
        delete req.session.codeVerifier;
        delete req.session.state;
        
        await new Promise((resolve) => req.session.save(resolve));

        res.json({ 
            accessToken: response.accessToken,
            user: response.account
        });

    } catch (error) {
        console.error("Callback error:", error);
        res.status(500).json({ 
            error: "Authentication failed",
            details: error.message
        });
    }
});

// Health check endpoint
app.get("/health", (req, res) => {
    res.json({ status: "healthy" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});
