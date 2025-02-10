require("dotenv").config();
const express = require("express");
const session = require("express-session");
const Sequelize = require("sequelize");
const SequelizeStore = require("connect-session-sequelize")(session.Store);
const cors = require("cors");
const msal = require("@azure/msal-node");
const crypto = require("crypto");

const app = express();

// Enable CORS with credentials
app.use(cors({
    origin: process.env.FRONTEND_URL || "http://localhost:5173",
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "Cookie"]  // Added Cookie to allowed headers
}));

app.use(express.json());

// Configure Session Store
const sequelize = new Sequelize({
    dialect: "sqlite",
    storage: "./session.sqlite",
    logging: false // Reduce console noise
});

const sessionStore = new SequelizeStore({
    db: sequelize,
    expiration: 24 * 60 * 60 * 1000, // 24 hours
    checkExpirationInterval: 15 * 60 * 1000 // Clean up expired sessions every 15 minutes
});

// Configure Session Middleware
const sessionMiddleware = session({
    secret: process.env.SESSION_SECRET || "supersecretkey", // Better to use environment variable
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    name: 'sessionId', // Explicit cookie name
    cookie: {
        secure: process.env.NODE_ENV === "production",
        httpOnly: true,
        sameSite: 'lax', // Changed from 'none' to 'lax' for better compatibility
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
});

app.use(sessionMiddleware);

// Ensure session store is synced
sessionStore.sync();

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

        // Save state to verify later
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
            state: state // Include state parameter
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

        // Verify state parameter
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
        
        // Clear sensitive session data
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