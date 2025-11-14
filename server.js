import express from "express";
import session from "express-session";
import passport from "passport";
import { Strategy as DiscordStrategy } from "passport-discord";
import dotenv from "dotenv";
import fetch from "node-fetch";
import path from "path";
import { fileURLToPath } from "url";
import MongoStore from "connect-mongo";
import mongoose from "mongoose";
import cors from "cors";

// Setup
dotenv.config();
const app = express();
app.use(express.json());

// Path Setup
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Session setup
app.set("trust proxy", 1); // Required for Render (uses reverse proxy)

// MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// CORS middleware
app.use(cors({
  origin: true,
  credentials: true
}));

// Guild Schema
const GuildSchema = new mongoose.Schema({
  guildId: { type: String, required: true, unique: true },
  name: String,
  icon: String,
  settings: {
    prefix: { type: String, default: "!" },
    muteRole: { type: String, default: "" },
    welcomeChannel: { type: String, default: "" },
    leaveChannel: { type: String, default: "" },
    logChannel: { type: String, default: "" },
  },
});

const Guild = mongoose.model("Guild", GuildSchema);

app.use(
  session({
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      collectionName: "sessions",
      ttl: 60 * 60 * 24 * 7, // 7 days
    }),
    secret: process.env.SESSION_SECRET || "supersecretkey",
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      secure: true,
      httpOnly: true,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Passport config
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// Discord OAuth2 strategy
passport.use(
  new DiscordStrategy(
    {
      clientID: process.env.DISCORD_CLIENT_ID,
      clientSecret: process.env.DISCORD_CLIENT_SECRET,
      callbackURL: process.env.DISCORD_REDIRECT_URI,
      scope: ["identify", "guilds"],
    },
    (accessToken, refreshToken, profile, done) => {
      profile.accessToken = accessToken;
      return done(null, profile);
    }
  )
);

// ---------------- ROUTES ----------------

// Start Discord login
app.get("/api/auth/discord", passport.authenticate("discord"));

// Discord callback
app.get(
  "/api/auth/discord/callback",
  passport.authenticate("discord", { failureRedirect: "/" }),
  (req, res) => res.redirect("/account.html")
);

// Logout
app.get("/api/auth/logout", (req, res) => {
  req.logout(err => {
    if (err) return res.status(500).json({ error: "Failed to logout" });
    req.session.destroy(() => {
      res.clearCookie("connect.sid");
      res.json({ success: true });
    });
  });
});

// Get user info
app.get("/api/me", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Not logged in" });
  res.json(req.user);
});

// Get mutual guilds
app.get("/api/guilds", async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Not logged in" });

  try {
    const userGuilds = req.user.guilds;
    const botGuilds = await fetch("https://discord.com/api/v10/users/@me/guilds", {
      headers: { Authorization: `Bot ${process.env.BOT_TOKEN}` },
    }).then((r) => r.json());

    const mutualGuilds = userGuilds.filter((g) =>
      botGuilds.find((b) => b.id === g.id)
    );

    res.json(mutualGuilds);
  } catch (err) {
    console.error("Guild fetch error:", err);
    res.status(500).json({ error: "Failed to fetch guilds" });
  }
});

// Get guild channels
app.get("/api/discord/:guildId/channels", async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });

  try {
    const guildId = req.params.guildId;

    // Permission check
    const guild = req.user.guilds.find(
      (g) => g.id === guildId && (g.permissions & 0x20) // MANAGE_GUILD
    );
    if (!guild) return res.status(403).json({ error: "Missing permissions" });

    // Fetch channels from Discord API
    const channels = await fetch(
      `https://discord.com/api/v10/guilds/${guildId}/channels`,
      {
        headers: {
          Authorization: `Bot ${process.env.BOT_TOKEN}`,
        },
      }
    ).then((r) => r.json());

    res.json(channels);
  } catch (err) {
    console.error("Channels fetch error:", err);
    res.status(500).json({ error: "Failed to fetch channels" });
  }
});

// Get guild settings
app.get("/api/guild/:id", async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Not logged in" });

  try {
    const guildId = req.params.id;
    console.log(`Fetching guild ${guildId} for user ${req.user.id}`);

    // Check if user has MANAGE_GUILD permission in this guild
    const userGuild = req.user.guilds?.find(g => g.id === guildId);
    if (!userGuild) {
      return res.status(404).json({ error: "Guild not found in user's servers" });
    }

    // Check permissions (0x20 = MANAGE_GUILD)
    const hasPermission = (userGuild.permissions & 0x20) === 0x20;
    if (!hasPermission) {
      return res.status(403).json({ 
        error: "Missing MANAGE_GUILD permission",
        details: "You need the 'Manage Server' permission to configure bot settings"
      });
    }

    let record = await Guild.findOne({ guildId });
    if (!record) {
      console.log(`Creating new guild record for ${guildId}`);
      record = await Guild.create({
        guildId,
        name: userGuild.name,
        icon: userGuild.icon
      });
    }

    console.log(`Returning guild data for ${guildId}:`, record);
    res.json(record);
  } catch (err) {
    console.error("Guild fetch error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Update guild settings
app.post("/api/guild/:id", async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });

  try {
    const guildId = req.params.id;
    const { prefix, muteRole, welcomeChannel, leaveChannel, logChannel } =
      req.body;

    await Guild.findOneAndUpdate(
      { guildId },
      {
        $set: {
          "settings.prefix": prefix,
          "settings.muteRole": muteRole,
          "settings.welcomeChannel": welcomeChannel,
          "settings.leaveChannel": leaveChannel,
          "settings.logChannel": logChannel,
        },
      },
      { new: true, upsert: true }
    );

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update guild settings" });
  }
});

// Set Welcome Channel
app.post("/api/guild/:id/welcome-channel", async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });

  try {
    const guildId = req.params.id;
    const { welcomeChannel } = req.body;

    // Permission check
    const guild = req.user.guilds.find(
      (g) => g.id === guildId && (g.permissions & 0x20)
    );
    if (!guild)
      return res.status(403).json({ error: "Missing MANAGE_GUILD permission" });

    console.log(`Attempting to save welcome channel for guild ${guildId}: ${welcomeChannel}`);
    
    // Get the database connection - use the same database as your bot
    const db = mongoose.connection.db;
    console.log(`Using database: ${db.databaseName}`);
    
    // List all collections to debug
    const collections = await db.listCollections().toArray();
    console.log('Available collections:', collections.map(c => c.name));

    // Save exactly like bot does
    const result = await db.collection("guild_settings").updateOne(
      { _id: "welcome_channels" },
      { 
        $set: { 
          [`channels.${guildId}`]: welcomeChannel 
        } 
      },
      { upsert: true }
    );

    console.log(`✅ Welcome channel saved successfully!`);
    console.log(`MongoDB result:`, result);
    
    // Verify the data was saved
    const savedData = await db.collection("guild_settings").findOne(
      { _id: "welcome_channels" }
    );
    console.log(`Verified saved data:`, savedData);
    
    res.json({
      success: true,
      message: `Welcome channel set to ${welcomeChannel}`,
      guildId,
      welcomeChannel,
      savedTo: "guild_settings collection",
      database: db.databaseName,
      result: result
    });
  } catch (err) {
    console.error("Welcome channel save error:", err);
    res.status(500).json({ 
      error: "Failed to save welcome channel",
      details: err.message,
      stack: err.stack
    });
  }
});

// Debug endpoint to check welcome channels in bot format
app.get("/api/debug/mongodb-details", async (req, res) => {
  try {
    const db = mongoose.connection.db;
    
    // Get database info
    const adminDb = db.admin();
    const serverInfo = await adminDb.serverStatus();
    
    // List all databases
    const admin = mongoose.connection.getClient().db().admin();
    const databases = await admin.listDatabases();
    
    // Current database collections
    const collections = await db.listCollections().toArray();
    
    res.json({
      connected_database: db.databaseName,
      available_databases: databases.databases.map(d => d.name),
      collections_in_current_db: collections.map(c => c.name),
      server_version: serverInfo.version,
      connection_string: process.env.MONGO_URI ? process.env.MONGO_URI.substring(0, 50) + '...' : 'Not set'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Test endpoint to verify MongoDB connection
app.get("/api/debug/mongodb", async (req, res) => {
  try {
    const adminDb = mongoose.connection.db.admin();
    const pingResult = await adminDb.ping();
    
    const collections = await mongoose.connection.db.listCollections().toArray();
    const collectionNames = collections.map(c => c.name);
    
    res.json({
      mongodb: pingResult.ok === 1 ? "✅ Connected" : "❌ Disconnected",
      database: mongoose.connection.db.databaseName,
      collections: collectionNames,
      connectionState: mongoose.connection.readyState
    });
  } catch (error) {
    res.status(500).json({ 
      error: "MongoDB test failed",
      message: error.message,
      connectionState: mongoose.connection.readyState
    });
  }
});

// Serve static frontend
app.use(express.static(path.join(__dirname, "public")));

// Fallback for React/SPA routing
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`✅ Lunov backend + frontend running on port ${PORT}`)
);
