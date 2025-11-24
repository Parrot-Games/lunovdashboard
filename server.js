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
  .connect(process.env.MONGO_URI, {
    dbName: 'lunov'  // Force using lunov database
  })
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
    chatLevelChannel: { type: String, default: "" },
    leaveChannel: { type: String, default: "" },
    logChannel: { type: String, default: "" },
  },
});

const Guild = mongoose.model("Guild", GuildSchema);

app.use(
  session({
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      dbName: 'lunov',
      collectionName: "sessions",
      ttl: 60 * 60 * 24 * 7, // 7 days
    }),
    secret: process.env.SESSION_SECRET || "supersecretkey",
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      // only secure in production (https). Makes local development easier.
      secure: process.env.NODE_ENV === 'production',
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
app.get("/api/auth/logout", (req, res, next) => {
  // passport >=0.6 requires a callback
  req.logout(function(err) {
    if (err) return next(err);
    req.session.destroy(() => {
      // clear cookie with same name used by express-session
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

// total server counts 
app.get("/api/bot/stats", async (req, res) => {
  try {
    const r = await fetch("https://discord.com/api/v10/users/@me/guilds", {
      headers: { Authorization: `Bot ${process.env.BOT_TOKEN}` },
    });
    const botGuilds = await r.json();

    res.json({
      serverCount: Array.isArray(botGuilds) ? botGuilds.length : 0
    });
  } catch (err) {
    console.error("Stats error:", err);
    res.json({ serverCount: 0 });
  }
});

// helper to safely check MANAGE_GUILD permission using BigInt (handles string bitfields)
function hasManageGuildPermission(permValue) {
  try {
    const bits = typeof permValue === 'string' ? BigInt(permValue) : BigInt(permValue || 0);
    return (bits & 0x20n) === 0x20n;
  } catch (err) {
    return false;
  }
}

// Get mutual guilds
app.get("/api/guilds", async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Not logged in" });

  try {
    const userGuilds = req.user.guilds || [];
    const r = await fetch("https://discord.com/api/v10/users/@me/guilds", {
      headers: { Authorization: `Bot ${process.env.BOT_TOKEN}` },
    });
    const botGuilds = await r.json();

    if (!Array.isArray(botGuilds)) return res.status(500).json({ error: 'Failed to fetch bot guilds' });

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

    // Permission check: use BigInt safe checker
    const guild = req.user.guilds.find(
      (g) => g.id === guildId && hasManageGuildPermission(g.permissions)
    );
    if (!guild) return res.status(403).json({ error: "Missing permissions" });

    // Fetch channels from Discord API
    const r = await fetch(
      `https://discord.com/api/v10/guilds/${guildId}/channels`,
      {
        headers: {
          Authorization: `Bot ${process.env.BOT_TOKEN}`,
        },
      }
    );

    const channels = await r.json();

    res.json(channels);
  } catch (err) {
    console.error("Channels fetch error:", err);
    res.status(500).json({ error: "Failed to fetch channels" });
  }
});

// Helper function to get welcome channel from bot's database
async function getWelcomeChannelFromBot(guildId) {
  try {
    const db = mongoose.connection.db;
    const welcomeData = await db.collection("guild_settings").findOne(
      { _id: "welcome_channels" }
    );
    if (welcomeData && welcomeData.channels && welcomeData.channels[guildId]) {
      return welcomeData.channels[guildId];
    }
    return null;
  } catch (error) {
    console.error("Error getting welcome channel from bot database:", error);
    return null;
  }
}

// Helper function to get chatLevel channel from bot's database
async function getChatLevelChannelFromBot(guildId) {
  try {
    const db = mongoose.connection.db;
    const data = await db.collection("guild_settings").findOne(
      { _id: "chatLevel_channels" }
    );
    if (data && data.channels && data.channels[guildId]) return data.channels[guildId];
    return null;
  } catch (error) {
    console.error("Error getting chatLevel channel from bot database:", error);
    return null;
  }
}

// Helper function to get demon hunt channel from bot's database
async function getDemonHuntChannelFromBot(guildId) {
  try {
    const db = mongoose.connection.db;
    const data = await db.collection("guild_settings").findOne(
      { _id: "demon_hunt_channels" }
    );
    if (data && data.channels && data.channels[guildId]) return data.channels[guildId];
    return null;
  } catch (error) {
    console.error("Error getting demon hunt channel from bot database:", error);
    return null;
  }
}

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

    // Check permissions (0x20 = MANAGE_GUILD) using BigInt-safe helper
    const hasPermission = hasManageGuildPermission(userGuild.permissions);
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

    // GET EXISTING WELCOME CHANNEL FROM BOT'S DATABASE
    const botWelcomeChannel = await getWelcomeChannelFromBot(guildId);
    console.log(`Bot welcome channel for ${guildId}: ${botWelcomeChannel}`);

    // GET EXISTING CHATLEVEL CHANNEL FROM BOT'S DATABASE
    const botChatLevelChannel = await getChatLevelChannelFromBot(guildId);
    console.log(`Bot chatLevel channel for ${guildId}: ${botChatLevelChannel}`);

    // GET EXISTING DEMON HUNT CHANNEL FROM BOT'S DATABASE
    const botDemonHuntChannel = await getDemonHuntChannelFromBot(guildId);
    console.log(`Bot demon hunt channel for ${guildId}: ${botDemonHuntChannel}`);
    
    // If bot has a welcome channel but dashboard doesn't, update dashboard
    if (botWelcomeChannel && !record.settings.welcomeChannel) {
      console.log(`Syncing welcome channel from bot to dashboard: ${botWelcomeChannel}`);
      record.settings.welcomeChannel = String(botWelcomeChannel);
      await record.save();
    }

    // If bot has a chatLevel channel but dashboard doesn't, update dashboard
    if (botChatLevelChannel && !record.settings.chatLevelChannel) {
      console.log(`Syncing chatLevel channel from bot to dashboard: ${botChatLevelChannel}`);
      record.settings.chatLevelChannel = String(botChatLevelChannel);
      await record.save();
    }

    // If bot has a demon hunt channel but dashboard doesn't, update dashboard
    if (botDemonHuntChannel && !record.settings.demonHuntChannel) {
      console.log(`Syncing demon hunt channel from bot to dashboard: ${botDemonHuntChannel}`);
      record.settings.demonHuntChannel = String(botDemonHuntChannel);
      await record.save();
    }

    // Include bot welcome, chatLevel & demon hunt info in response
    const response = {
      ...record.toObject(),
      botWelcomeChannel: botWelcomeChannel,
      hasBotWelcomeChannel: !!botWelcomeChannel,
      botChatLevelChannel: botChatLevelChannel,
      hasBotChatLevelChannel: !!botChatLevelChannel,
      botDemonHuntChannel: botDemonHuntChannel,
      hasBotDemonHuntChannel: !!botDemonHuntChannel
    };

    console.log(`Returning guild data for ${guildId}:`, response);
    res.json(response);
  } catch (err) {
    console.error("Guild fetch error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Generic helper to safely convert input to BigInt string; returns null on invalid
function safeBigIntString(value) {
  if (value === undefined || value === null || value === '') return null;
  try {
    return BigInt(String(value)).toString();
  } catch (err) {
    return null;
  }
}

// Set Welcome Channel
app.post("/api/guild/:id/welcome-channel", async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });

  try {
    const guildId = req.params.id;
    let { welcomeChannel } = req.body;

    // Permission check
    const guild = req.user.guilds.find(
      (g) => g.id === guildId && hasManageGuildPermission(g.permissions)
    );
    if (!guild)
      return res.status(403).json({ error: "Missing MANAGE_GUILD permission" });

    // Safe conversion
    const safeId = safeBigIntString(welcomeChannel);
    if (welcomeChannel && !safeId) return res.status(400).json({ error: 'Invalid channel id' });

    welcomeChannel = safeId;

    console.log(`Saving welcome channel for guild ${guildId}: ${welcomeChannel} (type: ${typeof welcomeChannel})`);

    // Get the database connection
    const db = mongoose.connection.db;
    
    // Save exactly like bot does
    await db.collection("guild_settings").updateOne(
      { _id: "welcome_channels" },
      { 
        $set: { 
          [`channels.${guildId}`]: welcomeChannel 
        } 
      },
      { upsert: true }
    );

    // Also update dashboard (single source for dashboard view)
    const record = await Guild.findOne({ guildId });
    if (record) {
      record.settings.welcomeChannel = welcomeChannel || "";
      await record.save();
    }

    console.log(`✅ Welcome channel saved successfully!`);
    
    // Verify the data was saved
    const savedData = await db.collection("guild_settings").findOne(
      { _id: "welcome_channels" }
    );
    
    res.json({
      success: true,
      message: `Welcome channel set to ${welcomeChannel}`,
      guildId,
      welcomeChannel,
      dataType: typeof welcomeChannel,
      savedTo: "guild_settings collection",
      verified: savedData?.channels?.[guildId] === welcomeChannel
    });
  } catch (err) {
    console.error("Welcome channel save error:", err);
    res.status(500).json({ 
      error: "Failed to save welcome channel",
      details: err.message
    });
  }
});

// Set chatLevel Channel (fixed: safe BigInt, save to bot DB and dashboard schema)
app.post("/api/guild/:id/chatLevel-channel", async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });

  try {
    const guildId = req.params.id;
    let { chatLevelChannel } = req.body;

    // Permission check
    const guild = req.user.guilds.find(
      (g) => g.id === guildId && hasManageGuildPermission(g.permissions)
    );
    if (!guild)
      return res.status(403).json({ error: "Missing MANAGE_GUILD permission" });

    // Safe conversion
    const safeId = safeBigIntString(chatLevelChannel);
    if (chatLevelChannel && !safeId) return res.status(400).json({ error: 'Invalid channel id' });

    chatLevelChannel = safeId;

    console.log(`Saving chatLevel channel for guild ${guildId}: ${chatLevelChannel} (type: ${typeof chatLevelChannel})`);

    // Get the database connection
    const db = mongoose.connection.db;

    // Save in bot format (separate document)
    await db.collection("guild_settings").updateOne(
      { _id: "chatLevel_channels" },
      { 
        $set: { 
          [`channels.${guildId}`]: chatLevelChannel 
        } 
      },
      { upsert: true }
    );

    // Also update dashboard record
    const record = await Guild.findOne({ guildId });
    if (record) {
      record.settings.chatLevelChannel = chatLevelChannel || "";
      await record.save();
    }

    console.log(`✅ chatLevel channel saved successfully!`);

    // Verify the data was saved
    const savedData = await db.collection("guild_settings").findOne(
      { _id: "chatLevel_channels" }
    );

    res.json({
      success: true,
      message: `chatLevel channel set to ${chatLevelChannel}`,
      guildId,
      chatLevelChannel,
      dataType: typeof chatLevelChannel,
      savedTo: "guild_settings collection",
      verified: savedData?.channels?.[guildId] === chatLevelChannel
    });
  } catch (err) {
    console.error("chatLevel channel save error:", err);
    res.status(500).json({ 
      error: "Failed to save chatLevel channel",
      details: err.message
    });
  }
});

// Set Demon Hunt Channel
app.post("/api/guild/:id/demonhunt-channel", async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });

  try {
    const guildId = req.params.id;
    let { demonHuntChannel } = req.body;

    // Permission check
    const guild = req.user.guilds.find(
      (g) => g.id === guildId && hasManageGuildPermission(g.permissions)
    );
    if (!guild)
      return res.status(403).json({ error: "Missing MANAGE_GUILD permission" });

    // Safe conversion
    const safeId = safeBigIntString(demonHuntChannel);
    if (demonHuntChannel && !safeId) return res.status(400).json({ error: 'Invalid channel id' });

    demonHuntChannel = safeId;

    console.log(`Saving demon hunt channel for guild ${guildId}: ${demonHuntChannel} (type: ${typeof demonHuntChannel})`);

    // Get the database connection
    const db = mongoose.connection.db;

    // Save in bot format (separate document)
    await db.collection("guild_settings").updateOne(
      { _id: "demon_hunt_channels" },
      { 
        $set: { 
          [`channels.${guildId}`]: demonHuntChannel 
        } 
      },
      { upsert: true }
    );

    // Also update dashboard record
    const record = await Guild.findOne({ guildId });
    if (record) {
      record.settings.demonHuntChannel = demonHuntChannel || "";
      await record.save();
    }

    console.log(`✅ Demon Hunt channel saved successfully!`);

    // Verify the data was saved
    const savedData = await db.collection("guild_settings").findOne(
      { _id: "demon_hunt_channels" }
    );

    res.json({
      success: true,
      message: `Demon Hunt channel set to ${demonHuntChannel}`,
      guildId,
      demonHuntChannel,
      dataType: typeof demonHuntChannel,
      savedTo: "guild_settings collection",
      verified: savedData?.channels?.[guildId] === demonHuntChannel
    });
  } catch (err) {
    console.error("Demon Hunt channel save error:", err);
    res.status(500).json({ 
      error: "Failed to save demon hunt channel",
      details: err.message
    });
  }
});

// Debug endpoint to see all welcome channels
app.get("/api/debug/all-welcome-channels", async (req, res) => {
  try {
    const db = mongoose.connection.db;
    
    // Get bot welcome channels
    const botWelcomeData = await db.collection("guild_settings").findOne(
      { _id: "welcome_channels" }
    );
    
    // Get dashboard welcome channels
    const dashboardWelcomeData = await Guild.find({}).select("guildId name settings.welcomeChannel settings.chatLevelChannel");
    
    // Create comparison
    const comparison = {};
    
    if (botWelcomeData && botWelcomeData.channels) {
      for (const [guildId, channelId] of Object.entries(botWelcomeData.channels)) {
        const dashboardRecord = dashboardWelcomeData.find(g => g.guildId === guildId);
        comparison[guildId] = {
          guildId: guildId,
          bot_welcome_channel: channelId,
          dashboard_welcome_channel: dashboardRecord?.settings?.welcomeChannel || "Not set",
          match: dashboardRecord?.settings?.welcomeChannel === String(channelId)
        };
      }
    }
    
    res.json({
      bot_welcome_channels: botWelcomeData?.channels || {},
      dashboard_welcome_channels: dashboardWelcomeData.map(g => ({
        guildId: g.guildId,
        name: g.name,
        welcomeChannel: g.settings.welcomeChannel,
        chatLevelChannel: g.settings.chatLevelChannel
      })),
      comparison: comparison,
      summary: {
        total_bot_channels: botWelcomeData ? Object.keys(botWelcomeData.channels).length : 0,
        total_dashboard_channels: dashboardWelcomeData.filter(g => g.settings.welcomeChannel).length,
        matching_channels: Object.values(comparison).filter(c => c.match).length
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
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

// Serve static frontend (only for non-API routes)
app.use(express.static(path.join(__dirname, "public")));

// Fallback for React/SPA routing: exclude /api routes from this handler
app.get(/^\/(?!api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`✅ Lunov backend + frontend running on port ${PORT}`)
);
