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
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });

  try {
    const guildId = req.params.id;

    const guild = req.user.guilds.find(
      (g) => g.id === guildId && (g.permissions & 0x20)
    );
    if (!guild)
      return res.status(403).json({ error: "Missing MANAGE_GUILD permission" });

    let record = await Guild.findOne({ guildId });
    if (!record) {
      record = await Guild.create({
        guildId,
        name: guild.name,
        icon: guild.icon
          ? `https://cdn.discordapp.com/icons/${guild.id}/${guild.icon}.png`
          : null,
      });
    }

    res.json(record);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch guild settings" });
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

    const updatedGuild = await Guild.findOneAndUpdate(
      { guildId },
      { $set: { "settings.welcomeChannel": welcomeChannel } },
      { new: true, upsert: true }
    );

    res.json({
      success: true,
      message: `Welcome channel updated to ${welcomeChannel}`,
      guild: updatedGuild,
    });
  } catch (err) {
    console.error("Welcome channel update error:", err);
    res.status(500).json({ error: "Failed to update welcome channel" });
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
