
const config = require("./config.json")

const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = Number(config.PORT || 8888);
const REDIRECT_URI =
  config.SPOTIFY_REDIRECT_URI ||
  "http://127.0.0.1:8888/callback";

const CLIENT_ID = config.SPOTIFY_CLIENT_ID;
const CLIENT_SECRET = config.SPOTIFY_CLIENT_SECRET;

if (!CLIENT_ID || !CLIENT_SECRET || !config.SESSION_SECRET) {
  throw new Error("Check SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET, and SESSION_SECRET in config.json");
}
if (REDIRECT_URI !== "http://127.0.0.1:8888/callback") {
  throw new Error("This local setup expects the registered 127.0.0.1 callback.");
}

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false }));

app.use(session({
  name: "spotify.sid",
 secret: config.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
    maxAge: 12 * 60 * 60 * 1000
  }
}));

app.use("/api", rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false
}));

app.use(express.static(path.join(__dirname, "public")));

const scopes = [
  "user-read-private",
  "user-read-playback-state",
  "user-read-currently-playing",
  "user-modify-playback-state",
  "playlist-read-private",
  "playlist-read-collaborative",
  "user-library-read"
].join(" ");

const pairingCodes = new Map();

function randomString(bytes = 32) {
  return crypto.randomBytes(bytes).toString("hex");
}

function cleanPairingCodes() {
  const now = Date.now();
  for (const [code, item] of pairingCodes) {
    if (item.expires < now) pairingCodes.delete(code);
  }
}

async function tokenRequest(params) {
  const basic = Buffer.from(
    `${CLIENT_ID}:${CLIENT_SECRET}`
  ).toString("base64");

  const response = await fetch(
    "https://accounts.spotify.com/api/token",
    {
      method: "POST",
      headers: {
        Authorization: `Basic ${basic}`,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams(params)
    }
  );

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error_description || data.error || "Spotify token request failed");
  }
  return data;
}

async function getAccessToken(req) {
  const auth = req.session.spotify;
  if (!auth) throw new Error("Please log in with Spotify first.");

  if (auth.expiresAt > Date.now() + 60_000) {
    return auth.accessToken;
  }

  if (!auth.refreshToken) {
    delete req.session.spotify;
    throw new Error("Your login expired. Please sign in again.");
  }

  const refreshed = await tokenRequest({
    grant_type: "refresh_token",
    refresh_token: auth.refreshToken
  });

  auth.accessToken = refreshed.access_token;
  auth.expiresAt = Date.now() + refreshed.expires_in * 1000;

  if (refreshed.refresh_token) {
    auth.refreshToken = refreshed.refresh_token;
  }

  return auth.accessToken;
}

async function spotify(req, endpoint, options = {}) {
  let token = await getAccessToken(req);

  async function send(accessToken) {
    const response = await fetch(
      `https://api.spotify.com/v1${endpoint}`,
      {
        method: options.method || "GET",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          ...(options.body ? { "Content-Type": "application/json" } : {})
        },
        ...(options.body ? { body: JSON.stringify(options.body) } : {})
      }
    );

    if (response.status === 204 || response.status === 202) {
      return { ok: true };
    }

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(
        data.error?.message || data.error_description ||
        `Spotify API returned ${response.status}`
      );
      error.status = response.status;
      error.spotifyStatus = response.status;
      throw error;
    }

    return data;
  }

  try {
    return await send(token);
  } catch (error) {
    if (error.spotifyStatus !== 401) throw error;

    // Refresh once if Spotify rejected the access token.
    const auth = req.session.spotify;
    auth.expiresAt = 0;
    token = await getAccessToken(req);
    return send(token);
  }
}

function requireLogin(req, res, next) {
  if (!req.session.spotify) {
    return res.status(401).json({ error: "Log in with Spotify first." });
  }
  next();
}

app.get("/login", (req, res) => {
  const state = randomString();
  req.session.oauthState = state;

  const url = new URL("https://accounts.spotify.com/authorize");
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: scopes,
    state
  }).toString();

  res.redirect(url.toString());
});

app.get("/callback", async (req, res) => {
  const { code, state, error } = req.query;

  if (error) return res.status(400).send("Spotify login was declined.");
  if (!code || !state || state !== req.session.oauthState) {
    return res.status(400).send("Invalid login state. Please try logging in again.");
  }

  delete req.session.oauthState;

  try {
    const tokens = await tokenRequest({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI
    });

    req.session.spotify = {
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt: Date.now() + tokens.expires_in * 1000
    };

    req.session.save(err => {
      if (err) return res.status(500).send("Could not save login session.");
      res.redirect("/");
    });
  } catch (err) {
    console.error("OAuth error:", err.message);
    res.status(502).send("Spotify login failed. Check your app credentials and redirect URI.");
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("spotify.sid");
    res.json({ ok: true });
  });
});

// Pair a second browser with the already-authorized Chromebook session.
// Pairing codes are one-use and expire after three minutes.
app.post("/api/pair-code", requireLogin, (req, res) => {
  cleanPairingCodes();

  const code = String(crypto.randomInt(100000, 1000000));
  pairingCodes.set(code, {
    auth: { ...req.session.spotify },
    expires: Date.now() + 3 * 60 * 1000
  });

  res.json({ code, expiresInSeconds: 180 });
});

app.post("/api/pair", (req, res) => {
  cleanPairingCodes();

  const code = String(req.body.code || "").trim();
  const entry = pairingCodes.get(code);

  if (!entry) {
    return res.status(400).json({
      error: "Invalid or expired pairing code. Generate a new one on the Chromebook."
    });
  }

  pairingCodes.delete(code);
  req.session.spotify = { ...entry.auth };

  req.session.save(err => {
    if (err) return res.status(500).json({ error: "Could not pair this browser." });
    res.json({ ok: true });
  });
});

app.get("/api/status", requireLogin, async (req, res) => {
  try {
    const [me, player] = await Promise.all([
      spotify(req, "/me"),
      spotify(req, "/me/player").catch(err => {
        if (err.spotifyStatus === 204 || err.spotifyStatus === 404) return null;
        throw err;
      })
    ]);

    res.json({
      loggedIn: true,
      user: me.display_name || me.id,
      player
    });
  } catch (err) {
    res.status(err.status || 502).json({ error: err.message });
  }
});

app.get("/api/playlists", requireLogin, async (req, res) => {
  try {
    const data = await spotify(req, "/me/playlists?limit=50");
    res.json(data.items || []);
  } catch (err) {
    res.status(err.status || 502).json({ error: err.message });
  }
});

app.get("/api/liked", requireLogin, async (req, res) => {
  try {
    const data = await spotify(req, "/me/tracks?limit=50");
    res.json((data.items || []).map(item => item.track).filter(Boolean));
  } catch (err) {
    res.status(err.status || 502).json({ error: err.message });
  }
});

app.get("/api/player", requireLogin, async (req, res) => {
  try {
    const data = await spotify(req, "/me/player");
    res.json(data || null);
  } catch (err) {
    if (err.spotifyStatus === 204 || err.spotifyStatus === 404) {
      return res.json(null);
    }
    res.status(err.status || 502).json({ error: err.message });
  }
});

app.post("/api/seek", requireLogin, async (req, res) => {
  try {
    const positionMs = Number(req.body.position_ms);

    if (!Number.isFinite(positionMs) || positionMs < 0) {
      return res.status(400).json({
        error: "Invalid song position."
      });
    }

    await spotify(
      req,
      `/me/player/seek?position_ms=${Math.floor(positionMs)}`,
      { method: "PUT" }
    );

    res.json({ success: true });
  } catch (err) {
    res.status(err.status || err.spotifyStatus || 502).json({
      error: err.message
    });
  }
});

app.post("/api/control", requireLogin, async (req, res) => {
  const { action, value, uri } = req.body || {};

  const commands = {
    play: ["PUT", "/me/player/play"],
    pause: ["PUT", "/me/player/pause"],
    next: ["POST", "/me/player/next"],
    previous: ["POST", "/me/player/previous"]
  };

  try {
    if (action === "volume") {
      const volume = Number(value);

      if (!Number.isInteger(volume) || volume < 0 || volume > 100) {
        return res.status(400).json({
          error: "Volume must be from 0 to 100."
        });
      }

      await spotify(req, `/me/player/volume?volume_percent=${volume}`, {
        method: "PUT"
      });

    } else if (action === "shuffle") {
      if (typeof value !== "boolean") {
        return res.status(400).json({
          error: "Shuffle must be true or false."
        });
      }

      await spotify(req, `/me/player/shuffle?state=${value}`, {
        method: "PUT"
      });

    } else if (action === "track") {
      if (typeof uri !== "string" ||
          !/^spotify:track:[A-Za-z0-9]+$/.test(uri)) {
        return res.status(400).json({
          error: "Invalid Spotify track URI."
        });
      }

      await spotify(req, "/me/player/play", {
        method: "PUT",
        body: { uris: [uri] }
      });

    } else if (action === "repeat") {
      if (!["off", "context", "track"].includes(value)) {
        return res.status(400).json({
          error: "Invalid repeat mode."
        });
      }

      await spotify(req, `/me/player/repeat?state=${value}`, {
        method: "PUT"
      });

    } else if (action === "playlist") {
      if (typeof uri !== "string" ||
          !/^spotify:playlist:[A-Za-z0-9]+$/.test(uri)) {
        return res.status(400).json({
          error: "Invalid playlist URI."
        });
      }

      await spotify(req, "/me/player/play", {
        method: "PUT",
        body: { context_uri: uri }
      });

    } else if (commands[action]) {
      const [method, endpoint] = commands[action];
      await spotify(req, endpoint, { method });

    } else {
      return res.status(400).json({
        error: "Unknown control action."
      });
    }

    res.json({ ok: true });

  } catch (err) {
    res.status(err.status || 502).json({
      error: err.message,
      hint: err.spotifyStatus === 403
        ? "Check Spotify playback permissions and the active device."
        : err.spotifyStatus === 404 || err.spotifyStatus === 204
        ? "Check whether Spotify has an active playback device."
        : undefined
    });
  }
});

   app.use((req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Spotify Control Center running on port ${PORT}`);
  console.log("On this Chromebook, open http://127.0.0.1:" + PORT);
  console.log("Other devices on your Wi-Fi can use the Chromebook's LAN IP.");
  console.log("For safety, only use this on a trusted private network.");
});
