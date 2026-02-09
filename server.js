import express from "express";
import cors from "cors";
import Airtable from "airtable";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

/* =========================
   Routes publiques (évite 404/401 navigateur)
========================= */
app.get("/", (req, res) => {
  res.status(200).send("✅ EventManager Backend is running");
});
app.get("/favicon.ico", (req, res) => res.status(204).end());

// Health check PUBLIC (pas de token)
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", timestamp: new Date().toISOString() });
});

/* =========================
   Airtable init + checks
========================= */
function assertEnv(name) {
  if (!process.env[name]) {
    console.error(`❌ Missing env var: ${name}`);
    return false;
  }
  return true;
}

const hasAirtableEnv =
  assertEnv("AIRTABLE_TOKEN") && assertEnv("AIRTABLE_BASE_ID");
const hasJwtEnv = assertEnv("JWT_SECRET");

// Connexion Airtable
const base = hasAirtableEnv
  ? new Airtable({ apiKey: process.env.AIRTABLE_TOKEN }).base(
      process.env.AIRTABLE_BASE_ID
    )
  : null;

/* =========================
   Auth middleware
========================= */
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token manquant" });

  try {
    if (!hasJwtEnv) {
      return res.status(500).json({ error: "JWT_SECRET manquant côté serveur" });
    }
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Token invalide" });
  }
};

/* =========================
   Helper : rendre l'erreur Airtable lisible
========================= */
function formatAirtableError(error) {
  // airtable lib renvoie souvent error.statusCode + error.error + error.message
  return {
    message: error?.message || "Unknown Airtable error",
    statusCode: error?.statusCode,
    name: error?.name,
    // parfois: { error: { type, message } }
    airtable: error?.error,
  };
}

/* =========================
   Routes API
========================= */

// LOGIN (public)
app.post("/api/auth/login", async (req, res) => {
  const { code, type } = req.body || {};

  if (!base) {
    return res
      .status(500)
      .json({ error: "Airtable non configuré (env manquantes)" });
  }
  if (!hasJwtEnv) {
    return res.status(500).json({ error: "JWT_SECRET manquant côté serveur" });
  }
  if (!code || !type) {
    return res.status(400).json({ error: "code et type sont requis" });
  }

  try {
    const table = type === "admin" ? "ASBL" : "Benevoles";
    const codeField = type === "admin" ? "codeAdmin" : "codeAcces";

    const records = await base(table)
      .select({ filterByFormula: `{${codeField}} = '${code}'` })
      .firstPage();

    if (records.length === 0) {
      return res.status(401).json({ error: "Code invalide" });
    }

    const record = records[0];

    const token = jwt.sign(
      { id: record.id, type, asblId: record.fields.id }, // record.id = recXXXX
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
    );

    res.json({ token, user: record.fields });
  } catch (error) {
    console.error("❌ LOGIN ERROR:", formatAirtableError(error));
    res.status(500).json({
      error: "Erreur serveur",
      details: formatAirtableError(error),
    });
  }
});

// GET ASBL par record Airtable ID (protégé)
app.get("/api/asbl/:id", verifyToken, async (req, res) => {
  if (!base) {
    return res
      .status(500)
      .json({ error: "Airtable non configuré (env manquantes)" });
  }

  try {
    const record = await base("ASBL").find(req.params.id); // req.params.id doit être recXXXX
    res.json(record.fields);
  } catch (error) {
    console.error("❌ /api/asbl/:id ERROR:", formatAirtableError(error));
    res.status(500).json({
      error: "Erreur Airtable",
      details: formatAirtableError(error),
    });
  }
});

// ✅ GET ASBL par code interne (protégé) : /api/asbl/by-code/ASBL001
app.get("/api/asbl/by-code/:asblCode", verifyToken, async (req, res) => {
  if (!base) {
    return res
      .status(500)
      .json({ error: "Airtable non configuré (env manquantes)" });
  }

  const asblCode = req.params.asblCode;

  try {
    const records = await base("ASBL")
      .select({ filterByFormula: `{id} = '${asblCode}'` }) // champ "id" dans Airtable (ASBL001)
      .firstPage();

    if (!records.length) {
      return res.status(404).json({ error: "ASBL introuvable" });
    }

    res.json(records[0].fields);
  } catch (error) {
    console.error("❌ /api/asbl/by-code ERROR:", formatAirtableError(error));
    res.status(500).json({
      error: "Erreur Airtable",
      details: formatAirtableError(error),
    });
  }
});

/* =========================
   Export Vercel
========================= */
export default app;

/* =========================
   Local dev only
========================= */
if (process.env.NODE_ENV !== "production") {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Serveur local: http://localhost:${PORT}`);
  });
}
