import express from "express";
import cors from "cors";
import Airtable from "airtable";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// ✅ Routes publiques (évite les 404/401 du navigateur)
app.get("/", (req, res) => {
  res.status(200).send("✅ EventManager Backend is running");
});

app.get("/favicon.ico", (req, res) => res.status(204).end());

// ✅ Connexion Airtable
const base = new Airtable({ apiKey: process.env.AIRTABLE_TOKEN }).base(
  process.env.AIRTABLE_BASE_ID
);

// ✅ Middleware auth (token + gestion expiration)
const verifyToken = (req, res, next) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "Token manquant" });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET); // vérifie signature + exp
    next();
  } catch (err) {
    if (err?.name === "TokenExpiredError") {
      return res.status(401).json({
        error: "Token expiré",
        expiredAt: err.expiredAt,
      });
    }
    return res.status(401).json({ error: "Token invalide" });
  }
};

/**
 * ✅ Sécurisation fine :
 * Un admin ne peut accéder qu'à SON ASBL.
 *
 * - Ton JWT contient :
 *   req.user.id     = record Airtable (rec...)
 *   req.user.asblId = id métier (ex: ASBL001)
 *
 * Règle :
 * - si tu demandes /api/asbl/:recId => le :recId DOIT être le même que req.user.id (admin)
 * - si tu demandes /api/asbl/by-code/:code => le record trouvé DOIT avoir fields.id === req.user.asblId
 */
const authorizeAdminAsblRecordId = (req, res, next) => {
  if (req.user?.type !== "admin") {
    return res.status(403).json({ error: "Accès réservé admin" });
  }
  if (req.params.id !== req.user.id) {
    return res.status(403).json({ error: "Accès interdit à une autre ASBL" });
  }
  next();
};

const authorizeAdminAsblByCode = (asblRecordFields, req, res) => {
  if (req.user?.type !== "admin") {
    return res.status(403).json({ error: "Accès réservé admin" });
  }
  if (asblRecordFields?.id !== req.user.asblId) {
    return res.status(403).json({ error: "Accès interdit à une autre ASBL" });
  }
  return null; // ok
};

// =====================
// ROUTES API
// =====================

app.post("/api/auth/login", async (req, res) => {
  const { code, type } = req.body;

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

    // ⚠️ IMPORTANT :
    // - admin : record.id = rec... de la table ASBL (parfait)
    // - admin : record.fields.id = "ASBL001" (id métier)
    // => on met les deux dans le JWT
    const token = jwt.sign(
      { id: record.id, type, asblId: record.fields.id },
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
    );

    res.json({ token, user: record.fields });
  } catch (error) {
    console.error("LOGIN ERROR:", error);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// ✅ Route protégée par record Airtable (rec...)
// -> verrouillée : un admin ne peut demander QUE son propre rec...
app.get("/api/asbl/:id", verifyToken, authorizeAdminAsblRecordId, async (req, res) => {
  try {
    const record = await base("ASBL").find(req.params.id);
    res.json(record.fields);
  } catch (error) {
    console.error("AIRTABLE /api/asbl/:id ERROR:", error);
    res.status(500).json({
      error: "Erreur Airtable",
      details: error?.message || String(error),
    });
  }
});

// ✅ Route protégée par "id métier" (ASBL001)
// -> verrouillée : on compare fields.id à req.user.asblId
app.get("/api/asbl/by-code/:code", verifyToken, async (req, res) => {
  try {
    const code = req.params.code;

    const records = await base("ASBL")
      .select({ filterByFormula: `{id} = '${code}'` })
      .firstPage();

    if (!records.length) {
      return res.status(404).json({ error: "ASBL introuvable" });
    }

    const record = records[0];

    const forbidden = authorizeAdminAsblByCode(record.fields, req, res);
    if (forbidden) return; // réponse déjà envoyée

    res.json(record.fields);
  } catch (error) {
    console.error("AIRTABLE /api/asbl/by-code ERROR:", error);
    res.status(500).json({
      error: "Erreur Airtable",
      details: error?.message || String(error),
    });
  }
});

// ✅ Health check public (sans token)
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", timestamp: new Date().toISOString() });
});

// Export pour Vercel
export default app;

// Test local uniquement
if (process.env.NODE_ENV !== "production") {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Serveur local: http://localhost:${PORT}`);
  });
}
