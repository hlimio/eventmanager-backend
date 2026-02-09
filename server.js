import express from 'express';
import cors from 'cors';
import Airtable from 'airtable';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// ✅ Routes publiques (évite 404/401 du navigateur)
app.get('/', (req, res) => {
  res.status(200).send('✅ EventManager Backend is running');
});
app.get('/favicon.ico', (req, res) => res.status(204).end());

// ✅ Health check public (sans token)
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Connexion Airtable
const base = new Airtable({ apiKey: process.env.AIRTABLE_TOKEN })
  .base(process.env.AIRTABLE_BASE_ID);

// Middleware auth (token)
const verifyToken = (req, res, next) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Token manquant' });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    // Token expiré => message clair
    if (err?.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expiré' });
    }
    return res.status(401).json({ error: 'Token invalide' });
  }
};

// --- Helpers sécurité ---
// Un admin ne peut accéder qu'à SON ASBL
function authorizeAdminAsblRecordId(requestedRecordId, req, res) {
  if (req.user?.type !== 'admin') {
    res.status(403).json({ error: "Accès refusé (admin uniquement)" });
    return true;
  }
  if (requestedRecordId !== req.user.id) {
    res.status(403).json({ error: "Accès refusé (ASBL non autorisée)" });
    return true;
  }
  return false;
}

function authorizeAdminAsblByCode(asblFields, req, res) {
  if (req.user?.type !== 'admin') {
    res.status(403).json({ error: "Accès refusé (admin uniquement)" });
    return true;
  }
  // asblFields.id = "ASBL001" dans ton Airtable
  if (asblFields?.id !== req.user.asblId) {
    res.status(403).json({ error: "Accès refusé (ASBL non autorisée)" });
    return true;
  }
  return false;
}

// --- Routes API ---
// Login
app.post('/api/auth/login', async (req, res) => {
  const { code, type } = req.body;

  try {
    const table = type === 'admin' ? 'ASBL' : 'Benevoles';
    const codeField = type === 'admin' ? 'codeAdmin' : 'codeAcces';

    const records = await base(table)
      .select({ filterByFormula: `{${codeField}} = '${code}'` })
      .firstPage();

    if (records.length === 0) {
      return res.status(401).json({ error: 'Code invalide' });
    }

    const record = records[0];

    // ✅ Payload :
    // - id = Airtable recordId (rec...)
    // - asblId = ton identifiant métier (ASBL001) (dans record.fields.id côté ASBL)
    const token = jwt.sign(
      { id: record.id, type, asblId: record.fields.id },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({ token, user: record.fields });
  } catch (error) {
    console.error('LOGIN ERROR:', error);
    res.status(500).json({
      error: 'Erreur serveur',
      details: error?.message || String(error),
    });
  }
});

// 🔒 Lire une ASBL par Airtable recordId (rec...)
app.get('/api/asbl/:id', verifyToken, async (req, res) => {
  try {
    const forbidden = authorizeAdminAsblRecordId(req.params.id, req, res);
    if (forbidden) return;

    const record = await base('ASBL').find(req.params.id);
    res.json(record.fields);
  } catch (error) {
    console.error('AIRTABLE /api/asbl/:id ERROR:', error);
    res.status(500).json({
      error: 'Erreur Airtable',
      details: error?.message || String(error),
    });
  }
});

// 🔒 Lire une ASBL par code "ASBL001" (champ {id} dans Airtable)
app.get('/api/asbl/by-code/:code', verifyToken, async (req, res) => {
  try {
    const code = req.params.code;

    const records = await base('ASBL')
      .select({ filterByFormula: `{id} = '${code}'` })
      .firstPage();

    if (!records.length) {
      return res.status(404).json({ error: 'ASBL introuvable' });
    }

    const record = records[0];

    const forbidden = authorizeAdminAsblByCode(record.fields, req, res);
    if (forbidden) return;

    res.json(record.fields);
  } catch (error) {
    console.error('AIRTABLE /api/asbl/by-code ERROR:', error);
    res.status(500).json({
      error: 'Erreur Airtable',
      details: error?.message || String(error),
    });
  }
});

// Export pour Vercel
export default app;

// Test local uniquement
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Serveur local: http://localhost:${PORT}`);
  });
}
