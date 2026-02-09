import express from 'express';
import cors from 'cors';
import Airtable from 'airtable';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// ✅ Routes publiques (évite les 404/401 du navigateur)
app.get('/', (req, res) => {
  res.status(200).send('✅ EventManager Backend is running');
});
app.get('/favicon.ico', (req, res) => res.status(204).end());

// Connexion Airtable
const base = new Airtable({ apiKey: process.env.AIRTABLE_TOKEN })
  .base(process.env.AIRTABLE_BASE_ID);

// Middleware auth (gère expiré vs invalide)
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token manquant' });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    if (err?.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expiré' });
    }
    return res.status(401).json({ error: 'Token invalide' });
  }
};

// ✅ Sécurisation fine: l'admin ne peut accéder qu'à SON ASBL
const requireSameAsbl = (req, res, asblCodeRequested) => {
  // Ici: route réservée aux admins. (Tu pourras étendre aux bénévoles plus tard)
  if (req.user?.type !== 'admin') {
    res.status(403).json({ error: 'Accès interdit (admin uniquement)' });
    return true;
  }

  if (req.user.asblId !== asblCodeRequested) {
    res.status(403).json({ error: 'Accès interdit (ASBL mismatch)' });
    return true;
  }

  return false;
};

// Routes API
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

    // IMPORTANT :
    // - record.id = Airtable Record ID (rec...)
    // - record.fields.id = ton code ASBL (ex: ASBL001)
    const token = jwt.sign(
      { id: record.id, type, asblId: record.fields.id },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({ token, user: record.fields });
  } catch (error) {
    console.error('LOGIN ERROR:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Route protégée: fetch ASBL par Airtable Record ID (rec...)
app.get('/api/asbl/:id', verifyToken, async (req, res) => {
  try {
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

// ✅ Nouvelle route protégée: fetch ASBL par code (ASBL001)
// + sécurisation: l'admin ne peut demander que son propre code
app.get('/api/asbl/by-code/:code', verifyToken, async (req, res) => {
  try {
    const code = req.params.code;

    if (requireSameAsbl(req, res, code)) return;

    const records = await base('ASBL')
      .select({ filterByFormula: `{id} = '${code}'` })
      .firstPage();

    if (!records.length) {
      return res.status(404).json({ error: 'ASBL introuvable' });
    }

    res.json(records[0].fields);
  } catch (error) {
    console.error('AIRTABLE /api/asbl/by-code ERROR:', error);
    res.status(500).json({
      error: 'Erreur Airtable',
      details: error?.message || String(error),
    });
  }
});

// Health check public (sans token)
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
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
