
import express from 'express';
import cors from 'cors';
import Airtable from 'airtable';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// ✅ Routes publiques (pour éviter les 404/401 du navigateur)
app.get('/', (req, res) => {
  res.status(200).send('✅ EventManager Backend is running');
});

app.get('/favicon.ico', (req, res) => res.status(204).end());

// Connexion Airtable
const base = new Airtable({ apiKey: process.env.AIRTABLE_TOKEN })
  .base(process.env.AIRTABLE_BASE_ID);

// Middleware auth
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token manquant' });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token invalide' });
  }
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

    const token = jwt.sign(
      { id: record.id, type, asblId: record.fields.id },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({ token, user: record.fields });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/asbl/:id', verifyToken, async (req, res) => {
  try {
    const record = await base('ASBL').find(req.params.id);
    res.json(record.fields);
  } catch (error) {
    res.status(500).json({ error: 'Erreur Airtable' });
  }
});

// Test route
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
