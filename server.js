import express from 'express';
import cors from 'cors';
import Airtable from 'airtable';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

/* ------------------------------------------------------------------ */
/* Public routes                                                      */
/* ------------------------------------------------------------------ */
app.get('/', (req, res) => res.status(200).send('✅ EventManager Backend is running'));
app.get('/favicon.ico', (req, res) => res.status(204).end());

app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

/* ------------------------------------------------------------------ */
/* Airtable init                                                      */
/* ------------------------------------------------------------------ */
if (!process.env.AIRTABLE_TOKEN) console.warn('⚠️ AIRTABLE_TOKEN missing');
if (!process.env.AIRTABLE_BASE_ID) console.warn('⚠️ AIRTABLE_BASE_ID missing');
if (!process.env.JWT_SECRET) console.warn('⚠️ JWT_SECRET missing');
if (!process.env.SUPERADMIN_PASSWORD) console.warn('⚠️ SUPERADMIN_PASSWORD missing');

const base = new Airtable({ apiKey: process.env.AIRTABLE_TOKEN }).base(process.env.AIRTABLE_BASE_ID);

/* ------------------------------------------------------------------ */
/* Auth middleware                                                    */
/* ------------------------------------------------------------------ */
const verifyToken = (req, res, next) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Token manquant' });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    if (err?.name === 'TokenExpiredError') return res.status(401).json({ error: 'Token expiré' });
    return res.status(401).json({ error: 'Token invalide' });
  }
};

const requireRole = (roles) => (req, res, next) => {
  const t = req.user?.type;
  if (!t || !roles.includes(t)) {
    return res.status(403).json({ error: `Accès refusé (${roles.join(' / ')} uniquement)` });
  }
  next();
};

/* ------------------------------------------------------------------ */
/* Helpers Airtable                                                   */
/* ------------------------------------------------------------------ */
function nowISO() {
  return new Date().toISOString().slice(0, 10);
}

async function findAsblByBusinessId(asblCode) {
  const records = await base('ASBL')
    .select({ filterByFormula: `{id} = '${asblCode}'`, maxRecords: 1 })
    .firstPage();

  return records?.[0] || null;
}

async function getAsblCodeFromBenevoleRecord(benevoleRecord) {
  const f = benevoleRecord.fields || {};

  // 1) Cas simple : champ texte "asblId"
  if (typeof f.asblId === 'string' && f.asblId.trim()) return f.asblId.trim();

  // 2) Cas : champ texte "asblCode"
  if (typeof f.asblCode === 'string' && f.asblCode.trim()) return f.asblCode.trim();

  // 3) Cas linked record : champ "asbl" (array de recordIds)
  // (tu peux aussi avoir "ASBL" selon comment tu l'as nommé)
  const linked = Array.isArray(f.asbl) ? f.asbl : Array.isArray(f.ASBL) ? f.ASBL : null;
  const asblRecordId = linked?.[0];
  if (!asblRecordId) return null;

  const asblRecord = await base('ASBL').find(asblRecordId);
  const code = asblRecord?.fields?.id;
  return typeof code === 'string' && code.trim() ? code.trim() : null;
}

function canAccessAsbl(asblCode, req) {
  // superadmin : accès total
  if (req.user?.type === 'superadmin') return true;

  // admin/benevole : uniquement leur ASBL
  return req.user?.asblId === asblCode;
}

/* ------------------------------------------------------------------ */
/* AUTH ROUTES                                                        */
/* ------------------------------------------------------------------ */

// ✅ Superadmin login -> JWT type=superadmin
app.post('/api/superadmin/login', async (req, res) => {
  const { password } = req.body || {};
  if (!process.env.SUPERADMIN_PASSWORD) {
    return res.status(500).json({ error: 'SUPERADMIN_PASSWORD manquant (Vercel env)' });
  }
  if (password !== process.env.SUPERADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Mot de passe superadmin incorrect' });
  }

  const token = jwt.sign({ type: 'superadmin' }, process.env.JWT_SECRET, { expiresIn: '8h' });
  res.json({ token });
});

// Login admin / benevole
app.post('/api/auth/login', async (req, res) => {
  const { code, type } = req.body || {};

  if (!code || !type) return res.status(400).json({ error: 'code et type requis' });
  if (!['admin', 'benevole'].includes(type)) return res.status(400).json({ error: 'type invalide' });

  try {
    const table = type === 'admin' ? 'ASBL' : 'Benevoles';
    const codeField = type === 'admin' ? 'codeAdmin' : 'codeAcces';

    const records = await base(table)
      .select({ filterByFormula: `{${codeField}} = '${code}'`, maxRecords: 1 })
      .firstPage();

    if (!records.length) return res.status(401).json({ error: 'Code invalide' });

    const record = records[0];

    let asblId = null;

    if (type === 'admin') {
      // admin record = ASBL record
      asblId = record.fields?.id || null;
      if (!asblId) return res.status(500).json({ error: "Champ ASBL 'id' manquant dans Airtable" });
    } else {
      // benevole record = Benevoles record
      asblId = await getAsblCodeFromBenevoleRecord(record);
      if (!asblId) {
        return res.status(500).json({
          error: "Bénévole sans ASBL liée (ajoute 'asblId' texte ou 'asbl' linked-record)",
        });
      }
    }

    // ✅ token standardisé
    // id = recordId Airtable (rec...)
    // asblId = code métier "ASBL001"
    const token = jwt.sign({ id: record.id, type, asblId }, process.env.JWT_SECRET, { expiresIn: '8h' });

    res.json({ token, user: record.fields });
  } catch (error) {
    console.error('LOGIN ERROR:', error);
    res.status(500).json({ error: 'Erreur serveur', details: error?.message || String(error) });
  }
});

/* ------------------------------------------------------------------ */
/* ✅ AJOUTS IMPORTANT : /api/auth/me + /api/benevoles/me              */
/* ------------------------------------------------------------------ */

// ✅ Permet au front de vérifier le token (corrige ton 404 /api/auth/me)
app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    res.json({ user: req.user });
  } catch (e) {
    res.status(500).json({ error: 'Erreur /api/auth/me' });
  }
});

// ✅ Infos du bénévole connecté (évite que le front appelle une route admin-only)
app.get('/api/benevoles/me', verifyToken, requireRole(['benevole']), async (req, res) => {
  try {
    const record = await base('Benevoles').find(req.user.id); // req.user.id = recordId Airtable
    res.json({ recordId: record.id, ...record.fields });
  } catch (e) {
    res.status(500).json({ error: 'Erreur /api/benevoles/me', details: e?.message || String(e) });
  }
});

/* ------------------------------------------------------------------ */
/* ASBL ROUTES                                                        */
/* ------------------------------------------------------------------ */

// ✅ Liste des ASBL (superadmin)
app.get('/api/asbl', verifyToken, requireRole(['superadmin']), async (req, res) => {
  try {
    const records = await base('ASBL').select({ maxRecords: 500 }).firstPage();
    const list = records.map((r) => ({ recordId: r.id, ...r.fields }));
    res.json(list);
  } catch (error) {
    console.error('GET /api/asbl ERROR:', error);
    res.status(500).json({ error: 'Erreur Airtable', details: error?.message || String(error) });
  }
});

// ✅ Créer ASBL (superadmin) -> écrit dans Airtable
app.post('/api/asbl', verifyToken, requireRole(['superadmin']), async (req, res) => {
  try {
    const { id, nom, email, telephone, adminNom, adminPrenom, adminEmail, codeAdmin, actif, dateCreation } = req.body || {};

    if (!id || !nom || !email || !codeAdmin) {
      return res.status(400).json({ error: "Champs requis: id, nom, email, codeAdmin" });
    }

    // Vérifie unicité id métier (ASBL001)
    const existing = await findAsblByBusinessId(id);
    if (existing) return res.status(409).json({ error: `ASBL ${id} existe déjà` });

    const created = await base('ASBL').create([
      {
        fields: {
          id,
          nom,
          email,
          telephone: telephone || '',
          adminNom: adminNom || '',
          adminPrenom: adminPrenom || '',
          adminEmail: adminEmail || '',
          codeAdmin,
          actif: typeof actif === 'boolean' ? actif : true,
          dateCreation: dateCreation || nowISO(),
        },
      },
    ]);

    res.json({ recordId: created[0].id, ...created[0].fields });
  } catch (error) {
    console.error('POST /api/asbl ERROR:', error);
    res.status(500).json({ error: 'Erreur Airtable', details: error?.message || String(error) });
  }
});

// 🔒 Lire une ASBL par recordId Airtable (admin/superadmin)
app.get('/api/asbl/:recordId', verifyToken, requireRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const record = await base('ASBL').find(req.params.recordId);

    // admin ne peut lire que son recordId (option stricte)
    if (req.user.type === 'admin' && req.user.id !== req.params.recordId) {
      return res.status(403).json({ error: 'Accès refusé (ASBL non autorisée)' });
    }

    res.json({ recordId: record.id, ...record.fields });
  } catch (error) {
    console.error('GET /api/asbl/:recordId ERROR:', error);
    res.status(500).json({ error: 'Erreur Airtable', details: error?.message || String(error) });
  }
});

// 🔒 Lire ASBL par code métier "ASBL001" (admin/benevole/superadmin)
app.get('/api/asbl/by-code/:code', verifyToken, requireRole(['admin', 'benevole', 'superadmin']), async (req, res) => {
  try {
    const code = req.params.code;
    if (!canAccessAsbl(code, req)) {
      return res.status(403).json({ error: 'Accès refusé (ASBL non autorisée)' });
    }

    const record = await findAsblByBusinessId(code);
    if (!record) return res.status(404).json({ error: 'ASBL introuvable' });

    res.json({ recordId: record.id, ...record.fields });
  } catch (error) {
    console.error('GET /api/asbl/by-code ERROR:', error);
    res.status(500).json({ error: 'Erreur Airtable', details: error?.message || String(error) });
  }
});

/* ------------------------------------------------------------------ */
/* BENEVOLES ROUTES                                                   */
/* ------------------------------------------------------------------ */

// ✅ Lister benevoles d'une ASBL (admin/superadmin)
app.get('/api/benevoles/by-asbl/:asblCode', verifyToken, requireRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const asblCode = req.params.asblCode;

    if (req.user.type === 'admin' && req.user.asblId !== asblCode) {
      return res.status(403).json({ error: 'Accès refusé (ASBL non autorisée)' });
    }

    const records = await base('Benevoles')
      .select({ filterByFormula: `{asblId} = '${asblCode}'`, maxRecords: 500 })
      .firstPage();

    const list = records.map((r) => ({ recordId: r.id, ...r.fields }));
    res.json(list);
  } catch (error) {
    console.error('GET /api/benevoles/by-asbl ERROR:', error);
    res.status(500).json({ error: 'Erreur Airtable', details: error?.message || String(error) });
  }
});

// ✅ Créer un bénévole (admin/superadmin) -> écrit dans Airtable
app.post('/api/benevoles', verifyToken, requireRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const { nom, prenom, telephone, email, codeAcces, role, tablesGerees, asblId } = req.body || {};

    if (!nom || !codeAcces) {
      return res.status(400).json({ error: "Champs requis: nom, codeAcces" });
    }

    const finalAsblId = req.user.type === 'admin' ? req.user.asblId : asblId;

    if (!finalAsblId) {
      return res.status(400).json({ error: "asblId requis pour créer un bénévole (superadmin)" });
    }

    const asblRecord = await findAsblByBusinessId(finalAsblId);
    if (!asblRecord) return res.status(404).json({ error: `ASBL ${finalAsblId} introuvable` });

    const existing = await base('Benevoles')
      .select({ filterByFormula: `{codeAcces} = '${codeAcces}'`, maxRecords: 1 })
      .firstPage();
    if (existing.length) return res.status(409).json({ error: 'codeAcces déjà utilisé' });

    const created = await base('Benevoles').create([
      {
        fields: {
          nom,
          prenom: prenom || '',
          telephone: telephone || '',
          email: email || '',
          codeAcces,
          role: role || 'both',
          tablesGerees: Array.isArray(tablesGerees) ? tablesGerees : [],
          asblId: finalAsblId,
          // Si tu veux aussi remplir un champ linked-record 'asbl' :
          // asbl: [asblRecord.id],
        },
      },
    ]);

    res.json({ recordId: created[0].id, ...created[0].fields });
  } catch (error) {
    console.error('POST /api/benevoles ERROR:', error);
    res.status(500).json({ error: 'Erreur Airtable', details: error?.message || String(error) });
  }
});

/* ------------------------------------------------------------------ */
/* ✅ AJOUT : Réservations (admin/superadmin)                          */
/* ------------------------------------------------------------------ */

app.get('/api/reservations/by-asbl/:asblCode', verifyToken, requireRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const asblCode = req.params.asblCode;

    if (req.user.type === 'admin' && req.user.asblId !== asblCode) {
      return res.status(403).json({ error: 'Accès refusé (ASBL non autorisée)' });
    }

    const records = await base('Reservations')
      .select({ filterByFormula: `{asblId} = '${asblCode}'`, maxRecords: 500 })
      .firstPage();

    res.json(records.map((r) => ({ recordId: r.id, ...r.fields })));
  } catch (e) {
    console.error('GET /api/reservations/by-asbl ERROR:', e);
    res.status(500).json({ error: 'Erreur réservations', details: e?.message || String(e) });
  }
});

/* ------------------------------------------------------------------ */
/* Export for Vercel                                                  */
/* ------------------------------------------------------------------ */
export default app;

/* Local test only */
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Serveur local: http://localhost:${PORT}`));
}
