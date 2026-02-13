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
app.get('/favicon.png', (req, res) => res.status(204).end()); // ✅ évite le 404 dans les logs Vercel

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
  const linked = Array.isArray(f.asbl) ? f.asbl : Array.isArray(f.ASBL) ? f.ASBL : null;
  const asblRecordId = linked?.[0];
  if (!asblRecordId) return null;

  const asblRecord = await base('ASBL').find(asblRecordId);
  const code = asblRecord?.fields?.id;
  return typeof code === 'string' && code.trim() ? code.trim() : null;
}

function canAccessAsbl(asblCode, req) {
  if (req.user?.type === 'superadmin') return true;
  return req.user?.asblId === asblCode;
}

/**
 * ✅ Safe fetch: on récupère jusqu’à 500 records puis on filtre en JS.
 * Ça évite de planter si le champ Airtable change de nom.
 */
async function fetchAll(tableName, maxRecords = 500) {
  const records = await base(tableName).select({ maxRecords }).firstPage();
  return records.map((r) => ({ recordId: r.id, ...r.fields }));
}

/**
 * ✅ Détecte l’ASBL d’un record participant/réservation même si tes champs changent.
 * - essaie asblId (texte)
 * - essaie asblCode (texte)
 * - essaie lookup "id (from ASBL)" (dans tes screenshots)
 * - essaie linked "ASBL" (selon comment Airtable renvoie)
 */
function getAsblCodeFromRecordFields(fields = {}) {
  if (typeof fields.asblId === 'string' && fields.asblId.trim()) return fields.asblId.trim();
  if (typeof fields.asblCode === 'string' && fields.asblCode.trim()) return fields.asblCode.trim();

  const lookup = fields['id (from ASBL)'];
  if (typeof lookup === 'string' && lookup.trim()) return lookup.trim();
  if (Array.isArray(lookup) && typeof lookup[0] === 'string' && lookup[0].trim()) return lookup[0].trim();

  // parfois Airtable renvoie le nom affiché du linked record dans un array
  const linked = fields.ASBL;
  if (typeof linked === 'string' && linked.trim()) return linked.trim();
  if (Array.isArray(linked) && typeof linked[0] === 'string' && linked[0].trim()) return linked[0].trim();

  return null;
}

/* ------------------------------------------------------------------ */
/* ✅ AJOUT : création automatique des tables                          */
/* ------------------------------------------------------------------ */
/**
 * Crée les records dans Airtable table "Tables" à partir de:
 * - asblId (ex: ASBL001)
 * - maxParticipants (ex: 200)
 * - peoplePerTable (ex: 10)
 *
 * ⚠️ Ne casse rien : si maxParticipants / peoplePerTable manquants => ne fait rien.
 * ⚠️ Par défaut, on supprime les anciennes tables de l'ASBL avant de recréer (évite les doublons).
 *     Si tu veux garder l'historique, dis-le et je change ce comportement.
 */
async function createTablesForAsbl({ asblId, maxParticipants, peoplePerTable }) {
  const mp = Number(maxParticipants);
  const ppt = Number(peoplePerTable);

  if (!asblId || !mp || !ppt) {
    return { created: 0, reason: "maxParticipants/peoplePerTable manquants ou invalides" };
  }

  const nbTables = Math.ceil(mp / ppt);

  // Nettoyage des tables existantes pour cette ASBL (évite doublons)
  const existing = await base('Tables')
    .select({ filterByFormula: `{asblId} = '${asblId}'`, maxRecords: 500 })
    .firstPage();

  if (existing.length) {
    await base('Tables').destroy(existing.map((r) => r.id));
  }

  const payload = Array.from({ length: nbTables }, (_, i) => {
    const n = String(i + 1).padStart(3, '0');
    return {
      fields: {
        id: `T${n}`,       // T001, T002...
        asblId: asblId,    // ASBL001
        capacite: ppt,     // 8/10/12
        type: 'standard',  // optionnel
      },
    };
  });

  // Airtable: create par batch de 10
  let created = 0;
  for (let i = 0; i < payload.length; i += 10) {
    const batch = payload.slice(i, i + 10);
    const res = await base('Tables').create(batch);
    created += res.length;
  }

  return { created, nbTables };
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
      asblId = record.fields?.id || null;
      if (!asblId) return res.status(500).json({ error: "Champ ASBL 'id' manquant dans Airtable" });
    } else {
      asblId = await getAsblCodeFromBenevoleRecord(record);
      if (!asblId) {
        return res.status(500).json({
          error: "Bénévole sans ASBL liée (ajoute 'asblId' texte ou 'asbl' linked-record)",
        });
      }
    }

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

app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    res.json({ user: req.user });
  } catch (e) {
    res.status(500).json({ error: 'Erreur /api/auth/me' });
  }
});

app.get('/api/benevoles/me', verifyToken, requireRole(['benevole']), async (req, res) => {
  try {
    const record = await base('Benevoles').find(req.user.id);
    res.json({ recordId: record.id, ...record.fields });
  } catch (e) {
    res.status(500).json({ error: 'Erreur /api/benevoles/me', details: e?.message || String(e) });
  }
});

/* ------------------------------------------------------------------ */
/* ASBL ROUTES                                                        */
/* ------------------------------------------------------------------ */

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

app.post('/api/asbl', verifyToken, requireRole(['superadmin']), async (req, res) => {
  try {
    // ✅ AJOUT : maxParticipants + peoplePerTable (sans enlever le reste)
    const {
      id,
      nom,
      email,
      telephone,
      adminNom,
      adminPrenom,
      adminEmail,
      codeAdmin,
      actif,
      dateCreation,
      maxParticipants,
      peoplePerTable,
    } = req.body || {};

    if (!id || !nom || !email || !codeAdmin) {
      return res.status(400).json({ error: "Champs requis: id, nom, email, codeAdmin" });
    }

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

          // ✅ AJOUT : on stocke ces infos dans Airtable si la table ASBL a ces champs
          maxParticipants: Number(maxParticipants) || 0,
          peoplePerTable: Number(peoplePerTable) || 0,
        },
      },
    ]);

    // ✅ AJOUT : création automatique des tables dans Airtable "Tables"
    // (si maxParticipants/peoplePerTable sont fournis)
    try {
      await createTablesForAsbl({
        asblId: id,
        maxParticipants,
        peoplePerTable,
      });
    } catch (e) {
      // ⚠️ Ne bloque pas la création ASBL si la création des tables échoue
      console.error('CREATE TABLES AFTER ASBL ERROR:', e);
    }

    res.json({ recordId: created[0].id, ...created[0].fields });
  } catch (error) {
    console.error('POST /api/asbl ERROR:', error);
    res.status(500).json({ error: 'Erreur Airtable', details: error?.message || String(error) });
  }
});

app.get('/api/asbl/:recordId', verifyToken, requireRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const record = await base('ASBL').find(req.params.recordId);

    if (req.user.type === 'admin' && req.user.id !== req.params.recordId) {
      return res.status(403).json({ error: 'Accès refusé (ASBL non autorisée)' });
    }

    res.json({ recordId: record.id, ...record.fields });
  } catch (error) {
    console.error('GET /api/asbl/:recordId ERROR:', error);
    res.status(500).json({ error: 'Erreur Airtable', details: error?.message || String(error) });
  }
});

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
/* ✅ AJOUT : TABLES ROUTES                                            */
/* ------------------------------------------------------------------ */
/**
 * Permet au front de récupérer les tables d'une ASBL:
 * GET /api/tables?asblId=ASBL001
 */
app.get('/api/tables', verifyToken, requireRole(['admin', 'superadmin', 'benevole']), async (req, res) => {
  try {
    const asblId = String(req.query.asblId || '').trim();
    if (!asblId) return res.status(400).json({ error: 'asblId manquant' });

    if (req.user.type !== 'superadmin' && req.user.asblId !== asblId) {
      return res.status(403).json({ error: 'Accès refusé (ASBL non autorisée)' });
    }

    const records = await base('Tables')
      .select({ filterByFormula: `{asblId} = '${asblId}'`, maxRecords: 500 })
      .firstPage();

    res.json(records.map((r) => ({ recordId: r.id, ...r.fields })));
  } catch (e) {
    console.error('GET /api/tables ERROR:', e);
    res.status(500).json({ error: 'Erreur tables', details: e?.message || String(e) });
  }
});

/* ------------------------------------------------------------------ */
/* BENEVOLES ROUTES                                                   */
/* ------------------------------------------------------------------ */

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
        },
      },
    ]);

    res.json({ recordId: created[0].id, ...created[0].fields });
  } catch (error) {
    console.error('POST /api/benevoles ERROR FULL:', error);

    return res.status(500).json({
      error: 'Erreur Airtable',
      details: error?.message || String(error),
      airtable: {
        name: error?.name,
        statusCode: error?.statusCode,
        error: error?.error,
      },
    });
  }
});

/* ------------------------------------------------------------------ */
/* ✅ RÉSERVATIONS : support route /by-asbl + route ?asblId            */
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

// ✅ pour ton front : /api/reservations?asblId=ASBL001
app.get('/api/reservations', verifyToken, requireRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const asblId = String(req.query.asblId || '').trim();
    if (!asblId) return res.status(400).json({ error: 'asblId manquant (query)' });

    if (req.user.type === 'admin' && req.user.asblId !== asblId) {
      return res.status(403).json({ error: 'Accès refusé (ASBL non autorisée)' });
    }

    const all = await fetchAll('Reservations', 500);
    const filtered = all.filter((x) => getAsblCodeFromRecordFields(x) === asblId);

    // ✅ IMPORTANT : on renvoie un ARRAY (le front aime ça)
    res.json(filtered);
  } catch (e) {
    console.error('GET /api/reservations ERROR:', e);
    res.status(500).json({ error: 'Erreur réservations', details: e?.message || String(e) });
  }
});

/* ------------------------------------------------------------------ */
/* ✅ PARTICIPANTS : route ?asblId (celle que ton front appelle)       */
/* ------------------------------------------------------------------ */

// ✅ pour ton front : /api/participants?asblId=ASBL001
app.get('/api/participants', verifyToken, requireRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const asblId = String(req.query.asblId || '').trim();
    if (!asblId) return res.status(400).json({ error: 'asblId manquant (query)' });

    if (req.user.type === 'admin' && req.user.asblId !== asblId) {
      return res.status(403).json({ error: 'Accès refusé (ASBL non autorisée)' });
    }

    const all = await fetchAll('participants', 500); // ⚠️ respecte exactement le nom de ta table Airtable ("participants")
    const filtered = all.filter((x) => getAsblCodeFromRecordFields(x) === asblId);

    // ✅ IMPORTANT : on renvoie un ARRAY, pas {participants:...}
    res.json(filtered);
  } catch (e) {
    console.error('GET /api/participants ERROR:', e);
    res.status(500).json({ error: 'Erreur participants', details: e?.message || String(e) });
  }
});

// Optionnel (si tu veux aussi une route REST propre)
app.get('/api/participants/by-asbl/:asblCode', verifyToken, requireRole(['admin', 'superadmin']), async (req, res) => {
  try {
    const asblCode = req.params.asblCode;

    if (req.user.type === 'admin' && req.user.asblId !== asblCode) {
      return res.status(403).json({ error: 'Accès refusé (ASBL non autorisée)' });
    }

    const all = await fetchAll('participants', 500);
    const filtered = all.filter((x) => getAsblCodeFromRecordFields(x) === asblCode);

    res.json(filtered);
  } catch (e) {
    console.error('GET /api/participants/by-asbl ERROR:', e);
    res.status(500).json({ error: 'Erreur participants', details: e?.message || String(e) });
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
