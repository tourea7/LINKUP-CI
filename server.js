require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const { createClient } = require('@supabase/supabase-js');

// ══════════════════════════════════════
// CONFIG
// ══════════════════════════════════════
const app = express();
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

app.use(cors({ origin: '*', credentials: true, exposedHeaders: ['Content-Disposition'] }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ══════════════════════════════════════
// MULTER - Upload fichiers
// ══════════════════════════════════════
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads', req.user.id);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`)
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    ['image/jpeg','image/png','application/pdf'].includes(file.mimetype)
      ? cb(null, true) : cb(new Error('Format non supporté. JPG, PNG, PDF uniquement.'));
  },
  limits: { fileSize: 5 * 1024 * 1024 }
});

// ══════════════════════════════════════
// MIDDLEWARE AUTH
// ══════════════════════════════════════
const protect = async (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Token manquant.' });
  }
  try {
    const decoded = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET);
    const { data: user, error } = await supabase.from('users').select('*').eq('id', decoded.id).single();
    if (error || !user) return res.status(401).json({ success: false, message: 'Utilisateur introuvable.' });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ success: false, message: 'Token invalide.' });
  }
};

const adminOnly = (req, res, next) => {
  if (req.user?.role === 'admin') return next();
  res.status(403).json({ success: false, message: 'Accès admin requis.' });
};

const genToken = (id) => jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '7d' });

// ══════════════════════════════════════
// ROUTES AUTH
// ══════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { prenom, nom, email, telephone, password } = req.body;
    if (!prenom || !nom || !email || !password)
      return res.status(400).json({ success: false, message: 'Champs obligatoires manquants.' });

    const { data: existing } = await supabase.from('users').select('id').eq('email', email).single();
    if (existing) return res.status(400).json({ success: false, message: 'Email déjà utilisé.' });

    const hashed = await bcrypt.hash(password, 10);
    const user = { id: uuidv4(), prenom, nom, email, telephone: telephone || null, password: hashed, role: 'client' };

    const { data, error } = await supabase.from('users').insert(user).select().single();
    if (error) throw error;

    await supabase.from('notifications').insert({
      id: uuidv4(), user_id: user.id,
      title: 'Bienvenue sur Linkup !',
      message: `Bonjour ${prenom}, votre compte a été créé avec succès.`,
      type: 'info', read: false
    });

    res.status(201).json({ success: true, token: genToken(user.id), user: { id: data.id, prenom: data.prenom, nom: data.nom, email: data.email, telephone: data.telephone, role: data.role } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email et mot de passe requis.' });

    const { data: user } = await supabase.from('users').select('*').eq('email', email).single();
    if (!user) return res.status(401).json({ success: false, message: 'Identifiants incorrects.' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ success: false, message: 'Identifiants incorrects.' });

    res.json({ success: true, token: genToken(user.id), user: { id: user.id, prenom: user.prenom, nom: user.nom, email: user.email, telephone: user.telephone, role: user.role } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', protect, (req, res) => {
  const u = req.user;
  res.json({ success: true, user: { id: u.id, prenom: u.prenom, nom: u.nom, email: u.email, telephone: u.telephone, role: u.role } });
});

// PUT /api/auth/me
app.put('/api/auth/me', protect, async (req, res) => {
  try {
    const { prenom, nom, telephone } = req.body;
    const { data, error } = await supabase.from('users').update({ prenom, nom, telephone }).eq('id', req.user.id).select().single();
    if (error) throw error;
    res.json({ success: true, user: { id: data.id, prenom: data.prenom, nom: data.nom, email: data.email, telephone: data.telephone, role: data.role } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ══════════════════════════════════════
// ROUTES DOSSIERS
// ══════════════════════════════════════
const MONTANTS = { EI: 25000, SA: 150000, SAU: 150000, SAS: 100000, SARLU: 50000, SARL: 75000, SCP: 75000, SCI: 75000, COOP: 60000, MUT: 60000 };
const TYPES = Object.keys(MONTANTS);

// POST /api/dossiers
app.post('/api/dossiers', protect, async (req, res) => {
  try {
    const { typeEntreprise, nomEntreprise, activite, capitalSocial, adresse, nombreAssocies, nomGerant, telephoneGerant } = req.body;

    if (!typeEntreprise || !nomEntreprise || !activite || !adresse)
      return res.status(400).json({ success: false, message: 'Champs obligatoires manquants.' });

    if (!TYPES.includes(typeEntreprise))
      return res.status(400).json({ success: false, message: `Type invalide. Valeurs: ${TYPES.join(', ')}` });

    const { count } = await supabase.from('dossiers').select('*', { count: 'exact', head: true });
    const reference = `LKP-${new Date().getFullYear()}-${String((count || 0) + 1).padStart(5, '0')}`;

    const dossier = {
      id: uuidv4(), reference,
      user_id: req.user.id,
      type_entreprise: typeEntreprise,
      nom_entreprise: nomEntreprise,
      activite, adresse,
      capital_social: capitalSocial || 0,
      nombre_associes: nombreAssocies || 1,
      nom_gerant: nomGerant || `${req.user.prenom} ${req.user.nom}`,
      telephone_gerant: telephoneGerant || req.user.telephone,
      statut: 'recu',
      montant: MONTANTS[typeEntreprise],
      paiement_statut: 'en_attente',
      historique: [{ statut: 'recu', date: new Date().toISOString(), message: 'Dossier reçu et enregistré.' }]
    };

    const { data, error } = await supabase.from('dossiers').insert(dossier).select().single();
    if (error) throw error;

    await supabase.from('notifications').insert({
      id: uuidv4(), user_id: req.user.id,
      title: 'Dossier soumis ✅',
      message: `Votre dossier ${reference} a été reçu. Montant: ${dossier.montant.toLocaleString()} FCFA.`,
      type: 'success', read: false, dossier_id: dossier.id
    });

    res.status(201).json({ success: true, dossier: data });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/dossiers/stats (admin)
app.get('/api/dossiers/stats', protect, adminOnly, async (req, res) => {
  try {
    const { data: dossiers } = await supabase.from('dossiers').select('statut,type_entreprise,montant');
    const { data: users } = await supabase.from('users').select('role');
    const { data: payments } = await supabase.from('payments').select('montant,statut');
    const d = dossiers || [];
    res.json({ success: true, stats: {
      total: d.length,
      parStatut: { recu: d.filter(x=>x.statut==='recu').length, en_cours: d.filter(x=>x.statut==='en_cours').length, traitement: d.filter(x=>x.statut==='traitement').length, valide: d.filter(x=>x.statut==='valide').length, livre: d.filter(x=>x.statut==='livre').length },
      totalClients: (users||[]).filter(u=>u.role==='client').length,
      totalRevenuFCFA: (payments||[]).filter(p=>p.statut==='confirme').reduce((s,p)=>s+p.montant, 0)
    }});
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/dossiers
app.get('/api/dossiers', protect, async (req, res) => {
  try {
    let query = supabase.from('dossiers').select('*').order('created_at', { ascending: false });
    if (req.user.role !== 'admin') query = query.eq('user_id', req.user.id);
    const { data, error } = await query;
    if (error) throw error;

    let dossiers = data || [];
    if (req.user.role === 'admin') {
      const ids = [...new Set(dossiers.map(d => d.user_id))];
      const { data: usrs } = await supabase.from('users').select('id,prenom,nom,email').in('id', ids);
      const map = Object.fromEntries((usrs||[]).map(u => [u.id, u]));
      dossiers = dossiers.map(d => ({ ...d, client: map[d.user_id] || null }));
    }
    res.json({ success: true, dossiers });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/dossiers/:id
app.get('/api/dossiers/:id', protect, async (req, res) => {
  try {
    const { data: dossier, error } = await supabase.from('dossiers').select('*').eq('id', req.params.id).single();
    if (error || !dossier) return res.status(404).json({ success: false, message: 'Dossier introuvable.' });
    if (req.user.role !== 'admin' && dossier.user_id !== req.user.id)
      return res.status(403).json({ success: false, message: 'Accès refusé.' });

    const { data: documents } = await supabase.from('documents').select('*').eq('dossier_id', dossier.id);
    const { data: payments } = await supabase.from('payments').select('*').eq('dossier_id', dossier.id);
    res.json({ success: true, dossier: { ...dossier, documents: documents||[], payments: payments||[] } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// PUT /api/dossiers/:id/statut (admin)
app.put('/api/dossiers/:id/statut', protect, adminOnly, async (req, res) => {
  try {
    const { statut, message } = req.body;
    const STATUTS = ['recu','en_cours','traitement','valide','livre'];
    if (!STATUTS.includes(statut)) return res.status(400).json({ success: false, message: 'Statut invalide.' });

    const { data: dossier } = await supabase.from('dossiers').select('*').eq('id', req.params.id).single();
    if (!dossier) return res.status(404).json({ success: false, message: 'Introuvable.' });

    const messages = { en_cours: 'En cours de traitement.', traitement: 'Soumis aux autorités.', valide: 'Validé officiellement.', livre: 'Documents prêts à télécharger.' };
    const entry = { statut, date: new Date().toISOString(), message: message || messages[statut] || statut };
    const historique = [...(dossier.historique||[]), entry];

    const { data, error } = await supabase.from('dossiers').update({ statut, historique }).eq('id', req.params.id).select().single();
    if (error) throw error;

    await supabase.from('notifications').insert({
      id: uuidv4(), user_id: dossier.user_id,
      title: `Dossier ${dossier.reference} mis à jour`,
      message: entry.message, type: 'info', read: false, dossier_id: dossier.id
    });

    res.json({ success: true, dossier: data });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ══════════════════════════════════════
// ROUTES DOCUMENTS
// ══════════════════════════════════════

// POST /api/documents/upload
app.post('/api/documents/upload', protect, upload.single('document'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, message: 'Aucun fichier.' });
    const { dossierId, typeDocument } = req.body;

    const { data: dossier } = await supabase.from('dossiers').select('user_id').eq('id', dossierId).single();
    if (!dossier) { fs.unlinkSync(req.file.path); return res.status(404).json({ success: false, message: 'Dossier introuvable.' }); }

    const doc = {
      id: uuidv4(), dossier_id: dossierId, user_id: req.user.id,
      type_document: typeDocument || 'autre',
      nom_fichier: req.file.originalname,
      url: `/uploads/${req.user.id}/${req.file.filename}`,
      taille: req.file.size, mime_type: req.file.mimetype,
      storage_path: req.file.path, storage_type: 'local'
    };

    const { data, error } = await supabase.from('documents').insert(doc).select().single();
    if (error) throw error;

    res.status(201).json({ success: true, message: 'Document téléversé !', document: data });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/documents/dossier/:dossierId
app.get('/api/documents/dossier/:dossierId', protect, async (req, res) => {
  try {
    const { data, error } = await supabase.from('documents').select('*').eq('dossier_id', req.params.dossierId);
    if (error) throw error;
    res.json({ success: true, documents: data || [] });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/documents/:id/download
app.get('/api/documents/:id/download', protect, async (req, res) => {
  try {
    const { data: doc } = await supabase.from('documents').select('*').eq('id', req.params.id).single();
    if (!doc) return res.status(404).json({ success: false, message: 'Document introuvable.' });
    if (!fs.existsSync(doc.storage_path)) return res.status(404).json({ success: false, message: 'Fichier non trouvé.' });
    res.setHeader('Content-Disposition', `attachment; filename="${doc.nom_fichier}"`);
    res.sendFile(path.resolve(doc.storage_path));
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ══════════════════════════════════════
// ROUTES PAIEMENTS
// ══════════════════════════════════════

// POST /api/payments
app.post('/api/payments', protect, async (req, res) => {
  try {
    const { dossierId, methode } = req.body;
    const { data: dossier } = await supabase.from('dossiers').select('*').eq('id', dossierId).single();
    if (!dossier) return res.status(404).json({ success: false, message: 'Dossier introuvable.' });

    const payment = { id: uuidv4(), reference: `PAY-${Date.now()}`, dossier_id: dossierId, user_id: req.user.id, montant: dossier.montant, methode, statut: 'en_attente' };
    const { data, error } = await supabase.from('payments').insert(payment).select().single();
    if (error) throw error;

    res.status(201).json({ success: true, payment: data });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// PUT /api/payments/:id/confirmer (admin)
app.put('/api/payments/:id/confirmer', protect, adminOnly, async (req, res) => {
  try {
    const { data: payment } = await supabase.from('payments').select('*').eq('id', req.params.id).single();
    if (!payment) return res.status(404).json({ success: false, message: 'Introuvable.' });

    await supabase.from('payments').update({ statut: 'confirme' }).eq('id', req.params.id);

    const { data: dossier } = await supabase.from('dossiers').select('*').eq('id', payment.dossier_id).single();
    const historique = [...(dossier?.historique||[]), { statut: 'en_cours', date: new Date().toISOString(), message: `Paiement de ${payment.montant.toLocaleString()} FCFA confirmé.` }];
    await supabase.from('dossiers').update({ paiement_statut: 'confirme', statut: 'en_cours', historique }).eq('id', payment.dossier_id);

    await supabase.from('notifications').insert({ id: uuidv4(), user_id: payment.user_id, title: 'Paiement confirmé ✅', message: `Paiement de ${payment.montant.toLocaleString()} FCFA confirmé.`, type: 'success', read: false });

    res.json({ success: true, message: 'Paiement confirmé.' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/payments
app.get('/api/payments', protect, async (req, res) => {
  try {
    let query = supabase.from('payments').select('*').order('created_at', { ascending: false });
    if (req.user.role !== 'admin') query = query.eq('user_id', req.user.id);
    const { data, error } = await query;
    if (error) throw error;
    res.json({ success: true, payments: data || [] });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ══════════════════════════════════════
// ROUTES NOTIFICATIONS
// ══════════════════════════════════════
app.get('/api/notifications', protect, async (req, res) => {
  try {
    const { data } = await supabase.from('notifications').select('*').eq('user_id', req.user.id).order('created_at', { ascending: false });
    res.json({ success: true, notifications: data||[], unread: (data||[]).filter(n=>!n.read).length });
  } catch (err) { res.status(500).json({ success: false }); }
});

app.put('/api/notifications/tout-lire', protect, async (req, res) => {
  await supabase.from('notifications').update({ read: true }).eq('user_id', req.user.id);
  res.json({ success: true });
});

app.put('/api/notifications/:id/lire', protect, async (req, res) => {
  await supabase.from('notifications').update({ read: true }).eq('id', req.params.id);
  res.json({ success: true });
});

// ══════════════════════════════════════
// HEALTH + START
// ══════════════════════════════════════
app.get('/api/health', (req, res) => {
  res.json({ success: true, message: '✅ Linkup API — JavaScript + Supabase', version: '3.0.0', timestamp: new Date().toISOString() });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.use((req, res) => res.status(404).json({ success: false, message: `Route introuvable: ${req.method} ${req.originalUrl}` }));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`\n🚀 Linkup API — JavaScript + Supabase`);
  console.log(`🌍 http://localhost:${PORT}`);
  console.log(`❤️  http://localhost:${PORT}/api/health`);
  console.log(`🗄️  Supabase: ${process.env.SUPABASE_URL}\n`);
});
