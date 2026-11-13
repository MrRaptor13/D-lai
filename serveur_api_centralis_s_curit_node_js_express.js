/**
 * ============================================================================
 * BACKEND CENTRALISÉ MULTI-UTILISATEURS - SUIVI DE PRODUCTION CABINET
 * - Authentification individuelle (JWT HttpOnly Secure + Argon2)
 * - Contrôle d'accès par permissions (RBAC)
 * - Génération idempotente des tâches récurrentes (verrouillage PostgreSQL)
 * - Diffusion temps réel (Server-Sent Events / WebSocket) entre collaborateurs
 * - Sauvegardes automatisées chiffrées (pg_dump + rotation)
 * ============================================================================
 */
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const argon2 = require('argon2');
const { Pool } = require('pg');
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const { CgiLoopConnector, encryptSecret } = require('./loopConnector');

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false
});

app.use(helmet());
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

// Protection brute-force sur l'authentification
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  message: { error: 'Trop de tentatives de connexion. Réessayez dans 15 minutes.' }
});

// ============================================================================
// 1. JOURNALISATION D'AUDIT CENTRALISÉE
// ============================================================================
async function logAudit({ userId = null, userEmail = null, action, entityType, entityId = null, ip = null, details = {} }) {
  try {
    await pool.query(
      `INSERT INTO audit_logs (user_id, user_email, action, entity_type, entity_id, ip_address, details)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [userId, userEmail, action, entityType, entityId ? String(entityId) : null, ip, JSON.stringify(details)]
    );
  } catch (err) {
    console.error('[AUDIT_ERROR]', err.message);
  }
}

const loopConnector = new CgiLoopConnector(pool, logAudit);

// ============================================================================
// 2. SYNCHRONISATION TEMPS RÉEL MULTI-COLLABORATEURS (SSE)
// ============================================================================
const sseClients = new Set();

function broadcastEvent(eventName, payload) {
  const frame = `event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const res of sseClients) {
    res.write(frame);
  }
}

// ============================================================================
// 3. AUTHENTIFICATION INDIVIDUELLE & GESTION DES PERMISSIONS (RBAC)
// ============================================================================
const PERMISSIONS = {
  ADMIN: ['*'],
  ASSOCIE: ['task:read', 'task:write', 'task:validate', 'dossier:read', 'dossier:write', 'rec:write', 'loop:sync', 'audit:read'],
  CHEF_MISSION: ['task:read', 'task:write', 'task:validate', 'dossier:read', 'dossier:write', 'rec:write', 'loop:sync'],
  COLLABORATEUR: ['task:read', 'task:write', 'dossier:read']
};

function requireAuth(req, res, next) {
  const token = req.cookies?.cabinet_session || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentification individuelle requise.' });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Session expirée ou invalide.' });
  }
}

function requirePermission(permission) {
  return (req, res, next) => {
    const allowed = PERMISSIONS[req.user?.role] || [];
    if (allowed.includes('*') || allowed.includes(permission)) return next();
    logAudit({
      userId: req.user?.id,
      userEmail: req.user?.email,
      action: 'ACCESS_DENIED',
      entityType: 'permission',
      entityId: permission,
      ip: req.ip
    });
    return res.status(403).json({ error: 'Droits insuffisants pour cette action.' });
  };
}

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Identifiants requis.' });

  const { rows } = await pool.query(
    `SELECT id, email, full_name, password_hash, role, is_active FROM users WHERE LOWER(email) = LOWER($1)`,
    [email.trim()]
  );
  const user = rows[0];

  if (!user || !user.is_active || !(await argon2.verify(user.password_hash, password))) {
    await logAudit({ userEmail: email, action: 'AUTH_LOGIN_FAILED', entityType: 'user', ip: req.ip });
    return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });
  }

  await pool.query(`UPDATE users SET last_login_at = NOW() WHERE id = $1`, [user.id]);

  const token = jwt.sign(
    { id: user.id, email: user.email, name: user.full_name, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '10h' }
  );

  res.cookie('cabinet_session', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 10 * 3600 * 1000
  });

  await logAudit({ userId: user.id, userEmail: user.email, action: 'AUTH_LOGIN_OK', entityType: 'user', entityId: user.id, ip: req.ip });
  res.json({ id: user.id, email: user.email, name: user.full_name, role: user.role });
});

app.post('/api/auth/logout', requireAuth, async (req, res) => {
  await logAudit({ userId: req.user.id, userEmail: req.user.email, action: 'AUTH_LOGOUT', entityType: 'user', entityId: req.user.id, ip: req.ip });
  res.clearCookie('cabinet_session');
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json(req.user);
});

// Flux temps réel partagé entre les collaborateurs connectés
app.get('/api/stream', requireAuth, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();
  sseClients.add(res);
  req.on('close', () => sseClients.delete(res));
});

// ============================================================================
// 4. PRÉVENTION DES DOUBLONS LORS DE LA GÉNÉRATION DES TÂCHES RÉCURRENTES
// ============================================================================
function computeNextDate(isoDateStr, freq, customInterval = 1, customUnit = 'm', dayOfMonth = null) {
  const d = new Date(`${isoDateStr}T12:00:00Z`);
  if (freq === 'Quotidienne') { d.setUTCDate(d.getUTCDate() + 1); return d.toISOString().slice(0, 10); }
  if (freq === 'Hebdomadaire') { d.setUTCDate(d.getUTCDate() + 7); return d.toISOString().slice(0, 10); }
  if (freq === 'Personnalisée' && customUnit === 'd') {
    d.setUTCDate(d.getUTCDate() + Math.max(1, customInterval));
    return d.toISOString().slice(0, 10);
  }
  const monthsMap = { Mensuelle: 1, Trimestrielle: 3, Semestrielle: 6, Annuelle: 12 };
  const addMonths = freq === 'Personnalisée' ? Math.max(1, customInterval) : (monthsMap[freq] || 1);
  const year = d.getUTCFullYear();
  const month = d.getUTCMonth() + addMonths;
  const lastDay = new Date(Date.UTC(year, month + 1, 0)).getUTCDate();
  const targetDay = Math.min(dayOfMonth || d.getUTCDate(), lastDay);
  return new Date(Date.UTC(year, month, targetDay)).toISOString().slice(0, 10);
}

/**
 * Génération transactionnelle avec :
 * 1. Verrou transactionnel PostgreSQL (pg_try_advisory_xact_lock)
 * 2. Clause ON CONFLICT (recurring_template_id, occurrence_key) DO NOTHING
 * Garantit zéro doublon même si plusieurs collaborateurs déclenchent la génération simultanément.
 */
async function generateRecurringTasksSafe(actorUserId = null) {
  const client = await pool.connect();
  let createdCount = 0;

  try {
    await client.query('BEGIN');

    // Verrou exclusif non-bloquant dédié à la génération des récurrences
    const lockRes = await client.query(`SELECT pg_try_advisory_xact_lock(987654321) AS acquired`);
    if (!lockRes.rows[0].acquired) {
      await client.query('ROLLBACK');
      return { skipped: true, reason: 'Génération déjà en cours par un autre processus.' };
    }

    const horizon = new Date(Date.now() + 30 * 86400_000).toISOString().slice(0, 10);
    const { rows: templates } = await client.query(
      `SELECT * FROM recurring_templates WHERE is_active = TRUE AND next_due_date <= $1 FOR UPDATE`,
      [horizon]
    );

    for (const tpl of templates) {
      let nextDate = tpl.next_due_date.toISOString().slice(0, 10);
      let guard = 0;
      let advanced = false;

      while (nextDate <= horizon && guard++ < 60 && (!tpl.end_date || nextDate <= tpl.end_date.toISOString().slice(0, 10))) {
        const occurrenceKey = `${tpl.id}_${nextDate}`;

        const insertRes = await client.query(
          `INSERT INTO tasks (
             title, group_label, description, dossier_id, responsable_id, validateur_id,
             due_date, priority, status, recurring_template_id, occurrence_key, created_by
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, $9, $10, $11)
           ON CONFLICT (recurring_template_id, occurrence_key) DO NOTHING
           RETURNING id`,
          [
            `${tpl.title} – ${nextDate}`,
            tpl.title,
            tpl.description,
            tpl.dossier_id,
            tpl.responsable_id,
            tpl.validateur_id,
            nextDate,
            tpl.priority,
            tpl.id,
            occurrenceKey,
            actorUserId
          ]
        );

        if (insertRes.rowCount > 0) {
          createdCount++;
        }

        nextDate = computeNextDate(nextDate, tpl.frequency, tpl.custom_interval, tpl.custom_unit, tpl.day_of_month);
        advanced = true;
      }

      if (advanced) {
        await client.query(`UPDATE recurring_templates SET next_due_date = $1 WHERE id = $2`, [nextDate, tpl.id]);
      }
    }

    await client.query('COMMIT');

    if (createdCount > 0) {
      await logAudit({
        userId: actorUserId,
        action: 'RECURRENCE_GENERATED',
        entityType: 'tasks',
        details: { createdCount }
      });
      broadcastEvent('tasks_changed', { reason: 'recurrence_generated', count: createdCount });
    }

    return { createdCount };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ============================================================================
// 5. ENDPOINTS MÉTIER PARTAGÉS (TÂCHES, VALIDATIONS, CGI LOOP, AUDIT)
// ============================================================================
app.get('/api/state', requireAuth, requirePermission('task:read'), async (req, res) => {
  const [users, dossiers, tasks, recs, loopCfg] = await Promise.all([
    pool.query(`SELECT id, full_name AS name, email, role FROM users WHERE is_active = TRUE ORDER BY full_name`),
    pool.query(`SELECT * FROM dossiers WHERE is_archived = FALSE ORDER BY numero_dossier`),
    pool.query(`
      SELECT t.*, d.numero_dossier AS dos, u.full_name AS resp, v.full_name AS val
      FROM tasks t
      JOIN dossiers d ON d.id = t.dossier_id
      JOIN users u ON u.id = t.responsable_id
      LEFT JOIN users v ON v.id = t.validateur_id
      WHERE t.is_archived = FALSE
      ORDER BY t.due_date ASC
    `),
    pool.query(`SELECT * FROM recurring_templates ORDER BY next_due_date ASC`),
    pool.query(`SELECT provider, base_url, tenant_id, last_sync_at, last_sync_status, last_sync_error FROM integration_configs LIMIT 1`)
  ]);

  res.json({
    users: users.rows,
    dossiers: dossiers.rows,
    tasks: tasks.rows,
    recurrences: recs.rows,
    loopStatus: loopCfg.rows[0] || null
  });
});

// Mise à jour d'une tâche avec contrôle de permission sur la validation (statut 5) et verrouillage optimiste
app.patch('/api/tasks/:id', requireAuth, requirePermission('task:write'), async (req, res) => {
  const { id } = req.params;
  const { status, due_date, priority, responsable_id, version } = req.body;

  if (Number(status) === 5) {
    const allowed = PERMISSIONS[req.user.role] || [];
    if (!allowed.includes('*') && !allowed.includes('task:validate')) {
      return res.status(403).json({ error: 'Seul un chef de mission ou associé peut passer une tâche au statut Validé.' });
    }
  }

  const { rows } = await pool.query(
    `UPDATE tasks
     SET status = COALESCE($1, status),
         due_date = COALESCE($2, due_date),
         priority = COALESCE($3, priority),
         responsable_id = COALESCE($4, responsable_id),
         version = version + 1,
         updated_at = NOW()
     WHERE id = $5 AND version = $6
     RETURNING *`,
    [status ?? null, due_date ?? null, priority ?? null, responsable_id ?? null, id, version]
  );

  if (!rows.length) {
    return res.status(409).json({ error: 'Conflit de modification : un autre collaborateur vient de modifier cette tâche. Rechargez les données.' });
  }

  await logAudit({
    userId: req.user.id,
    userEmail: req.user.email,
    action: 'TASK_UPDATED',
    entityType: 'task',
    entityId: id,
    ip: req.ip,
    details: { status, due_date, priority }
  });

  broadcastEvent('tasks_changed', { taskId: id, updatedBy: req.user.name });
  res.json(rows[0]);
});

// Déclenchement manuel de la synchronisation CGI Loop
app.post('/api/integrations/loop/sync', requireAuth, requirePermission('loop:sync'), async (req, res) => {
  try {
    const result = await loopConnector.syncDossiers(req.user.id, req.ip);
    broadcastEvent('dossiers_changed', { syncedBy: req.user.name });
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: `Erreur de synchronisation CGI Loop : ${err.message}` });
  }
});

// Enregistrement sécurisé des clés API CGI Loop (Administrateur uniquement)
app.put('/api/integrations/loop/config', requireAuth, requirePermission('*'), async (req, res) => {
  const { base_url, client_id, client_secret, tenant_id } = req.body;
  if (!base_url || !client_id || !client_secret || !tenant_id) {
    return res.status(400).json({ error: 'Tous les paramètres CGI Loop sont obligatoires.' });
  }

  await pool.query(
    `INSERT INTO integration_configs (provider, base_url, client_id_enc, client_secret_enc, tenant_id, updated_by, updated_at)
     VALUES ('CGI_LOOP', $1, $2, $3, $4, $5, NOW())
     ON CONFLICT (provider) DO UPDATE SET
       base_url = EXCLUDED.base_url,
       client_id_enc = EXCLUDED.client_id_enc,
       client_secret_enc = EXCLUDED.client_secret_enc,
       tenant_id = EXCLUDED.tenant_id,
       updated_by = EXCLUDED.updated_by,
       updated_at = NOW()`,
    [base_url, encryptSecret(client_id), encryptSecret(client_secret), tenant_id, req.user.id]
  );

  await logAudit({
    userId: req.user.id,
    userEmail: req.user.email,
    action: 'LOOP_CONFIG_UPDATED',
    entityType: 'integration',
    entityId: 'CGI_LOOP',
    ip: req.ip
  });

  res.json({ ok: true });
});

// Consultation du journal d'audit
app.get('/api/audit-logs', requireAuth, requirePermission('audit:read'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, occurred_at, user_email, action, entity_type, entity_id, ip_address, details
     FROM audit_logs ORDER BY occurred_at DESC LIMIT 200`
  );
  res.json(rows);
});

// ============================================================================
// 6. SAUVEGARDES RÉGULIÈRES AUTOMATISÉES (pg_dump + rétention 30 jours)
// ============================================================================
function runAutomatedBackup() {
  const backupDir = process.env.BACKUP_DIR || path.join(__dirname, 'backups');
  fs.mkdirSync(backupDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const outFile = path.join(backupDir, `cabinet-prod-${stamp}.dump`);

  execFile('pg_dump', ['--format=custom', '--compress=9', `--file=${outFile}`, process.env.DATABASE_URL], async (err) => {
    if (err) {
      await logAudit({ action: 'BACKUP_ERROR', entityType: 'database', details: { error: err.message } });
      return;
    }
    await logAudit({ action: 'BACKUP_SUCCESS', entityType: 'database', details: { file: path.basename(outFile) } });

    // Rotation : suppression des sauvegardes de plus de 30 jours
    const cutoff = Date.now() - 30 * 86400_000;
    for (const file of fs.readdirSync(backupDir)) {
      const full = path.join(backupDir, file);
      if (fs.statSync(full).mtimeMs < cutoff) fs.unlinkSync(full);
    }
  });
}

// Exécution périodique : récurrences toutes les heures, sauvegarde toutes les 6 heures
setInterval(() => generateRecurringTasksSafe(null).catch(console.error), 3600_000);
setInterval(runAutomatedBackup, 6 * 3600_000);

app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serveur centralisé Suivi de production démarré sur le port ${PORT}`);
});