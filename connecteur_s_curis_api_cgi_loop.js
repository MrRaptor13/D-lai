/**
 * ============================================================================
 * CONNECTEUR API SÉCURISÉ CGI LOOP
 * - Authentification OAuth2 Client Credentials avec renouvellement anticipé du jeton
 * - Chiffrement AES-256-GCM des clés API en base
 * - Retry exponentiel, gestion fine des erreurs HTTP (401, 429, 5xx) et journalisation
 * ============================================================================
 */
const crypto = require('crypto');

const ENCRYPTION_KEY = Buffer.from(process.env.MASTER_ENCRYPTION_KEY_HEX, 'hex'); // 32 octets

function encryptSecret(plainText) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]);
}

function decryptSecret(buffer) {
  const iv = buffer.subarray(0, 12);
  const tag = buffer.subarray(12, 28);
  const encrypted = buffer.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

class CgiLoopConnector {
  constructor(pool, auditFn) {
    this.pool = pool;
    this.audit = auditFn;
    this.accessToken = null;
    this.tokenExpiresAt = 0;
  }

  async getCredentials() {
    const { rows } = await this.pool.query(
      `SELECT base_url, client_id_enc, client_secret_enc, tenant_id 
       FROM integration_configs WHERE provider = 'CGI_LOOP' LIMIT 1`
    );
    if (!rows.length) {
      throw new Error('Configuration API CGI Loop absente.');
    }
    const cfg = rows[0];
    return {
      baseUrl: cfg.base_url.replace(/\/+$/, ''),
      clientId: decryptSecret(cfg.client_id_enc),
      clientSecret: decryptSecret(cfg.client_secret_enc),
      tenantId: cfg.tenant_id
    };
  }

  async authenticate(forceRefresh = false) {
    if (!forceRefresh && this.accessToken && Date.now() < this.tokenExpiresAt - 60_000) {
      return this.accessToken;
    }
    const { baseUrl, clientId, clientSecret, tenantId } = await this.getCredentials();

    const response = await fetch(`${baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Tenant-Id': tenantId
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: clientSecret,
        scope: 'dossiers.read echeances.read'
      }),
      signal: AbortSignal.timeout(15_000)
    });

    if (!response.ok) {
      const errBody = await response.text().catch(() => '');
      throw new Error(`Échec OAuth2 CGI Loop (HTTP ${response.status}) : ${errBody.slice(0, 200)}`);
    }

    const data = await response.json();
    this.accessToken = data.access_token;
    this.tokenExpiresAt = Date.now() + (data.expires_in || 3600) * 1000;
    return this.accessToken;
  }

  async requestWithRetry(endpoint, attempt = 1) {
    const { baseUrl, tenantId } = await this.getCredentials();
    const token = await this.authenticate(attempt > 1);

    try {
      const res = await fetch(`${baseUrl}${endpoint}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'X-Tenant-Id': tenantId,
          'Accept': 'application/json'
        },
        signal: AbortSignal.timeout(20_000)
      });

      if (res.status === 401 && attempt === 1) {
        return this.requestWithRetry(endpoint, 2);
      }
      if ((res.status === 429 || res.status >= 500) && attempt <= 3) {
        const delayMs = Math.pow(2, attempt) * 1000;
        await new Promise(r => setTimeout(r, delayMs));
        return this.requestWithRetry(endpoint, attempt + 1);
      }
      if (!res.ok) {
        throw new Error(`Erreur API Loop ${endpoint} : HTTP ${res.status}`);
      }
      return await res.json();
    } catch (err) {
      if (attempt <= 3 && (err.name === 'TimeoutError' || err.code === 'ECONNRESET')) {
        await new Promise(r => setTimeout(r, attempt * 1500));
        return this.requestWithRetry(endpoint, attempt + 1);
      }
      throw err;
    }
  }

  /**
   * Synchronisation transactionnelle des dossiers clients depuis CGI Loop
   */
  async syncDossiers(triggeredByUserId = null, ip = null) {
    const client = await this.pool.connect();
    let upsertedCount = 0;

    try {
      const payload = await this.requestWithRetry('/api/v1/dossiers?statut=ACTIF');
      const loopDossiers = Array.isArray(payload.items) ? payload.items : [];

      await client.query('BEGIN');

      for (const item of loopDossiers) {
        await client.query(
          `INSERT INTO dossiers (
             loop_external_id, numero_dossier, raison_sociale, siren,
             forme_juridique, regime_tva, date_cloture, synced_at, updated_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
           ON CONFLICT (loop_external_id) DO UPDATE SET
             numero_dossier = EXCLUDED.numero_dossier,
             raison_sociale = EXCLUDED.raison_sociale,
             siren = EXCLUDED.siren,
             forme_juridique = EXCLUDED.forme_juridique,
             regime_tva = EXCLUDED.regime_tva,
             date_cloture = EXCLUDED.date_cloture,
             synced_at = NOW(),
             updated_at = NOW()`,
          [
            item.id,
            item.codeDossier,
            item.raisonSociale,
            item.siren || null,
            item.formeJuridique || null,
            item.regimeTva || null,
            item.dateCloture || null
          ]
        );
        upsertedCount++;
      }

      await client.query(
        `UPDATE integration_configs
         SET last_sync_at = NOW(), last_sync_status = 'OK', last_sync_error = NULL
         WHERE provider = 'CGI_LOOP'`
      );

      await client.query('COMMIT');

      await this.audit({
        userId: triggeredByUserId,
        action: 'LOOP_SYNC_SUCCESS',
        entityType: 'integration',
        entityId: 'CGI_LOOP',
        ip,
        details: { dossiers_synchronises: upsertedCount }
      });

      return { status: 'OK', count: upsertedCount };
    } catch (err) {
      await client.query('ROLLBACK');

      await this.pool.query(
        `UPDATE integration_configs
         SET last_sync_at = NOW(), last_sync_status = 'ERROR', last_sync_error = $1
         WHERE provider = 'CGI_LOOP'`,
        [err.message]
      );

      await this.audit({
        userId: triggeredByUserId,
        action: 'LOOP_SYNC_ERROR',
        entityType: 'integration',
        entityId: 'CGI_LOOP',
        ip,
        details: { error: err.message }
      });

      throw err;
    } finally {
      client.release();
    }
  }
}

module.exports = { CgiLoopConnector, encryptSecret };