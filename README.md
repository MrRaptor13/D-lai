# D-lai

**Le suivi de production de votre cabinet comptable : chaque dossier, chaque échéance, chaque délai tenu.**

D-lai est une application collaborative de gestion de tâches pour cabinet d’expertise comptable. Elle centralise les travaux comptables, fiscaux et administratifs de chaque dossier client (synchronisés depuis CGI Loop), avec tâches récurrentes, circuit de validation, tableau de bord et calendrier.

---

## Fonctionnalités

| Domaine | Détail |
|---|---|
| **Dossiers clients** | Synchronisation depuis l’API CGI Loop (numéro, raison sociale, SIREN, forme juridique, régime TVA, clôture), saisie manuelle possible, import Excel/CSV |
| **Tâches** | Création, modification, duplication, archivage, suppression ; responsable, collaborateurs associés, validateur, priorité, échéance |
| **Récurrences** | Quotidienne, hebdomadaire, mensuelle, trimestrielle, semestrielle, annuelle, personnalisée ; date de début et de fin ; suspension / arrêt |
| **Occurrences** | Chaque occurrence est indépendante (statut, échéance, commentaires, historique) et regroupée sous sa tâche récurrente |
| **Statuts** | Non fait · Demande au client · En attente · En cours · Fait · Validé (modifiables directement depuis la liste) |
| **Validation** | « Fait » notifie le validateur, qui valide, refuse ou demande une correction ; seul le validateur peut passer en « Validé » |
| **Suivi** | Tableau de bord filtrable, vue personnelle, calendrier jour/semaine/mois avec glisser-déposer |
| **Notifications** | Attribution, modification, commentaire, validation, rappels J-7 / J-3 / J-1 / jour J |
| **Traçabilité** | Historique par tâche et journal d’audit global |

---

## Architecture

```
Navigateur (public/index.html)
   │  HTTPS + cookie de session HttpOnly
   ▼
Serveur Node.js / Express (server.js)
   ├─ Authentification individuelle (JWT + Argon2) et droits par rôle
   ├─ Génération idempotente des récurrences (verrou PostgreSQL)
   ├─ Temps réel entre collaborateurs (Server-Sent Events)
   ├─ Connecteur CGI Loop (loopConnector.js) — identifiants chiffrés AES-256-GCM
   └─ Sauvegardes automatiques (pg_dump, rétention 30 jours)
   ▼
PostgreSQL 15+ (schema.sql)
```

Les identifiants CGI Loop ne sont **jamais** présents dans le code du navigateur : ils sont saisis par l’administrateur, chiffrés côté serveur et stockés en base.

### Fichiers

| Fichier de ce dépôt | Rôle |
|---|---|
| `server.js` | API Express, authentification, droits, récurrences, SSE, audit, sauvegardes |
| `loopConnector.js` | Connecteur OAuth2 CGI Loop (jeton renouvelé, retry exponentiel, gestion 401/429/5xx) |
| `schema.sql` | Schéma PostgreSQL (utilisateurs, dossiers, tâches, récurrences, audit) |
| `public/index.html` | Interface web servie par le serveur |

> Les fichiers fournis ont des noms longs ; renommez-les ainsi. `server.js` attend le connecteur sous `./loopConnector` et l’interface dans `./public`.

---

## Installation

**Prérequis :** Node.js 18 ou plus récent, PostgreSQL 15+, `pg_dump` disponible sur le serveur.

```bash
npm init -y
npm install express helmet cookie-parser express-rate-limit jsonwebtoken argon2 pg dotenv
psql "$DATABASE_URL" -f schema.sql
```

Créez un fichier `.env` (à ne jamais versionner) :

```ini
NODE_ENV=production
PORT=3000
DATABASE_URL=postgres://utilisateur:motdepasse@hote:5432/dlai
JWT_SECRET=<longue chaîne aléatoire>
MASTER_ENCRYPTION_KEY_HEX=<64 caractères hexadécimaux = 32 octets>
BACKUP_DIR=/var/backups/d-lai
```

Générer les secrets :

```bash
openssl rand -hex 32    # MASTER_ENCRYPTION_KEY_HEX
openssl rand -base64 48 # JWT_SECRET
```

Démarrer :

```bash
node server.js
```

### Premier administrateur

Aucune route ne crée encore d’utilisateur. Insérez le premier compte directement en base avec un mot de passe haché Argon2id :

```bash
node -e "require('argon2').hash('MotDePasseTemporaire').then(console.log)"
```

```sql
INSERT INTO users (email, full_name, password_hash, role)
VALUES ('admin@cabinet.fr', 'Administrateur', '<hash argon2>', 'ADMIN');
```

### Connexion à CGI Loop

1. Connectez-vous en administrateur.
2. Renseignez l’URL de l’API, le `client_id`, le `client_secret` et le `tenant_id` (route `PUT /api/integrations/loop/config`).
3. Lancez une synchronisation (`POST /api/integrations/loop/sync`).

L’état de la dernière synchronisation (OK / ERROR) est conservé en base et journalisé.

---

## Rôles et droits

| Rôle | Droits |
|---|---|
| `ADMIN` | Tous |
| `ASSOCIE` | Lecture/écriture des tâches et dossiers, validation, récurrences, synchronisation, journal d’audit |
| `CHEF_MISSION` | Idem sans le journal d’audit |
| `COLLABORATEUR` | Lecture/écriture des tâches, lecture des dossiers |

---

## Import Excel des dossiers

Colonnes attendues (repérées par leurs en-têtes, accents et casse ignorés) :

| NOM | NUMERO | PERIODE | TYPE | EBIC | COMMENTAIRE |
|---|---|---|---|---|---|
| CLIENT EXEMPLE | 101 | Mensuelle | TVA | Oui | Déclaration mensuelle |

Prévisualisation avant import, signalement des lignes en erreur, détection des doublons par numéro de dossier, mise à jour des dossiers existants, sans création de doublons en cas de réimport.

---

## Sécurité

- Cookie de session `HttpOnly`, `Secure`, `SameSite=Strict` ; limitation des tentatives de connexion (15 par 15 minutes)
- Mots de passe hachés (Argon2) ; secrets CGI Loop chiffrés AES-256-GCM
- En-têtes de sécurité via Helmet ; connexion PostgreSQL vérifiée en production
- Verrouillage optimiste (`version`) contre les modifications simultanées
- Contrainte `UNIQUE (recurring_template_id, occurrence_key)` : aucune occurrence en double, même avec plusieurs processus
- Journal d’audit de toutes les actions sensibles
- Sauvegardes chiffrées au repos du volume : à placer sur un volume chiffré

---

## État du projet et à compléter

Le serveur fourni couvre l’authentification, les droits, la lecture de l’état partagé, la mise à jour des tâches, la synchronisation CGI Loop, la génération des récurrences, le temps réel, l’audit et les sauvegardes. Il reste à ajouter côté serveur :

- création, duplication, archivage et suppression de tâches, et gestion des collaborateurs associés ;
- création et modification des récurrences (avec début et fin) ;
- commentaires, historique par tâche et notifications ;
- circuit de validation par validateur désigné (aujourd’hui contrôlé par rôle uniquement) ;
- import Excel des dossiers (colonnes `periode`, `type`, `ebic`, `commentaire` à ajouter au schéma `dossiers`) ;
- création et gestion des utilisateurs ;
- limitation de l’accès aux sauvegardes (`pg_dump` reçoit `DATABASE_URL` en argument, visible dans la liste des processus : préférer `PGPASSFILE` ou les variables `PG*`).

Un prototype fonctionnel de l’interface, avec base partagée hébergée par claude.ai, a servi de maquette de référence pour ces fonctionnalités.

---

## Licence

Usage interne du cabinet. À définir.
