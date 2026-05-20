# Wazuh Autotask Connector

API SOC en JavaScript pour centraliser les données Wazuh avant de brancher la
création de tickets Autotask.

## Périmètre Actuel

Le premier jalon est en mode observation uniquement :

- ingérer les alertes Wazuh normalisées depuis `alerts.json`
- stocker les evenements SOC dans SQLite
- maintenir une table d'endpoints
- exposer des endpoints JSON utilisables par un dashboard
- synchroniser optionnellement les agents via la Wazuh Server API

La creation de tickets Autotask n'est pas encore implementee volontairement.
On stabilise d'abord le modele dashboard/SOC.

## Installation

```bash
npm install
cp config.example.yaml config.yaml
npm run ingest:sample
npm start
```

API par defaut :

```text
http://127.0.0.1:3080
```

En developpement, utiliser `nodemon` pour redemarrer automatiquement l'API et
voir les logs HTTP dans le terminal :

```bash
npm run dev
```

## API

```text
GET  /health
GET  /api/soc/overview?range_hours=24
GET  /api/soc/events?limit=100
GET  /api/soc/endpoints
GET  /api/soc/clients?range_hours=24
GET  /api/soc/sources?range_hours=24
GET  /api/soc/ingest-state
POST /api/ingest/alert
POST /api/sync/wazuh/agents
```

## Sources De Donnees

Utiliser `alerts.json` pour le flux d'evenements SOC :

```text
/var/ossec/logs/alerts/alerts.json
```

Ce fichier sert au dashboard pour le volume d'alertes, les sévérites, les
sources, le mapping client, les endpoints touchés et le flux des évènements
notables. Il ne sert pas uniquement a créer des tickets.

Utiliser la Wazuh Server API pour l'etat des endpoints :

```text
GET /agents
GET /agents/summary/status
GET /agents/summary/os
GET /syscollector/{agent_id}/os
GET /syscollector/{agent_id}/hardware
GET /syscollector/{agent_id}/netaddr
GET /syscollector/{agent_id}/packages
GET /syscollector/{agent_id}/ports
GET /syscollector/{agent_id}/services
```

Utiliser le Wazuh indexer plus tard pour les recherches historiques lourdes,
les vulnerabilites et les analytics si les appels directs deviennent trop lents.

## ingérer Des Alertes Existantes

```bash
npm run ingest:file -- /var/ossec/logs/alerts/alerts.json
```

## Activer Le Live Tail

Dans `config.yaml` :

```yaml
wazuh:
  live_enabled: true
  alerts_file: /var/ossec/logs/alerts/alerts.json
  tail_start_from: end
  poll_interval_ms: 1000
```

Puis lancer l'API :

```bash
npm run dev
```

Verifier l'etat du tail :

```bash
curl http://127.0.0.1:3080/api/soc/ingest-state | jq .
```

## Synchroniser Les Agents Wazuh

Activer la configuration Wazuh API dans `config.yaml`.

Option simple en dev, avec identifiants directement dans `config.yaml` :

```yaml
wazuh:
  api:
    enabled: true
    base_url: https://127.0.0.1:55000
    username: wazuh
    password: changeme
    reject_unauthorized: false
```

Ne pas committer `config.yaml` avec de vrais identifiants. Le fichier est ignore
par Git.

Option environnement :

```yaml
wazuh:
  api:
    enabled: true
    base_url: https://127.0.0.1:55000
    username_env: WAZUH_API_USERNAME
    password_env: WAZUH_API_PASSWORD
    reject_unauthorized: false
```

Puis :

```bash
export WAZUH_API_USERNAME=...
export WAZUH_API_PASSWORD=...
```

Appeler ensuite l'endpoint de synchronisation :

```bash
curl -X POST http://127.0.0.1:3080/api/sync/wazuh/agents
```

## Stack

- Node.js 20+
- JavaScript pur
- Express pour l'API HTTP
- Logs HTTP avec `morgan`
- Redemarrage dev avec `nodemon`
- SQLite via `better-sqlite3`
- YAML pour la configuration
