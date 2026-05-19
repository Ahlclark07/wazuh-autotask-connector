# Wazuh Autotask Connector

SOC visibility API for Wazuh data, with Autotask ticketing planned after the
dashboard data model is stable.

## Current Scope

The first milestone is observe-only:

- ingest normalized Wazuh alerts from `alerts.json`
- store SOC events in SQLite
- keep an endpoint inventory table
- expose dashboard-friendly JSON endpoints
- optionally sync Wazuh agents from the Wazuh Server API

Ticket creation is intentionally not implemented yet.

## Setup

```bash
npm install
cp config.example.yaml config.yaml
npm run ingest:sample
npm start
```

API default:

```text
http://127.0.0.1:3080
```

## API

```text
GET  /health
GET  /api/soc/overview?range_hours=24
GET  /api/soc/events?limit=100
GET  /api/soc/endpoints
GET  /api/soc/clients?range_hours=24
GET  /api/soc/sources?range_hours=24
POST /api/ingest/alert
POST /api/sync/wazuh/agents
```

## Data Sources

Use `alerts.json` for SOC events:

```text
/var/ossec/logs/alerts/alerts.json
```

This gives the dashboard alert volume, severity, source, client mapping,
affected endpoint, and notable event stream.

Use the Wazuh Server API for endpoint state:

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

Use the Wazuh indexer later for heavier historical queries and vulnerability
state, if direct API calls become too slow for the dashboard.

## Ingest Existing Alerts

```bash
npm run ingest:file -- /var/ossec/logs/alerts/alerts.json
```

## Sync Wazuh Agents

Enable the Wazuh API config in `config.yaml`, set credentials in environment
variables, then call:

```bash
curl -X POST http://127.0.0.1:3080/api/sync/wazuh/agents
```

```bash
export WAZUH_API_USERNAME=...
export WAZUH_API_PASSWORD=...
```
