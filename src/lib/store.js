import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";

export function openStore(dbPath) {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });

  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.function("severity_rank", (severity) => severityRank(severity));
  migrate(db);

  return {
    close: () => db.close(),
    insertEvent: buildInsertEvent(db),
    upsertEndpoint: buildUpsertEndpoint(db),
    getOverview: buildGetOverview(db),
    listEvents: buildListEvents(db),
    listEndpoints: buildListEndpoints(db),
    listClientSummaries: buildListClientSummaries(db),
    listSourceSummaries: buildListSourceSummaries(db)
  };
}

function migrate(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS soc_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      alert_id TEXT,
      timestamp TEXT NOT NULL,
      client_key TEXT,
      source TEXT NOT NULL,
      severity TEXT NOT NULL,
      rule_id TEXT,
      rule_level INTEGER,
      title TEXT NOT NULL,
      dedup_key TEXT,
      action TEXT NOT NULL,
      ticket_id TEXT,
      asset_hostname TEXT,
      asset_ip TEXT,
      raw_alert_json TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );

    CREATE INDEX IF NOT EXISTS idx_soc_events_timestamp ON soc_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_soc_events_client ON soc_events(client_key);
    CREATE INDEX IF NOT EXISTS idx_soc_events_source ON soc_events(source);
    CREATE INDEX IF NOT EXISTS idx_soc_events_severity ON soc_events(severity);
    CREATE INDEX IF NOT EXISTS idx_soc_events_dedup ON soc_events(dedup_key);

    CREATE TABLE IF NOT EXISTS endpoints (
      endpoint_key TEXT PRIMARY KEY,
      client_key TEXT,
      wazuh_agent_id TEXT,
      hostname TEXT,
      ip TEXT,
      os_name TEXT,
      status TEXT,
      last_seen TEXT,
      last_alert_at TEXT,
      alert_count INTEGER NOT NULL DEFAULT 0,
      max_severity TEXT,
      source TEXT NOT NULL,
      raw_json TEXT,
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );

    CREATE INDEX IF NOT EXISTS idx_endpoints_client ON endpoints(client_key);
    CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status);
    CREATE INDEX IF NOT EXISTS idx_endpoints_last_seen ON endpoints(last_seen);
  `);
}

function buildInsertEvent(db) {
  const insert = db.prepare(`
    INSERT INTO soc_events (
      alert_id,
      timestamp,
      client_key,
      source,
      severity,
      rule_id,
      rule_level,
      title,
      dedup_key,
      action,
      ticket_id,
      asset_hostname,
      asset_ip,
      raw_alert_json
    ) VALUES (
      @alert_id,
      @timestamp,
      @client_key,
      @source,
      @severity,
      @rule_id,
      @rule_level,
      @title,
      @dedup_key,
      @action,
      @ticket_id,
      @asset_hostname,
      @asset_ip,
      @raw_alert_json
    )
  `);

  return (event) => {
    const result = insert.run(toNullableRecord(event));
    return result.lastInsertRowid;
  };
}

function buildUpsertEndpoint(db) {
  const statement = db.prepare(`
    INSERT INTO endpoints (
      endpoint_key,
      client_key,
      wazuh_agent_id,
      hostname,
      ip,
      os_name,
      status,
      last_seen,
      last_alert_at,
      alert_count,
      max_severity,
      source,
      raw_json,
      updated_at
    ) VALUES (
      @endpoint_key,
      @client_key,
      @wazuh_agent_id,
      @hostname,
      @ip,
      @os_name,
      @status,
      @last_seen,
      @last_alert_at,
      @alert_count,
      @max_severity,
      @source,
      @raw_json,
      strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    )
    ON CONFLICT(endpoint_key) DO UPDATE SET
      client_key = COALESCE(excluded.client_key, endpoints.client_key),
      wazuh_agent_id = COALESCE(excluded.wazuh_agent_id, endpoints.wazuh_agent_id),
      hostname = COALESCE(excluded.hostname, endpoints.hostname),
      ip = COALESCE(excluded.ip, endpoints.ip),
      os_name = COALESCE(excluded.os_name, endpoints.os_name),
      status = COALESCE(excluded.status, endpoints.status),
      last_seen = COALESCE(excluded.last_seen, endpoints.last_seen),
      last_alert_at = COALESCE(excluded.last_alert_at, endpoints.last_alert_at),
      alert_count = endpoints.alert_count + excluded.alert_count,
      max_severity = CASE
        WHEN severity_rank(excluded.max_severity) > severity_rank(endpoints.max_severity)
        THEN excluded.max_severity
        ELSE endpoints.max_severity
      END,
      source = excluded.source,
      raw_json = COALESCE(excluded.raw_json, endpoints.raw_json),
      updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
  `);

  return (endpoint) => statement.run(toNullableRecord(endpoint));
}

function buildGetOverview(db) {
  return (rangeHours) => {
    const params = { since: sinceIso(rangeHours) };
    const totals = db
      .prepare(
        `
        SELECT
          COUNT(*) AS total_events,
          SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical,
          SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high,
          SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) AS medium,
          SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) AS low,
          SUM(CASE WHEN severity = 'info' THEN 1 ELSE 0 END) AS info,
          COUNT(DISTINCT client_key) AS clients_touched,
          COUNT(DISTINCT COALESCE(asset_hostname, asset_ip)) AS endpoints_touched,
          MAX(timestamp) AS last_event_at
        FROM soc_events
        WHERE timestamp >= @since
      `
      )
      .get(params);

    const endpointSummary = db
      .prepare(
        `
        SELECT
          COUNT(*) AS total_endpoints,
          SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active,
          SUM(CASE WHEN status = 'disconnected' THEN 1 ELSE 0 END) AS disconnected,
          SUM(CASE WHEN status IS NULL OR status = '' THEN 1 ELSE 0 END) AS unknown
        FROM endpoints
      `
      )
      .get();

    return {
      range_hours: rangeHours,
      since: params.since,
      events: totals,
      endpoints: endpointSummary
    };
  };
}

function buildListEvents(db) {
  return ({ limit, clientKey, source, severity }) => {
    const clauses = [];
    const params = { limit };
    if (clientKey) {
      clauses.push("client_key = @clientKey");
      params.clientKey = clientKey;
    }
    if (source) {
      clauses.push("source = @source");
      params.source = source;
    }
    if (severity) {
      clauses.push("severity = @severity");
      params.severity = severity;
    }

    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    return db
      .prepare(
        `
        SELECT *
        FROM soc_events
        ${where}
        ORDER BY timestamp DESC, id DESC
        LIMIT @limit
      `
      )
      .all(params);
  };
}

function buildListEndpoints(db) {
  return ({ limit, clientKey, status }) => {
    const clauses = [];
    const params = { limit };
    if (clientKey) {
      clauses.push("client_key = @clientKey");
      params.clientKey = clientKey;
    }
    if (status) {
      clauses.push("status = @status");
      params.status = status;
    }

    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    return db
      .prepare(
        `
        SELECT *
        FROM endpoints
        ${where}
        ORDER BY
          CASE status
            WHEN 'active' THEN 0
            WHEN 'disconnected' THEN 1
            ELSE 2
          END,
          COALESCE(last_seen, last_alert_at, updated_at) DESC
        LIMIT @limit
      `
      )
      .all(params);
  };
}

function buildListClientSummaries(db) {
  return (rangeHours) => {
    return db
      .prepare(
        `
        SELECT
          COALESCE(client_key, 'unmapped') AS client_key,
          COUNT(*) AS total_events,
          SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS important_events,
          COUNT(DISTINCT COALESCE(asset_hostname, asset_ip)) AS endpoints_touched,
          MAX(timestamp) AS last_event_at
        FROM soc_events
        WHERE timestamp >= @since
        GROUP BY COALESCE(client_key, 'unmapped')
        ORDER BY important_events DESC, total_events DESC
      `
      )
      .all({ since: sinceIso(rangeHours) });
  };
}

function buildListSourceSummaries(db) {
  return (rangeHours) => {
    return db
      .prepare(
        `
        SELECT
          source,
          COUNT(*) AS total_events,
          SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS important_events,
          MAX(timestamp) AS last_event_at
        FROM soc_events
        WHERE timestamp >= @since
        GROUP BY source
        ORDER BY important_events DESC, total_events DESC
      `
      )
      .all({ since: sinceIso(rangeHours) });
  };
}

function toNullableRecord(record) {
  return Object.fromEntries(
    Object.entries(record).map(([key, value]) => [key, value ?? null])
  );
}

function sinceIso(rangeHours) {
  return new Date(Date.now() - rangeHours * 60 * 60 * 1000).toISOString();
}

function severityRank(severity) {
  return {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
  }[severity] ?? -1;
}
