import express from "express";
import morgan from "morgan";
import { ingestAlert } from "./soc/ingest.js";
import { createWazuhClient } from "./wazuh/client.js";
import { syncWazuhAgents } from "./wazuh/sync.js";

export function createServer({ config, store, startedAt }) {
  const app = express();

  app.use(morgan("dev"));
  app.use(express.json({ limit: "2mb" }));
  app.use((_req, res, next) => {
    res.setHeader("cache-control", "no-store");
    next();
  });

  app.get("/health", (_req, res) => {
    res.json({
      ok: true,
      mode: "observe-only",
      uptime_seconds: Math.round((Date.now() - startedAt.getTime()) / 1000),
      started_at: startedAt.toISOString(),
      db_path: config.storage.db_path,
      wazuh_live_enabled: Boolean(config.wazuh.live_enabled)
    });
  });

  app.get("/api/soc/overview", (req, res) => {
    res.json(store.getOverview(getRangeHours(req.query, config)));
  });

  app.get("/api/soc/events", (req, res) => {
    res.json({
      items: store.listEvents({
        limit: getInt(req.query, "limit", 100, 1, 500),
        clientKey: req.query.client_key,
        source: req.query.source,
        severity: req.query.severity
      })
    });
  });

  app.get("/api/soc/endpoints", (req, res) => {
    res.json({
      items: store.listEndpoints({
        limit: getInt(req.query, "limit", 250, 1, 1000),
        clientKey: req.query.client_key,
        status: req.query.status
      })
    });
  });

  app.get("/api/soc/clients", (req, res) => {
    res.json({
      items: store.listClientSummaries(getRangeHours(req.query, config))
    });
  });

  app.get("/api/soc/sources", (req, res) => {
    res.json({
      items: store.listSourceSummaries(getRangeHours(req.query, config))
    });
  });

  app.get("/api/soc/ingest-state", (_req, res) => {
    res.json({
      items: store.listIngestStates()
    });
  });

  app.post("/api/ingest/alert", (req, res) => {
    const result = ingestAlert({ alert: req.body || {}, store, config });
    res.status(202).json(result);
  });

  app.post("/api/sync/wazuh/agents", async (_req, res, next) => {
    try {
      const wazuh = createWazuhClient(config.wazuh.api);
      const result = await syncWazuhAgents({ wazuh, store, config });
      res.json(result);
    } catch (error) {
      next(error);
    }
  });

  app.use((_req, res) => {
    res.status(404).json({ error: "not_found" });
  });

  app.use((error, _req, res, _next) => {
    const statusCode = error.statusCode || error.status || 500;
    res.status(statusCode).json({
      error: statusCode === 500 ? "internal_error" : error.code || "bad_request",
      message: error.message
    });
  });

  return app;
}

function getRangeHours(query, config) {
  return getInt(
    query,
    "range_hours",
    config.dashboard.default_range_hours,
    1,
    24 * 90
  );
}

function getInt(query, key, fallback, min, max) {
  const raw = query?.[key];
  const value = raw === undefined ? fallback : Number.parseInt(raw, 10);
  if (!Number.isFinite(value)) return fallback;
  return Math.max(min, Math.min(max, value));
}
