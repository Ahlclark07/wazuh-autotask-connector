import http from "node:http";
import { URL } from "node:url";
import { ingestAlert } from "./soc/ingest.js";
import { createWazuhClient } from "./wazuh/client.js";
import { syncWazuhAgents } from "./wazuh/sync.js";

export function createServer({ config, store, startedAt }) {
  return http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, `http://${req.headers.host}`);
      const route = `${req.method} ${url.pathname}`;

      if (route === "GET /health") {
        return sendJson(res, 200, {
          ok: true,
          mode: "observe-only",
          uptime_seconds: Math.round((Date.now() - startedAt.getTime()) / 1000),
          started_at: startedAt.toISOString(),
          db_path: config.storage.db_path
        });
      }

      if (route === "GET /api/soc/overview") {
        return sendJson(res, 200, store.getOverview(getRangeHours(url, config)));
      }

      if (route === "GET /api/soc/events") {
        return sendJson(res, 200, {
          items: store.listEvents({
            limit: getInt(url, "limit", 100, 1, 500),
            clientKey: url.searchParams.get("client_key"),
            source: url.searchParams.get("source"),
            severity: url.searchParams.get("severity")
          })
        });
      }

      if (route === "GET /api/soc/endpoints") {
        return sendJson(res, 200, {
          items: store.listEndpoints({
            limit: getInt(url, "limit", 250, 1, 1000),
            clientKey: url.searchParams.get("client_key"),
            status: url.searchParams.get("status")
          })
        });
      }

      if (route === "GET /api/soc/clients") {
        return sendJson(res, 200, {
          items: store.listClientSummaries(getRangeHours(url, config))
        });
      }

      if (route === "GET /api/soc/sources") {
        return sendJson(res, 200, {
          items: store.listSourceSummaries(getRangeHours(url, config))
        });
      }

      if (route === "POST /api/ingest/alert") {
        const alert = await readJson(req);
        const result = ingestAlert({ alert, store, config });
        return sendJson(res, 202, result);
      }

      if (route === "POST /api/sync/wazuh/agents") {
        const wazuh = createWazuhClient(config.wazuh.api);
        const result = await syncWazuhAgents({ wazuh, store, config });
        return sendJson(res, 200, result);
      }

      return sendJson(res, 404, { error: "not_found" });
    } catch (error) {
      const status = error.statusCode || 500;
      return sendJson(res, status, {
        error: status === 500 ? "internal_error" : error.code || "bad_request",
        message: error.message
      });
    }
  });
}

function getRangeHours(url, config) {
  return getInt(
    url,
    "range_hours",
    config.dashboard.default_range_hours,
    1,
    24 * 90
  );
}

function getInt(url, key, fallback, min, max) {
  const raw = url.searchParams.get(key);
  const value = raw === null ? fallback : Number.parseInt(raw, 10);
  if (!Number.isFinite(value)) return fallback;
  return Math.max(min, Math.min(max, value));
}

async function readJson(req) {
  const body = await readBody(req);
  try {
    return JSON.parse(body || "{}");
  } catch (error) {
    const wrapped = new Error(`Invalid JSON body: ${error.message}`);
    wrapped.statusCode = 400;
    wrapped.code = "invalid_json";
    throw wrapped;
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 2_000_000) {
        const error = new Error("Request body too large");
        error.statusCode = 413;
        reject(error);
        req.destroy();
      }
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store"
  });
  res.end(`${JSON.stringify(payload, null, 2)}\n`);
}
