import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";

const DEFAULT_CONFIG = {
  server: {
    host: "127.0.0.1",
    port: 3080
  },
  storage: {
    db_path: "./data/soc.sqlite"
  },
  wazuh: {
    alerts_file: "/var/ossec/logs/alerts/alerts.json",
    api: {
      enabled: false,
      base_url: "https://127.0.0.1:55000",
      username_env: "WAZUH_API_USERNAME",
      password_env: "WAZUH_API_PASSWORD",
      reject_unauthorized: false
    }
  },
  dashboard: {
    default_range_hours: 24
  },
  clients: []
};

export function loadConfig() {
  const configPath = process.env.CONNECTOR_CONFIG || "./config.yaml";
  const source = fs.existsSync(configPath)
    ? YAML.parse(fs.readFileSync(configPath, "utf8"))
    : {};

  const config = merge(DEFAULT_CONFIG, source || {});
  config.storage.db_path = path.resolve(config.storage.db_path);
  config.server.port = Number.parseInt(config.server.port, 10);

  return config;
}

function merge(base, override) {
  if (Array.isArray(base) || Array.isArray(override)) {
    return override === undefined ? base : override;
  }

  if (isPlainObject(base) && isPlainObject(override)) {
    const result = { ...base };
    for (const [key, value] of Object.entries(override)) {
      result[key] = merge(base[key], value);
    }
    return result;
  }

  return override === undefined ? base : override;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
