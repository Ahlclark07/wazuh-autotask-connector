import { Agent } from "undici";

export function createWazuhClient(apiConfig) {
  return new WazuhClient(apiConfig);
}

class WazuhClient {
  constructor(apiConfig) {
    this.config = apiConfig;
    this.token = null;
    this.dispatcher =
      apiConfig.reject_unauthorized === false
        ? new Agent({ connect: { rejectUnauthorized: false } })
        : undefined;
  }

  async listAgents() {
    return this.request("/agents?limit=10000");
  }

  async authenticate() {
    if (this.token) return this.token;

    const username = readCredential(this.config, "username", "username_env");
    const password = readCredential(this.config, "password", "password_env");
    const credentials = Buffer.from(`${username}:${password}`).toString("base64");
    const response = await fetch(
      `${trimSlash(this.config.base_url)}/security/user/authenticate?raw=true`,
      {
        method: "POST",
        headers: {
          authorization: `Basic ${credentials}`
        },
        dispatcher: this.dispatcher
      }
    );

    if (!response.ok) {
      throw new Error(`Wazuh authentication failed with HTTP ${response.status}`);
    }

    this.token = (await response.text()).trim();
    return this.token;
  }

  async request(endpoint) {
    const token = await this.authenticate();
    const response = await fetch(`${trimSlash(this.config.base_url)}${endpoint}`, {
      headers: {
        authorization: `Bearer ${token}`
      },
      dispatcher: this.dispatcher
    });

    const text = await response.text();
    const payload = text ? JSON.parse(text) : {};

    if (!response.ok || payload.error) {
      throw new Error(
        `Wazuh API request failed: ${response.status} ${JSON.stringify(payload)}`
      );
    }

    return payload.data || payload;
  }
}

function readCredential(config, directKey, envKey) {
  if (config[directKey]) {
    return config[directKey];
  }

  return readEnv(config[envKey], directKey);
}

function readEnv(name, label) {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `Missing Wazuh API ${label}. Set wazuh.api.${label} in config.yaml or environment variable ${name}`
    );
  }
  return value;
}

function trimSlash(value) {
  return String(value).replace(/\/+$/, "");
}
