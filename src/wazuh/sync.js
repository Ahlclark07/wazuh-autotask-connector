import { mapClientFromEndpoint } from "./sync-client-mapper.js";

export async function syncWazuhAgents({ wazuh, store, config }) {
  const data = await wazuh.listAgents();
  const agents = data.affected_items || data.items || [];

  for (const agent of agents) {
    const endpoint = normalizeAgent(agent, mapClientFromEndpoint(agent, config));
    store.upsertEndpoint(endpoint);
  }

  return {
    ok: true,
    synced_agents: agents.length
  };
}

function normalizeAgent(agent, clientKey) {
  const endpointKey =
    agent.id && agent.id !== "000"
      ? `wazuh-agent:${agent.id}`
      : `hostname:${String(agent.name || "manager").toLowerCase()}`;

  return {
    endpoint_key: endpointKey,
    client_key: clientKey,
    wazuh_agent_id: agent.id,
    hostname: agent.name,
    ip: agent.ip,
    os_name: agent.os?.name,
    status: normalizeStatus(agent.status),
    last_seen: normalizeLastSeen(agent),
    last_alert_at: null,
    alert_count: 0,
    max_severity: null,
    source: "wazuh-api",
    raw_json: JSON.stringify(agent)
  };
}

function normalizeStatus(status) {
  if (status === "active") return "active";
  if (status === "disconnected") return "disconnected";
  if (status === "never_connected") return "never_connected";
  return status || "unknown";
}

function normalizeLastSeen(agent) {
  if (agent.id === "000" && String(agent.lastKeepAlive || "").startsWith("9999-")) {
    return agent.dateAdd || null;
  }

  return agent.lastKeepAlive || agent.dateAdd || null;
}
