function normalize(value) {
  return String(value || "").trim().toLowerCase();
}

export function mapClientFromEndpoint(agent, config) {
  const clients = config.clients || [];
  const matches = clients.filter((client) => endpointMatchesClient(agent, client));
  return matches.length === 1 ? matches[0].key : null;
}

function endpointMatchesClient(agent, client) {
  const match = client.match || {};
  const agentName = normalize(agent.name);
  const agentId = String(agent.id || "");
  const agentIp = String(agent.ip || "");

  if ((match.wazuh_agent_ids || []).some((id) => String(id) === agentId)) {
    return true;
  }

  if (
    (match.wazuh_agent_names || [])
      .map(normalize)
      .some((name) => name === agentName)
  ) {
    return true;
  }

  if ((match.hostnames || []).map(normalize).some((name) => name === agentName)) {
    return true;
  }

  if ((match.ips || []).some((ip) => String(ip) === agentIp)) {
    return true;
  }

  if ((match.ip_ranges || []).some((cidr) => ipInCidr(agentIp, cidr))) {
    return true;
  }

  return false;
}

function ipInCidr(ip, cidr) {
  const [range, bitsRaw] = String(cidr).split("/");
  const bits = Number.parseInt(bitsRaw, 10);
  const ipNumber = ipv4ToNumber(ip);
  const rangeNumber = ipv4ToNumber(range);

  if (ipNumber === null || rangeNumber === null || !Number.isFinite(bits)) {
    return false;
  }

  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipNumber & mask) === (rangeNumber & mask);
}

function ipv4ToNumber(value) {
  const parts = String(value).split(".").map((part) => Number.parseInt(part, 10));
  if (parts.length !== 4 || parts.some((part) => part < 0 || part > 255)) {
    return null;
  }
  return parts.reduce((acc, part) => ((acc << 8) + part) >>> 0, 0);
}
