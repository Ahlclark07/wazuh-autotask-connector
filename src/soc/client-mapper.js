import { getPath } from "./get-path.js";

export function mapClient(alert, config) {
  const candidates = config.clients || [];
  const evidence = collectEvidence(alert);
  const matches = candidates.filter((client) => clientMatches(client, evidence));

  if (matches.length === 1) {
    return {
      clientKey: matches[0].key,
      status: "matched",
      reason: "single_match"
    };
  }

  if (matches.length > 1) {
    return {
      clientKey: null,
      status: "ambiguous",
      reason: "multiple_matches",
      matches: matches.map((client) => client.key)
    };
  }

  return {
    clientKey: null,
    status: "unmapped",
    reason: "no_match"
  };
}

function collectEvidence(alert) {
  return {
    agentId: getPath(alert, "agent.id"),
    names: normalizeList([
      getPath(alert, "agent.name"),
      getPath(alert, "data.DeviceHostName"),
      getPath(alert, "data.win.system.computer")
    ]),
    ips: normalizeList([
      getPath(alert, "agent.ip"),
      getPath(alert, "data.DeviceIP"),
      getPath(alert, "data.asset_ip"),
      getPath(alert, "data.srcip"),
      getPath(alert, "data.dstip")
    ]),
    location: getPath(alert, "location")
  };
}

function clientMatches(client, evidence) {
  const match = client.match || {};

  if (contains(match.wazuh_agent_ids, evidence.agentId)) return true;
  if (intersects(match.wazuh_agent_names, evidence.names)) return true;
  if (intersects(match.hostnames, evidence.names)) return true;
  if (intersects(match.ips, evidence.ips)) return true;

  if (Array.isArray(match.ip_ranges)) {
    for (const ip of evidence.ips) {
      if (match.ip_ranges.some((cidr) => ipInCidr(ip, cidr))) return true;
    }
  }

  if (Array.isArray(match.domains)) {
    for (const name of evidence.names) {
      if (
        match.domains.some((domain) =>
          name.toLowerCase().endsWith(`.${domain.toLowerCase()}`)
        )
      ) {
        return true;
      }
    }
  }

  if (Array.isArray(match.locations) && evidence.location) {
    return match.locations.some((location) =>
      evidence.location.toLowerCase().includes(location.toLowerCase())
    );
  }

  return false;
}

function normalizeList(values) {
  return values
    .filter(Boolean)
    .map((value) => String(value).trim())
    .filter(Boolean);
}

function contains(values, candidate) {
  if (!Array.isArray(values) || !candidate) return false;
  return values.some((value) => String(value) === String(candidate));
}

function intersects(left = [], right = []) {
  const normalized = new Set(left.map((value) => String(value).toLowerCase()));
  return right.some((value) => normalized.has(String(value).toLowerCase()));
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
