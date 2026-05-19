import { getPath } from "./get-path.js";
import { severityFromRuleLevel } from "./severity.js";

export function normalizeAlert(alert, clientMapping) {
  const ruleId = String(getPath(alert, "rule.id", ""));
  const ruleLevel = Number.parseInt(getPath(alert, "rule.level", 0), 10);
  const decoder = getPath(alert, "decoder.name", "");
  const source = detectSource(alert);
  const assetHostname = detectHostname(alert);
  const assetIp = detectIp(alert);

  return {
    alert_id: getPath(alert, "id"),
    timestamp: normalizeTimestamp(getPath(alert, "timestamp")),
    client_key: clientMapping.clientKey,
    source,
    severity: severityFromRuleLevel(ruleLevel),
    rule_id: ruleId || null,
    rule_level: Number.isFinite(ruleLevel) ? ruleLevel : null,
    title: buildTitle(alert, source),
    dedup_key: buildDedupKey(alert, source, ruleId, assetHostname, assetIp),
    action: actionForClientMapping(clientMapping),
    ticket_id: null,
    asset_hostname: assetHostname,
    asset_ip: assetIp,
    raw_alert_json: JSON.stringify(alert)
  };
}

export function endpointFromEvent(event, alert) {
  const agentId = getPath(alert, "agent.id");
  const key =
    agentId && agentId !== "000"
      ? `wazuh-agent:${agentId}`
      : event.asset_hostname
        ? `hostname:${event.asset_hostname.toLowerCase()}`
        : event.asset_ip
          ? `ip:${event.asset_ip}`
          : null;

  if (!key) return null;

  return {
    endpoint_key: key,
    client_key: event.client_key,
    wazuh_agent_id: agentId,
    hostname: event.asset_hostname,
    ip: event.asset_ip,
    os_name: getPath(alert, "agent.os.name"),
    status: "active",
    last_seen: event.timestamp,
    last_alert_at: event.timestamp,
    alert_count: 1,
    max_severity: event.severity,
    source: "alerts.json",
    raw_json: JSON.stringify({
      agent: getPath(alert, "agent", {}),
      manager: getPath(alert, "manager", {})
    })
  };
}

function detectSource(alert) {
  const decoder = String(getPath(alert, "decoder.name", ""));
  const groups = getPath(alert, "rule.groups", []);
  const integration = getPath(alert, "data.integration");

  if (decoder === "gravityzone" || groups.includes("bitdefender-GZ")) {
    return "Bitdefender GravityZone";
  }
  if (decoder.startsWith("watchguard-firebox") || groups.includes("watchguard")) {
    return "WatchGuard";
  }
  if (integration === "qualys_vmdr" || groups.includes("qualys_vmdr")) {
    return "Qualys VMDR";
  }
  if (decoder === "windows_eventchannel") {
    return "Windows EventChannel";
  }
  return "Wazuh";
}

function detectHostname(alert) {
  const agentId = getPath(alert, "agent.id");
  const agentName = getPath(alert, "agent.name");

  return (
    getPath(alert, "data.DeviceHostName") ||
    getPath(alert, "data.win.system.computer") ||
    (agentId && agentId !== "000" ? agentName : null) ||
    null
  );
}

function detectIp(alert) {
  const source = detectSource(alert);
  const agentId = getPath(alert, "agent.id");

  if (source === "Bitdefender GravityZone") {
    return getPath(alert, "data.DeviceIP") || null;
  }

  if (source === "Qualys VMDR") {
    return getPath(alert, "data.asset_ip") || null;
  }

  if (source === "WatchGuard") {
    return getPath(alert, "data.srcip") || getPath(alert, "data.dstip") || null;
  }

  return (
    getPath(alert, "data.DeviceIP") ||
    getPath(alert, "data.asset_ip") ||
    (agentId && agentId !== "000" ? getPath(alert, "agent.ip") : null) ||
    null
  );
}

function buildTitle(alert, source) {
  const data = getPath(alert, "data", {});
  const ruleDescription = getPath(alert, "rule.description", "Wazuh alert");

  if (source === "Bitdefender GravityZone") {
    return `Bitdefender malware: ${data.MalwareName || "unknown"} on ${
      data.DeviceHostName || "unknown host"
    }`;
  }

  if (source === "Qualys VMDR") {
    return `Qualys ${data.risk_tier || "finding"}: ${
      data.title || "unknown vulnerability"
    } on ${data.asset_ip || "unknown asset"}`;
  }

  if (source === "WatchGuard") {
    return `WatchGuard: ${ruleDescription}`;
  }

  return ruleDescription;
}

function buildDedupKey(alert, source, ruleId, hostname, ip) {
  const data = getPath(alert, "data", {});

  if (source === "Bitdefender GravityZone") {
    return [
      "bitdefender",
      ruleId,
      data.DeviceHostName || hostname,
      data.MalwareHash,
      data.FilePath
    ]
      .filter(Boolean)
      .join(":");
  }

  if (source === "Qualys VMDR") {
    return ["qualys", data.asset_ip || ip, data.qid, data.qualys_status]
      .filter(Boolean)
      .join(":");
  }

  if (source === "WatchGuard") {
    return ["watchguard", ruleId, data.srcip, data.dstip, data.protocol]
      .filter(Boolean)
      .join(":");
  }

  return ["wazuh", ruleId, hostname, ip].filter(Boolean).join(":");
}

function actionForClientMapping(clientMapping) {
  if (clientMapping.status === "matched") return "report_only";
  if (clientMapping.status === "ambiguous") return "skipped_ambiguous_client";
  return "skipped_missing_client";
}

function normalizeTimestamp(value) {
  const date = value ? new Date(value) : new Date();
  if (Number.isNaN(date.getTime())) return new Date().toISOString();
  return date.toISOString();
}
