import { mapClient } from "./client-mapper.js";
import { endpointFromEvent, normalizeAlert } from "./normalizer.js";

export function ingestAlert({ alert, store, config }) {
  const clientMapping = mapClient(alert, config);
  const event = normalizeAlert(alert, clientMapping);
  const eventId = store.insertEvent(event);
  const endpoint = endpointFromEvent(event, alert);

  if (endpoint) {
    store.upsertEndpoint(endpoint);
  }

  return {
    ok: true,
    event_id: eventId,
    action: event.action,
    source: event.source,
    severity: event.severity,
    client_key: event.client_key,
    endpoint_key: endpoint?.endpoint_key || null
  };
}
