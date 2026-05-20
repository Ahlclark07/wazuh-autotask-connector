import { loadConfig } from "./lib/config.js";
import { openStore } from "./lib/store.js";
import { createServer } from "./server.js";
import { startAlertTail } from "./wazuh/alert-tail.js";

const config = loadConfig();
const store = openStore(config.storage.db_path);
const app = createServer({ config, store, startedAt: new Date() });
const alertTail = config.wazuh.live_enabled
  ? startAlertTail({ config, store })
  : null;
const server = app.listen(config.server.port, config.server.host, () => {
  console.log(
    `SOC API listening on http://${config.server.host}:${config.server.port}`
  );
});

const shutdown = () => {
  if (alertTail) alertTail.stop();
  server.close(() => {
    store.close();
    process.exit(0);
  });
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
