import fs from "node:fs";
import readline from "node:readline";
import { loadConfig } from "../src/lib/config.js";
import { openStore } from "../src/lib/store.js";
import { ingestAlert } from "../src/soc/ingest.js";

const filePath = process.argv[2];
if (!filePath) {
  console.error("Usage: npm run ingest:file -- /path/to/alerts.json");
  process.exit(1);
}

const config = loadConfig();
const store = openStore(config.storage.db_path);
let parsed = 0;
let failed = 0;

try {
  const stream = fs.createReadStream(filePath, { encoding: "utf8" });
  const lines = readline.createInterface({
    input: stream,
    crlfDelay: Infinity
  });

  for await (const line of lines) {
    if (!line.trim()) continue;
    try {
      ingestAlert({ alert: JSON.parse(line), store, config });
      parsed += 1;
    } catch (error) {
      failed += 1;
      console.error(`Failed to ingest line ${parsed + failed}: ${error.message}`);
    }
  }
} finally {
  store.close();
}

console.log(JSON.stringify({ ok: true, parsed, failed }, null, 2));
