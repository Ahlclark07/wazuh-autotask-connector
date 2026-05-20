import fs from "node:fs";
import { ingestAlert } from "../soc/ingest.js";

const SOURCE = "wazuh-alerts-json";

export function startAlertTail({ config, store, logger = console }) {
  const tail = new AlertTail({ config, store, logger });
  tail.start();
  return tail;
}

class AlertTail {
  constructor({ config, store, logger }) {
    this.config = config;
    this.store = store;
    this.logger = logger;
    this.filePath = config.wazuh.alerts_file;
    this.pollIntervalMs = config.wazuh.poll_interval_ms || 1000;
    this.startFrom = config.wazuh.tail_start_from || "end";
    this.timer = null;
    this.running = false;
    this.reading = false;
    this.state = null;
  }

  start() {
    if (this.running) return;
    this.running = true;
    this.initializeState();
    this.timer = setInterval(() => {
      this.tick().catch((error) => {
        this.logger.error(`[alerts-tail] ${error.message}`);
      });
    }, this.pollIntervalMs);
    this.logger.log(`[alerts-tail] watching ${this.filePath}`);
  }

  stop() {
    this.running = false;
    if (this.timer) clearInterval(this.timer);
  }

  initializeState() {
    const saved = this.store.getIngestState(SOURCE);
    const stats = this.safeStat();

    if (!stats) {
      this.state = {
        source: SOURCE,
        file_path: this.filePath,
        inode: null,
        offset: 0,
        partial_line: ""
      };
      this.saveState();
      this.logger.warn(`[alerts-tail] file not found yet: ${this.filePath}`);
      return;
    }

    const inode = inodeOf(stats);
    const canResume =
      saved &&
      saved.file_path === this.filePath &&
      saved.inode === inode &&
      saved.offset <= stats.size;

    this.state = {
      source: SOURCE,
      file_path: this.filePath,
      inode,
      offset: canResume ? saved.offset : this.initialOffset(stats),
      partial_line: canResume ? saved.partial_line || "" : ""
    };
    this.saveState();
  }

  async tick() {
    if (this.reading) return;
    this.reading = true;
    try {
      await this.readNewBytes();
    } finally {
      this.reading = false;
    }
  }

  async readNewBytes() {
    const stats = this.safeStat();
    if (!stats) return;

    const inode = inodeOf(stats);
    if (this.state.inode !== inode || stats.size < this.state.offset) {
      this.logger.log("[alerts-tail] rotation or truncation detected");
      this.state.inode = inode;
      this.state.offset = 0;
      this.state.partial_line = "";
      this.saveState();
    }

    if (stats.size <= this.state.offset) return;

    const startOffset = this.state.offset;
    const stream = fs.createReadStream(this.filePath, {
      start: startOffset,
      end: stats.size - 1,
      encoding: "utf8"
    });

    let buffer = this.state.partial_line || "";
    let bytesRead = 0;

    for await (const chunk of stream) {
      bytesRead += Buffer.byteLength(chunk, "utf8");
      buffer += chunk;

      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() || "";

      for (const line of lines) {
        this.ingestLine(line);
      }
    }

    this.state.offset = startOffset + bytesRead;
    this.state.partial_line = buffer;
    this.saveState();
  }

  ingestLine(line) {
    const trimmed = line.trim();
    if (!trimmed) return;

    try {
      const result = ingestAlert({
        alert: JSON.parse(trimmed),
        store: this.store,
        config: this.config
      });
      this.logger.log(
        `[alerts-tail] ingested event=${result.event_id} source="${result.source}" severity=${result.severity}`
      );
    } catch (error) {
      this.logger.error(`[alerts-tail] failed to ingest line: ${error.message}`);
    }
  }

  safeStat() {
    try {
      return fs.statSync(this.filePath);
    } catch (error) {
      if (error.code !== "ENOENT") {
        this.logger.error(`[alerts-tail] stat failed: ${error.message}`);
      }
      return null;
    }
  }

  initialOffset(stats) {
    return this.startFrom === "beginning" ? 0 : stats.size;
  }

  saveState() {
    this.store.upsertIngestState(this.state);
  }
}

function inodeOf(stats) {
  return String(stats.ino || `${stats.dev}:${stats.size}:${stats.mtimeMs}`);
}
