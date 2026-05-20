import { loadConfig } from "../src/lib/config.js";
import { openStore } from "../src/lib/store.js";
import { ingestAlert } from "../src/soc/ingest.js";

const config = loadConfig();
const store = openStore(config.storage.db_path);

const samples = [
  {
    timestamp: new Date().toISOString(),
    id: "sample-bitdefender-1",
    rule: {
      id: "100601",
      level: 10,
      description: "Bitdefender GravityZone malware detection",
      groups: ["bitdefender-GZ"]
    },
    agent: {
      id: "001",
      name: "CLIENTA-PC01",
      ip: "192.168.10.25"
    },
    decoder: {
      name: "gravityzone"
    },
    data: {
      DeviceHostName: "CLIENTA-PC01",
      DeviceIP: "192.168.10.25",
      MalwareName: "EICAR-Test-File",
      MalwareHash: "samplehash",
      Action: "deleted",
      FilePath: "C:\\Users\\demo\\Desktop\\eicar.txt"
    },
    location: "bitdefender"
  },
  {
    timestamp: new Date().toISOString(),
    id: "sample-watchguard-1",
    rule: {
      id: "191067",
      level: 10,
      description: "Multiple denied traffic from same source",
      groups: ["watchguard"]
    },
    agent: {
      id: "000",
      name: "soc-server",
      ip: "192.168.14.128"
    },
    decoder: {
      name: "watchguard-firebox"
    },
    data: {
      action: "Deny",
      srcip: "10.0.1.2",
      dstip: "10.0.1.1",
      protocol: "icmp",
      reason: "test"
    },
    location: "watchguard"
  },
  {
    timestamp: new Date().toISOString(),
    id: "sample-qualys-1",
    rule: {
      id: "100701",
      level: 13,
      description: "Critical internet-facing vulnerability",
      groups: ["qualys_vmdr"]
    },
    agent: {
      id: "000",
      name: "soc-server",
      ip: "192.168.14.128"
    },
    decoder: {
      name: "json"
    },
    data: {
      integration: "qualys_vmdr",
      risk_tier: "critical",
      internet_facing: "true",
      asset_ip: "192.0.2.10",
      qid: "12345",
      title: "Example vulnerability",
      qualys_status: "New"
    },
    location: "qualys"
  }
];

try {
  const results = samples.map((alert) => ingestAlert({ alert, store, config }));
  console.log(JSON.stringify({ ok: true, results }, null, 2));
} finally {
  store.close();
}
