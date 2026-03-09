/**
 * Mock Stratum V1 Pool — NyanMiner E2E Testing
 *
 * Replays known Bitcoin blocks for deterministic e2e testing.
 * The miner submits the exact known nonce, pool validates the hash
 * against the real block hash.
 *
 * Zero dependencies. Node built-in `net` + `crypto` only.
 * Share validation uses Node's OpenSSL SHA256 — fully independent
 * from the miner's nerdSHA256plus C implementation.
 *
 * Usage:
 *   node mock_pool.js [--block 125552] [--port 3333] [--diff 1e-4] [--timeout 120]
 *
 * Exits 0 on block found, exits 1 on timeout.
 */

const net = require("net");
const crypto = require("crypto");

// -- Known blocks library ----------------------------------------------------

const BLOCKS = {
  125552: {
    name: "Block 125552",
    extranonce1: "04f2b944",
    extranonce2_size: 4,
    known_extranonce2: "1a022a01",
    known_nonce: "9546a142",
    known_hash: "00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d",
    job: {
      id: "blk_125552",
      prevhash:
        "ab02cd818b9e567ee21793cddef299feb29ad444a41b85b8000008a300000000",
      coinb1:
        "01000000010000000000000000000000000000000000000000" +
        "000000000000000000000000ffffffff08",
      coinb2:
        "ffffffff014034152a01000000434104d879d5ef8b70cf0a" +
        "33925101b64429ad7eb370da8ad0b05c9cd60922c363a1ea" +
        "da85bcc2843b7378e226735048786c790b30b28438d22acf" +
        "ade24ef047b5f865ac00000000",
      merkle_branch: [
        "a1e197f9312b514b906dade27abf255ab0a12e9e24c6d5d7d3f8418dda5dc260",
        "5e996cc3307b11be5acab562575c583aba2f125ae82137bace5396db4b95aebf",
      ],
      version: "00000001",
      nbits:   "1a44b9f2",
      ntime:   "4dd7f5c7",
    },
  },
  100000: {
    name: "Block 100000",
    extranonce1: "044c8604",
    extranonce2_size: 4,
    known_extranonce2: "1b020602",
    known_nonce: "10572b0f",
    known_hash: "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506",
    job: {
      id: "blk_100000",
      prevhash:
        "1901125004612a1701c3a621d930d31d36b607df1fccc2160002d01c00000000",
      coinb1:
        "01000000010000000000000000000000000000000000000000" +
        "000000000000000000000000ffffffff08",
      coinb2:
        "ffffffff0100f2052a010000004341041b0e8c2567c12536" +
        "aa13357b79a073dc4444acb83c4ec7a0e2f99dd7457516c5" +
        "817242da796924ca4e99947d087fedf9ce467cb9f7c62870" +
        "78f801df276fdf84ac00000000",
      merkle_branch: [
        "c40297f730dd7b5a99567eb8d27b78758f607507c52292d02d4031895b52f2ff",
        "49aef42d78e3e9999c9e6ec9e1dddd6cb880bf3b076a03be1318ca789089308e",
      ],
      version: "00000001",
      nbits:   "1b04864c",
      ntime:   "4d1b2237",
    },
  },
  // Low-complexity test block — easy target, miner finds shares quickly
  0: {
    name: "Low complexity test",
    extranonce1: "08000002",
    extranonce2_size: 4,
    known_extranonce2: null,
    known_nonce: null,
    known_hash: null,
    job: {
      id: "e2e_easy",
      prevhash:
        "0000000000000000000000000000000000000000000000000000000000000000",
      coinb1:
        "01000000010000000000000000000000000000000000000000" +
        "000000000000000000000000ffffffff20020862062f503253482f04",
      coinb2:
        "0d2f6e6f64655374726174756d2f000000000100f2052a01" +
        "00000017a914000000000000000000000000000000000000000087" +
        "00000000",
      merkle_branch: [],
      version: "00000001",
      nbits:   "2100ffff",
      ntime:   Math.floor(Date.now() / 1000).toString(16).padStart(8, "0"),
    },
  },
};

// -- CLI args ----------------------------------------------------------------

const args = process.argv.slice(2);
function getArg(name, fallback) {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
}

const BLOCK_NUM  = parseInt(getArg("--block", "0"), 10);
const PORT       = parseInt(getArg("--port", "3333"), 10);
const POOL_DIFF  = parseFloat(getArg("--diff", "1e-4"));
const TIMEOUT_S  = parseInt(getArg("--timeout", "120"), 10);

const BLOCK = BLOCKS[BLOCK_NUM];
if (!BLOCK) {
  console.error(`[POOL] Unknown block: ${BLOCK_NUM}. Available: ${Object.keys(BLOCKS).join(", ")}`);
  process.exit(1);
}

const EXTRANONCE1      = BLOCK.extranonce1;
const EXTRANONCE2_SIZE = BLOCK.extranonce2_size;
const JOB              = BLOCK.job;

// -- Crypto helpers (OpenSSL via Node) ---------------------------------------

function sha256(buf)  { return crypto.createHash("sha256").update(buf).digest(); }
function sha256d(buf) { return sha256(sha256(buf)); }
function hexToBytes(h){ return Buffer.from(h, "hex"); }

function reverseBuffer(buf) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[buf.length - 1 - i];
  return out;
}

function reverseWords(buf) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i += 4) {
    out[i]     = buf[i + 3];
    out[i + 1] = buf[i + 2];
    out[i + 2] = buf[i + 1];
    out[i + 3] = buf[i];
  }
  return out;
}

// -- Difficulty --------------------------------------------------------------

const DIFF1 = BigInt(
  "0x00000000ffff0000000000000000000000000000000000000000000000000000"
);

function hashToDifficulty(hashBuf) {
  const be = reverseBuffer(hashBuf);
  let n = 0n;
  for (let i = 0; i < 32; i++) n = (n << 8n) | BigInt(be[i]);
  if (n === 0n) return Infinity;
  return Number(DIFF1) / Number(n);
}

// -- Share validation --------------------------------------------------------

function validateShare(extranonce2, ntime, nonceHex) {
  // 1. Coinbase
  const coinbase = hexToBytes(JOB.coinb1 + EXTRANONCE1 + extranonce2 + JOB.coinb2);
  let merkleRoot = sha256d(coinbase);

  // 2. Merkle branches
  for (const branch of JOB.merkle_branch) {
    merkleRoot = sha256d(Buffer.concat([merkleRoot, hexToBytes(branch)]));
  }

  // 3. Block header (80 bytes)
  const header = Buffer.concat([
    reverseBuffer(hexToBytes(JOB.version)),
    reverseWords(hexToBytes(JOB.prevhash)),
    merkleRoot,
    reverseBuffer(hexToBytes(ntime)),
    reverseBuffer(hexToBytes(JOB.nbits)),
    reverseBuffer(hexToBytes(nonceHex.padStart(8, "0"))),
  ]);

  if (header.length !== 80) {
    console.error(`[POOL] ERROR: header ${header.length} bytes, expected 80`);
    return { valid: false, diff: 0, hash: Buffer.alloc(32), blockFound: false };
  }

  // 4. SHA256d (OpenSSL — independent from miner's C code)
  const hash = sha256d(header);
  const diff = hashToDifficulty(hash);
  const displayHash = reverseBuffer(hash).toString("hex");
  const blockFound = displayHash === BLOCK.known_hash;

  return { valid: diff >= POOL_DIFF, diff, hash, displayHash, blockFound };
}

// -- Stratum server ----------------------------------------------------------

let shareCount = 0;

const server = net.createServer((socket) => {
  const addr = `${socket.remoteAddress}:${socket.remotePort}`;
  console.log(`[POOL] Miner connected: ${addr}`);

  let buf = "";

  socket.on("data", (data) => {
    buf += data.toString();
    const lines = buf.split("\n");
    buf = lines.pop();
    for (const line of lines) {
      if (line.trim()) handleMessage(socket, line.trim());
    }
  });

  socket.on("close", () => console.log(`[POOL] Miner disconnected: ${addr}`));
  socket.on("error", (e) => console.error(`[POOL] Socket error: ${e.message}`));
});

function send(socket, obj) {
  const line = JSON.stringify(obj) + "\n";
  console.log(`[POOL] >>> ${line.trimEnd()}`);
  socket.write(line);
}

function handleMessage(socket, line) {
  console.log(`[POOL] <<< ${line}`);

  let msg;
  try { msg = JSON.parse(line); }
  catch { console.error("[POOL] Bad JSON"); return; }

  switch (msg.method) {
    case "mining.subscribe":   onSubscribe(socket, msg);          break;
    case "mining.authorize":   onAuthorize(socket, msg);          break;
    case "mining.submit":      onSubmit(socket, msg);             break;
    case "mining.suggest_difficulty": send(socket, { id: msg.id, result: true, error: null }); break;
    default:
      if (!msg.method && msg.id) break; // response to our push — ignore
      console.log(`[POOL] Unknown method: ${msg.method}`);
  }
}

function onSubscribe(socket, msg) {
  send(socket, {
    id: msg.id,
    result: [
      [["mining.set_difficulty", "1"], ["mining.notify", "1"]],
      EXTRANONCE1,
      EXTRANONCE2_SIZE,
    ],
    error: null,
  });
}

function onAuthorize(socket, msg) {
  const worker = msg.params?.[0] || "unknown";
  console.log(`[POOL] Worker authorized: ${worker}`);

  send(socket, { id: msg.id, result: true, error: null });

  // Send difficulty + job
  send(socket, { id: null, method: "mining.set_difficulty", params: [POOL_DIFF] });
  send(socket, {
    id: null,
    method: "mining.notify",
    params: [
      JOB.id, JOB.prevhash, JOB.coinb1, JOB.coinb2,
      JOB.merkle_branch, JOB.version, JOB.nbits, JOB.ntime, true,
    ],
  });

  console.log(`[POOL] Sent ${BLOCK.name}, job=${JOB.id}`);
}

function onSubmit(socket, msg) {
  const [worker, jobId, en2, ntime, nonce] = msg.params || [];
  console.log(`[POOL] Submit from ${worker}: job=${jobId} en2=${en2} ntime=${ntime} nonce=${nonce}`);

  if (jobId !== JOB.id) {
    console.log("[POOL] REJECTED: unknown job");
    send(socket, { id: msg.id, result: false, error: [21, "Job not found", null] });
    return;
  }

  const { valid, diff, hash, displayHash, blockFound } = validateShare(en2, ntime, nonce);
  console.log(`[POOL]   hash=${hash.toString("hex")}`);
  console.log(`[POOL]   display=${displayHash}`);
  console.log(`[POOL]   diff=${diff.toFixed(6)}, required=${POOL_DIFF}`);

  if (blockFound) {
    shareCount++;
    console.log(`[POOL] BLOCK FOUND! Hash matches ${BLOCK.name}`);
    console.log(`[POOL]   expected: ${BLOCK.known_hash}`);
    console.log(`[POOL]   got:      ${displayHash}`);
    send(socket, { id: msg.id, result: true, error: null });
    console.log(`\n[POOL] E2E TEST PASSED — block replay verified`);
    setTimeout(() => process.exit(0), 500);
  } else if (valid) {
    shareCount++;
    console.log(`[POOL] ACCEPTED share #${shareCount} (not block match)`);
    send(socket, { id: msg.id, result: true, error: null });
  } else {
    console.log("[POOL] REJECTED: low difficulty");
    send(socket, { id: msg.id, result: false, error: [23, "Low difficulty", null] });
  }
}

// -- Start -------------------------------------------------------------------

server.listen(PORT, "0.0.0.0", () => {
  console.log(`[POOL] Mock Stratum V1 pool — ${BLOCK.name}`);
  console.log(`[POOL] Port: ${PORT}, Difficulty: ${POOL_DIFF}`);
  console.log(`[POOL] Known nonce: ${BLOCK.known_nonce}, Expected hash: ${BLOCK.known_hash}`);
  console.log(`[POOL] Timeout: ${TIMEOUT_S}s`);
  console.log(`[POOL] Waiting for miner...\n`);
});

setTimeout(() => {
  console.error(`\n[POOL] TIMEOUT: no valid block in ${TIMEOUT_S}s`);
  process.exit(1);
}, TIMEOUT_S * 1000);

process.on("SIGINT", () => {
  console.log(`\n[POOL] Shutdown. Shares: ${shareCount}`);
  server.close();
  process.exit(shareCount > 0 ? 0 : 1);
});
