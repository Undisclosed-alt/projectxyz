const crypto = require("crypto");
const express = require("express");

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static("public"));

const challenges = new Map();

const STREAM_INTERVAL_MS = 80;
const OPS_PER_CHALLENGE = 18;
const OP_WINDOW_MS = 700;
const TOTAL_TTL_MS = 3000;

const randomInt = (min, max) =>
  crypto.randomInt(min, max + 1);

const signPayload = (secret, payload) =>
  crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("hex");

const buildOperation = (seq) => {
  const op = crypto.randomInt(0, 2) === 0 ? "+" : "-";
  const value = randomInt(1, 9);
  return { seq, op, value };
};

app.post("/captcha/start", (req, res) => {
  const token = crypto.randomUUID();
  const secret = crypto.randomBytes(32).toString("hex");
  const createdAt = Date.now();

  challenges.set(token, {
    token,
    secret,
    createdAt,
    solved: false,
    ops: [],
    lastSeq: 0,
    expiresAt: createdAt + TOTAL_TTL_MS
  });

  res.json({
    token,
    streamUrl: `/captcha/stream/${token}`,
    solveUrl: "/captcha/solve",
    ttlMs: TOTAL_TTL_MS,
    opWindowMs: OP_WINDOW_MS,
    opsPerChallenge: OPS_PER_CHALLENGE
  });
});

app.get("/captcha/stream/:token", (req, res) => {
  const { token } = req.params;
  const challenge = challenges.get(token);

  if (!challenge || challenge.solved) {
    res.status(404).end();
    return;
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  let seq = 0;
  const interval = setInterval(() => {
    seq += 1;
    if (seq > OPS_PER_CHALLENGE) {
      clearInterval(interval);
      res.write("event: done\n");
      res.write("data: done\n\n");
      res.end();
      return;
    }

    const op = buildOperation(seq);
    const expiresAt = Date.now() + OP_WINDOW_MS;
    const payload = `${token}:${op.seq}:${op.op}:${op.value}:${expiresAt}`;
    const signature = signPayload(challenge.secret, payload);

    challenge.ops.push({ ...op, expiresAt, signature });
    challenge.lastSeq = op.seq;

    const message = {
      ...op,
      expiresAt,
      signature
    };

    res.write(`data: ${JSON.stringify(message)}\n\n`);
  }, STREAM_INTERVAL_MS);

  req.on("close", () => {
    clearInterval(interval);
  });
});

const computeTotal = (ops, lastSeq) => {
  return ops
    .filter((op) => op.seq <= lastSeq)
    .reduce((total, op) => {
      if (op.op === "+") {
        return total + op.value;
      }
      return total - op.value;
    }, 0);
};

app.post("/captcha/solve", (req, res) => {
  const { token, lastSeq, total, clientTs } = req.body;
  const challenge = challenges.get(token);

  if (!challenge || challenge.solved) {
    res.status(404).json({ ok: false, reason: "invalid-token" });
    return;
  }

  if (Date.now() > challenge.expiresAt) {
    res.status(400).json({ ok: false, reason: "challenge-expired" });
    return;
  }

  if (typeof lastSeq !== "number" || typeof total !== "number") {
    res.status(400).json({ ok: false, reason: "invalid-payload" });
    return;
  }

  const serverTotal = computeTotal(challenge.ops, lastSeq);
  const lastOp = challenge.ops.find((op) => op.seq === lastSeq);

  if (!lastOp) {
    res.status(400).json({ ok: false, reason: "missing-seq" });
    return;
  }

  if (total !== serverTotal) {
    res.status(400).json({ ok: false, reason: "total-mismatch" });
    return;
  }

  if (clientTs && Math.abs(Date.now() - clientTs) > OP_WINDOW_MS) {
    res.status(400).json({ ok: false, reason: "latency" });
    return;
  }

  if (Date.now() > lastOp.expiresAt) {
    res.status(400).json({ ok: false, reason: "window-expired" });
    return;
  }

  challenge.solved = true;

  res.json({ ok: true, token });
});

app.listen(port, () => {
  console.log(`Reverse CAPTCHA demo running on http://localhost:${port}`);
});
