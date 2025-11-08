// server.js
import express from "express";
import cors from "cors";
import axios from "axios";
import crypto from "crypto";
import fs from "fs";
import bodyParser from "body-parser";
import dotenv from "dotenv";
dotenv.config();

const app = express();

// We need raw body for webhook verification (signature over raw body)
// Use bodyParser.raw for callback route only; keep json for others
app.use(cors());
app.use(express.json());

// In-memory "DB" (replace with real DB in production)
const DB = { users: {}, transactions: {} };
// structure: DB.users[userId] = { balance: 0, transactions: [txId,...] }
// DB.transactions[txId] = { id, userId, type, amount, status, created, meta }

// Helper to init user
function ensureUser(userId){
  if(!DB.users[userId]) DB.users[userId] = { balance:0, transactions:[] };
  return DB.users[userId];
}

// CONFIG (from .env)
const TELEBIRR_API_BASE = process.env.TELEBIRR_API_BASE || "https://TELEBIRR_API_BASE_PLACEHOLDER";
const TELEBIRR_MERCHANT_ID = process.env.TELEBIRR_MERCHANT_ID || "YOUR_MERCHANT_ID";
const TELEBIRR_PRIVATE_KEY = process.env.TELEBIRR_PRIVATE_KEY || null; // PEM string or path
const TELEBIRR_PUBLIC_KEY = process.env.TELEBIRR_PUBLIC_KEY || null;   // Telebirr public key PEM (for verifying callbacks)
const CALLBACK_URL = process.env.CALLBACK_URL || "https://your-public-domain.com/api/telebirr-callback";

// Utility: load key from path or use string
function loadKey(val){
  if(!val) return null;
  if(val.includes("-----BEGIN")) return val;
  // try read file path
  try{ return fs.readFileSync(val, 'utf8'); } catch(e){ return null; }
}

// Load keys
const merchantPrivateKeyPem = loadKey(TELEBIRR_PRIVATE_KEY);
const telebirrPublicKeyPem = loadKey(TELEBIRR_PUBLIC_KEY);

/**
 * Create Telebirr payment (H5/web) — placeholder implementation.
 * Different Telebirr integrations vary; this function prepares
 * a request using expected fields and returns a checkoutUrl or response.
 *
 * You MUST replace endpoint/path/payload with Telebirr sandbox/production docs values.
 */
async function createTelebirrPayment(tx){
  // Example payload; change fields per Telebirr docs
  const payload = {
    merchantId: TELEBIRR_MERCHANT_ID,
    orderId: String(tx.id),
    amount: tx.amount,
    currency: "ETB",
    description: "LaamPay deposit",
    notifyUrl: CALLBACK_URL,
    // additional fields required by Telebirr (customer msisdn etc)
    customerPhone: tx.meta?.phone || "",
    timestamp: Date.now()
  };

  // Some Telebirr flows require signing or RSA encrypt; if required sign payload.
  // Here is a simple example of signing the JSON with merchant private key (RSA-SHA256).
  if(merchantPrivateKeyPem){
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(JSON.stringify(payload));
    const signature = signer.sign(merchantPrivateKeyPem, 'base64');
    payload.signature = signature;
  }

  // POST to Telebirr endpoint (placeholder URL)
  const url = `${TELEBIRR_API_BASE}/payment/initiate`; // UPDATE per docs
  try{
    const res = await axios.post(url, payload, { timeout: 10000 });
    // Example: Telebirr might return { checkoutUrl: "...", status: "PENDING", referenceId: "xxx" }
    return res.data;
  }catch(err){
    console.error("Telebirr create payment error:", err?.response?.data || err.message);
    throw new Error("Failed to create Telebirr payment (check config & endpoint).");
  }
}

// Endpoint: get wallet
app.get("/api/wallet/:userId", (req, res) => {
  const userId = req.params.userId;
  const user = ensureUser(userId);
  // build transactions list
  const transactions = (user.transactions || []).map(id => DB.transactions[id]).filter(Boolean);
  res.json({ balance: user.balance, transactions });
});

// Endpoint: deposit (frontend calls this to create payment)
app.post("/api/deposit", async (req, res) => {
  try{
    const { userId, phone, amount } = req.body;
    if(!userId || !amount) return res.status(400).json({ error: "Missing params" });
    ensureUser(userId);
    const txId = Date.now().toString();
    const tx = { id: txId, userId, type: "deposit", amount: Number(amount), status: "created", created: new Date().toISOString(), meta: { phone } };
    DB.transactions[txId] = tx;
    DB.users[userId].transactions.push(txId);

    // Create Telebirr payment: returns data (may include checkoutUrl)
    // NOTE: replace createTelebirrPayment implementation for exact Telebirr schema.
    const tbResp = await createTelebirrPayment(tx);

    // Save telebirr reference if provided
    if(tbResp && tbResp.referenceId) tx.meta.referenceId = tbResp.referenceId;
    tx.status = tbResp && tbResp.status ? tbResp.status.toLowerCase() : "pending";
    // If checkout URL returned, pass it to client to open H5
    return res.json({ message: "Payment initiated", txId, checkoutUrl: tbResp.checkoutUrl || tbResp.redirectUrl || null });
  }catch(err){
    console.error(err);
    return res.status(500).json({ error: err.message || "server error" });
  }
});

/**
 * Webhook: Telebirr will POST to this endpoint to notify payment result.
 * We need raw body to verify signature over exactly what Telebirr sent.
 *
 * Telebirr docs mention a header 'Signed-Token' or similar; update header name per docs.
 */
app.post("/api/telebirr-callback", bodyParser.raw({ type: '*/*' }), (req, res) => {
  // raw body buffer
  const rawBody = req.body;
  const headers = req.headers;
  const signedToken = headers['signed-token'] || headers['signedtoken'] || headers['x-signed-token'];

  // Try to parse JSON safely for logging
  let parsed = null;
  try { parsed = JSON.parse(rawBody.toString()); } catch(e){ parsed = null; }

  // Verify signature (example using RSA-SHA256). Adjust according to Telebirr docs.
  let verified = false;
  if(telebirrPublicKeyPem && signedToken){
    try{
      // If Telebirr sends signature base64 of rawBody
      const verifier = crypto.createVerify('RSA-SHA256');
      verifier.update(rawBody);
      verified = verifier.verify(telebirrPublicKeyPem, signedToken, 'base64');
    }catch(e){
      console.warn("Verification error:", e.message);
      verified = false;
    }
  } else {
    // If no key configured, we can't verify — in prod reject or log
    console.warn("Telebirr public key not configured; skipping verification (NOT RECOMMENDED FOR PROD)");
    verified = true; // temporary for sandbox — change policy in prod
  }

  if(!verified){
    console.warn("Callback signature not verified, rejecting");
    return res.status(400).send("Invalid signature");
  }

  // Extract relevant fields from parsed body (update according to Telebirr payload)
  // Example expected fields: { orderId, referenceId, amount, status } 
  const body = parsed || {};
  const orderId = body.orderId || body.order_id || body.referenceId || body.orderid;
  const status = (body.status || body.result || "").toString().toUpperCase();
  const amount = Number(body.amount || 0);

  // Find transaction by orderId (we used tx.id as orderId)
  const tx = DB.transactions[orderId];
  if(!tx){
    console.warn("Tx not found for orderId:", orderId);
    return res.status(404).send("Tx not found");
  }

  if(status === "SUCCESS" || status === "COMPLETED" || status === "OK"){
    tx.status = "completed";
    // credit user balance
    const u = DB.users[tx.userId];
    u.balance = +(u.balance + (amount || tx.amount));
  } else {
    tx.status = "failed";
  }

  // respond 200 to Telebirr
  res.status(200).send("OK");
});

// Withdraw endpoint (mock)
app.post("/api/withdraw", (req, res) => {
  const { userId, bank, account, amount } = req.body;
  if(!userId || !bank || !account || !amount) return res.status(400).json({ error: "Missing params" });
  ensureUser(userId);
  const user = DB.users[userId];
  if(amount > user.balance) return res.status(400).json({ error: "Insufficient balance" });

  const txId = Date.now().toString();
  const tx = { id: txId, userId, type:"withdraw", amount:Number(amount), status:"processing", created:new Date().toISOString(), meta:{ bank, account } };
  DB.transactions[txId] = tx;
  user.transactions.push(txId);
  // reserve/deduct
  user.balance = +(user.balance - amount);

  // simulate bank processing -> complete after delay
  setTimeout(()=> {
    tx.status = "completed";
  }, 4000);

  res.json({ message: "Withdraw started", txId });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, ()=> console.log(`LaamPay demo server running on port ${PORT}`));
