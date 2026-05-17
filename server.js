const express    = require('express');
const crypto     = require('crypto');
const fs         = require('fs');
const { google } = require('googleapis');

const app = express();
app.use(express.json());

// ── Config ────────────────────────────────────────────────────
const SPREADSHEET_ID = process.env.SPREADSHEET_ID || '1HXvohNrO8wVE98nppRaPybUzASIn9yb9k8T08LZemtY';
const SHEET_NAME     = 'Sheet1';
const CREDENTIALS    = JSON.parse(process.env.GOOGLE_CREDENTIALS || '{}');

// Private key: ưu tiên env var, fallback đọc file (local dev)
const PRIVATE_KEY = process.env.PRIVATE_KEY
  ? process.env.PRIVATE_KEY.replace(/\\n/g, '\n')
  : fs.readFileSync('private.pem', 'utf8');

// ── Google Sheets helper ──────────────────────────────────────
async function appendToSheet(row) {
  const auth = new google.auth.GoogleAuth({
    credentials: CREDENTIALS,
    scopes: ['https://www.googleapis.com/auth/spreadsheets']
  });
  const sheets = google.sheets({ version: 'v4', auth });
  await sheets.spreadsheets.values.append({
    spreadsheetId: SPREADSHEET_ID,
    range: `${SHEET_NAME}!A:H`,
    valueInputOption: 'USER_ENTERED',
    requestBody: { values: [row] }
  });
}

// ── Decryption ────────────────────────────────────────────────
function decryptRequest(body) {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

  // 1. Giải mã AES key bằng RSA private key (OAEP + SHA-256)
  const aesKey = crypto.privateDecrypt(
    {
      key: PRIVATE_KEY,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    Buffer.from(encrypted_aes_key, 'base64')
  );

  // 2. Giải mã body bằng AES-128-GCM
  const iv         = Buffer.from(initial_vector, 'base64');
  const raw        = Buffer.from(encrypted_flow_data, 'base64');
  const TAG_LEN    = 16;
  const ciphertext = raw.subarray(0, -TAG_LEN);
  const authTag    = raw.subarray(-TAG_LEN);

  const decipher = crypto.createDecipheriv('aes-128-gcm', aesKey, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);

  return {
    payload:   JSON.parse(decrypted.toString('utf-8')),
    aesKey,
    iv
  };
}

// ── Encryption ────────────────────────────────────────────────
function encryptResponse(responseObj, aesKey, iv) {
  // Flip last byte của IV — đúng spec Meta
  const flippedIv = Buffer.from(iv);
  flippedIv[flippedIv.length - 1] ^= 0xFF;

  const cipher    = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
  const plaintext = JSON.stringify(responseObj);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf-8'),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([encrypted, tag]).toString('base64');
}

// ── Routes ────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'WA Flow Webhook' });
});

app.get('/webhook', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/webhook', async (req, res) => {
  try {
    console.log('RAW BODY:', JSON.stringify(req.body));

    // ── Kiểm tra xem request có bị mã hoá không ──────────────
    const isEncrypted = !!(req.body.encrypted_aes_key);

    let payload, aesKey, iv;

    if (isEncrypted) {
      // Decrypt request từ Meta
      const decrypted = decryptRequest(req.body);
      payload = decrypted.payload;
      aesKey  = decrypted.aesKey;
      iv      = decrypted.iv;
    } else {
      // Unencrypted (test trực tiếp bằng curl)
      payload = req.body.data || req.body;
    }

    console.log('PAYLOAD:', JSON.stringify(payload));

    const action = payload.action || '';

    // ── PING / HEALTH CHECK ───────────────────────────────────
    if (action === 'ping' || action === 'health_check') {
      const response = { data: {} };
      if (isEncrypted) {
        return res.json({
          encrypted_flow_data: encryptResponse(response, aesKey, iv)
        });
      }
      return res.json(response);
    }

    // ── DATA_EXCHANGE: user submit form ───────────────────────
    const flow_token    = payload.flow_token    || '';
    const full_name     = payload.full_name     || '';
    const phone         = payload.phone         || '';
    const date_of_birth = payload.date_of_birth || '';
    const insurance     = payload.insurance     || '';
    const email         = payload.email         || '';

    // Ghi vào Google Sheet
    await appendToSheet([
      new Date().toISOString(),
      flow_token, full_name, phone,
      date_of_birth, insurance, email,
      'received'
    ]);

    const response = {
      screen: 'SUCCESS',
      data: {
        extension_message_response: {
          params: { flow_token }
        }
      }
    };

    if (isEncrypted) {
      return res.json({
        encrypted_flow_data: encryptResponse(response, aesKey, iv)
      });
    }
    return res.json(response);

  } catch (err) {
    console.error('ERROR:', err.toString());
    // Không trả chi tiết lỗi ra ngoài khi production
    return res.status(500).json({ error: 'server_error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Running on port ${PORT}`));
