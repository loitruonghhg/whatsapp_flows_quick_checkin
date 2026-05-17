const express    = require('express');
const crypto     = require('crypto');
const fs         = require('fs');
const { google } = require('googleapis');

const app = express();
app.use(express.json());

const SPREADSHEET_ID = process.env.SPREADSHEET_ID || '1HXvohNrO8wVE98nppRaPybUzASIn9yb9k8T08LZemtY';
const SHEET_NAME     = 'Sheet1';
const CREDENTIALS    = JSON.parse(process.env.GOOGLE_CREDENTIALS || '{}');
const PRIVATE_KEY    = process.env.PRIVATE_KEY
  ? process.env.PRIVATE_KEY.replace(/\\n/g, '\n')
  : fs.readFileSync('private.pem', 'utf8');

// ── Google Sheets ─────────────────────────────────────────────
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

// ── Decrypt request từ Meta ───────────────────────────────────
function decryptRequest(body) {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

  // Bước 1: RSA-OAEP decrypt → ra buffer 256 bytes
  const decryptedKeyBuffer = crypto.privateDecrypt(
    {
      key:     PRIVATE_KEY,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    Buffer.from(encrypted_aes_key, 'base64')
  );

  // Bước 2: CHỈ lấy 16 bytes đầu làm AES-128 key
  const aesKey = decryptedKeyBuffer.slice(0, 16);

  // Bước 3: AES-128-GCM decrypt
  const iv         = Buffer.from(initial_vector, 'base64');
  const rawData    = Buffer.from(encrypted_flow_data, 'base64');
  const TAG_LEN    = 16;
  const ciphertext = rawData.subarray(0, -TAG_LEN);
  const authTag    = rawData.subarray(-TAG_LEN);

  const decipher = crypto.createDecipheriv('aes-128-gcm', aesKey, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);

  return {
    payload: JSON.parse(decrypted.toString('utf-8')),
    aesKey,
    iv
  };
}

// ── Encrypt response trả về Meta ─────────────────────────────
function encryptResponse(responseObj, aesKey, iv) {
  // Flip last byte của IV — đúng spec Meta
  const flippedIv = Buffer.from(iv);
  flippedIv[flippedIv.length - 1] ^= 0xFF;

  const cipher    = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(responseObj), 'utf-8'),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([encrypted, tag]).toString('base64');
}

// ── Helper trả về encrypted response đúng spec Meta ──────────
function sendEncrypted(res, responseObj, aesKey, iv) {
  const flippedIv = Buffer.from(iv).map(b => b ^ 0xFF);

  const cipher    = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(responseObj), 'utf-8'),
    cipher.final()
  ]);
  const tag     = cipher.getAuthTag();
  const base64  = Buffer.concat([encrypted, tag]).toString('base64');

  // ✅ Trả raw Base64 string, KHÔNG bọc JSON
  res.set('Content-Type', 'text/plain');
  return res.send(base64);
}

// ── Routes ────────────────────────────────────────────────────
app.get('/',        (req, res) => res.json({ status: 'ok' }));
app.get('/webhook', (req, res) => res.json({ status: 'ok' }));

app.post('/webhook', async (req, res) => {
  try {
    console.log('RAW:', JSON.stringify(req.body));

    const isEncrypted = !!req.body.encrypted_aes_key;
    let payload, aesKey, iv;

    if (isEncrypted) {
      const dec = decryptRequest(req.body);
      payload   = dec.payload;
      aesKey    = dec.aesKey;
      iv        = dec.iv;
      console.log('DECRYPTED:', JSON.stringify(payload));
    } else {
      payload = req.body.data || req.body;
    }

    const action = payload.action || '';
    console.log('ACTION:', action);

    // ── Ping / health check ───────────────────────────────────
    if (action === 'ping' || action === 'health_check') {
      const response = {
        version: '3.0',
        data: {
          status: 'active'
        }
      };
      if (isEncrypted) {
        return sendEncrypted(res, response, aesKey, iv);
      }
      return res.json(response);
    }

    // ── Data exchange ─────────────────────────────────────────
    const flow_token    = payload.flow_token    || '';
    const full_name     = payload.full_name     || '';
    const phone         = payload.phone         || '';
    const date_of_birth = payload.date_of_birth || '';
    const insurance     = payload.insurance     || '';
    const email         = payload.email         || '';

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
      return sendEncrypted(res, response, aesKey, iv);
    }
    return res.json(response);

  } catch (err) {
    console.error('ERROR:', err.message, err.stack);
    return res.status(500).send('server_error');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Port ${PORT} — ready`));
