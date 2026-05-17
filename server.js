const express = require('express');
const { google } = require('googleapis');
const app = express();
app.use(express.json());

// Thay bằng Spreadsheet ID của bạn
// Lấy từ URL sheet: docs.google.com/spreadsheets/d/SPREADSHEET_ID/edit
const SPREADSHEET_ID = '1HXvohNrO8wVE98nppRaPybUzASIn9yb9k8T08LZemtY';
const SHEET_NAME     = 'Sheet1';

// Service account credentials (dán JSON key vào đây sau)
const CREDENTIALS = JSON.parse(process.env.GOOGLE_CREDENTIALS || '{}');

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

app.get('/', (req, res) => res.json({ status: 'ok' }));

app.post('/webhook', async (req, res) => {
  try {
    console.log('BODY:', JSON.stringify(req.body));
    const body   = req.body;
    const action = body.action || '';

    if (action === 'ping' || action === 'health_check') {
      return res.json({ data: {} });
    }

    const payload       = body.data         || body;
    const flow_token    = payload.flow_token    || '';
    const full_name     = payload.full_name     || '';
    const phone         = payload.phone         || '';
    const date_of_birth = payload.date_of_birth || '';
    const insurance     = payload.insurance     || '';
    const email         = payload.email         || '';

    await appendToSheet([
      new Date().toISOString(),
      flow_token, full_name, phone, date_of_birth, insurance, email, 'received'
    ]);

    return res.json({
      screen: 'SUCCESS',
      data: { extension_message_response: { params: { flow_token } } }
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: err.toString() });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Running on port ${PORT}`));