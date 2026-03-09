const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');
const cron = require('node-cron');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ── STORAGE EN MÉMOIRE (remplacé par DB en prod) ──
let inventory = [];
let alerts = [];
let watchlist = [];

// ══════════════════════════════
// PROXY APIs
// ══════════════════════════════

// VirusTotal
app.get('/api/virustotal/url', async (req, res) => {
  try {
    const id = Buffer.from(req.query.url).toString('base64').replace(/=/g, '');
    const r = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers: { 'x-apikey': process.env.VT_KEY || '' }
    });
    res.json(await r.json());
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/virustotal/hash', async (req, res) => {
  try {
    const r = await fetch(`https://www.virustotal.com/api/v3/files/${req.query.hash}`, {
      headers: { 'x-apikey': process.env.VT_KEY || '' }
    });
    res.json(await r.json());
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// AbuseIPDB
app.get('/api/abuseipdb', async (req, res) => {
  try {
    const r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${req.query.ip}&maxAgeInDays=90&verbose`, {
      headers: { 'Key': process.env.ABUSE_KEY || '', 'Accept': 'application/json' }
    });
    res.json(await r.json());
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// HaveIBeenPwned
app.get('/api/hibp', async (req, res) => {
  try {
    const r = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(req.query.email)}`, {
      headers: { 'hibp-api-key': process.env.HIBP_KEY || '', 'User-Agent': 'CyberOps-Platform' }
    });
    if (r.status === 404) return res.json([]);
    res.json(await r.json());
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// URLhaus
app.post('/api/urlhaus/url', async (req, res) => {
  try {
    const r = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      body: new URLSearchParams({ url: req.body.url })
    });
    res.json(await r.json());
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/urlhaus/host', async (req, res) => {
  try {
    const r = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      body: new URLSearchParams({ host: req.body.host })
    });
    res.json(await r.json());
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// MalwareBazaar
app.post('/api/malwarebazaar', async (req, res) => {
  try {
    const r = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      body: new URLSearchParams({ query: req.body.query || 'get_info', hash: req.body.hash || '', selector: req.body.selector || '' })
    });
    res.json(await r.json());
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// NIST NVD
app.get('/api/nvd', async (req, res) => {
  try {
    let url = `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20&`;
    if (req.query.cveId) url += `cveId=${req.query.cveId}`;
    else url += `keywordSearch=${encodeURIComponent(req.query.keyword || '')}`;
    if (req.query.severity) url += `&cvssV3Severity=${req.query.severity}`;
    const r = await fetch(url);
    res.json(await r.json());
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// CISA KEV
app.get('/api/cisa-kev', async (req, res) => {
  try {
    const r = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
    res.json(await r.json());
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GeoIP
app.get('/api/geo', async (req, res) => {
  try {
    const r = await fetch(`https://ipapi.co/${req.query.ip}/json/`);
    res.json(await r.json());
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// DNS
app.get('/api/dns', async (req, res) => {
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${req.query.name}&type=${req.query.type}`, {
      headers: { 'Accept': 'application/dns-json' }
    });
    res.json(await r.json());
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// CRT.SH
app.get('/api/crtsh', async (req, res) => {
  try {
    const r = await fetch(`https://crt.sh/?q=%.${req.query.domain}&output=json`);
    res.json(await r.json());
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Pwned Passwords
app.get('/api/pwned-passwords', async (req, res) => {
  try {
    const r = await fetch(`https://api.pwnedpasswords.com/range/${req.query.prefix}`);
    res.text().then(t => res.send(t));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════
// INVENTAIRE
// ══════════════════════════════
app.get('/api/inventory', (req, res) => res.json(inventory));

app.post('/api/inventory', (req, res) => {
  const asset = { id: Date.now(), ...req.body, addedAt: new Date().toISOString() };
  inventory.push(asset);
  res.json(asset);
});

app.delete('/api/inventory/:id', (req, res) => {
  inventory = inventory.filter(a => a.id !== parseInt(req.params.id));
  res.json({ ok: true });
});

// ══════════════════════════════
// ALERTES
// ══════════════════════════════
app.get('/api/alerts', (req, res) => res.json(alerts));

app.post('/api/alerts/read/:id', (req, res) => {
  const a = alerts.find(a => a.id === parseInt(req.params.id));
  if (a) a.read = true;
  res.json({ ok: true });
});

// ══════════════════════════════
// VEILLE CVE AUTOMATIQUE
// ══════════════════════════════
async function runCVEWatch() {
  console.log('[VEILLE] Scan CVE en cours...');
  if (!inventory.length) return;

  for (const asset of inventory) {
    if (!asset.cpe && !asset.product) continue;
    try {
      const keyword = asset.cpe || `${asset.vendor} ${asset.product} ${asset.version}`;
      const r = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5&keywordSearch=${encodeURIComponent(keyword)}&cvssV3Severity=CRITICAL`);
      const data = await r.json();

      if (data.vulnerabilities?.length) {
        for (const item of data.vulnerabilities) {
          const cveId = item.cve.id;
          const exists = alerts.find(a => a.cveId === cveId && a.assetId === asset.id);
          if (!exists) {
            const cvss = item.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 0;
            const alert = {
              id: Date.now(),
              cveId,
              assetId: asset.id,
              assetName: `${asset.vendor} ${asset.product} ${asset.version}`,
              cvss,
              description: item.cve.descriptions?.find(d => d.lang === 'en')?.value?.substring(0, 200) || '',
              date: new Date().toISOString(),
              read: false
            };
            alerts.push(alert);
            console.log(`[ALERTE] ${cveId} affecte ${asset.product}`);
            if (process.env.SMTP_HOST && process.env.ALERT_EMAIL) {
              await sendAlert(alert);
            }
          }
        }
      }
      await new Promise(r => setTimeout(r, 2000));
    } catch(e) { console.error('[VEILLE] Erreur:', e.message); }
  }
}

// Toutes les 12 heures
cron.schedule('0 */12 * * *', runCVEWatch);

// ══════════════════════════════
// EMAIL
// ══════════════════════════════
async function sendAlert(alert) {
  try {
    const transporter = nodemailer.createTransporter({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587'),
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });
    await transporter.sendMail({
      from: process.env.SMTP_USER,
      to: process.env.ALERT_EMAIL,
      subject: `[CYBEROPS] Nouvelle vulnérabilité critique — ${alert.cveId}`,
      html: `
        <h2 style="color:#ff2d55">⚠️ Alerte Vulnérabilité Critique</h2>
        <p><strong>CVE:</strong> ${alert.cveId}</p>
        <p><strong>Asset affecté:</strong> ${alert.assetName}</p>
        <p><strong>Score CVSS:</strong> ${alert.cvss}</p>
        <p><strong>Description:</strong> ${alert.description}</p>
        <p><strong>Détecté le:</strong> ${new Date(alert.date).toLocaleString('fr-FR')}</p>
      `
    });
  } catch(e) { console.error('[MAIL] Erreur:', e.message); }
}

// ══════════════════════════════
// DÉMARRAGE
// ══════════════════════════════
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`CyberOps démarré sur le port ${PORT}`));
