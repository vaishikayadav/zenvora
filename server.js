require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || `http://localhost:${PORT}`;
const isProduction = process.env.NODE_ENV === 'production';

if (isProduction && JWT_SECRET === 'dev-only-change-me') {
  throw new Error('JWT_SECRET must be configured in production');
}

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(compression());
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', CLIENT_ORIGIN);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  if (isProduction && req.header('x-forwarded-proto') !== 'https') {
    return res.redirect(`https://${req.hostname}${req.originalUrl}`);
  }
  next();
});
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
const signupLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 5, standardHeaders: true, legacyHeaders: false });

const users = new Map();
const demoPassword = process.env.ADMIN_PASSWORD || 'demo-admin-2026';
users.set('admin@zenvora.local', { id: 'usr_admin', email: 'admin@zenvora.local', role: 'admin', passwordHash: bcrypt.hashSync(demoPassword, 12) });

const offices = {
  scholarship: { name: 'District Scholarship Cell', address: 'Collectorate Campus, Student Welfare Wing', phone: '+91 1800 200 4578', hours: 'Mon-Fri, 10:00-17:00', map: 'https://maps.google.com/?q=District+Scholarship+Cell', documents: ['Application acknowledgement', 'Aadhaar-linked bank proof', 'Income certificate'] },
  aadhaar: { name: 'UIDAI Aadhaar Seva Kendra', address: 'Civic Centre, Citizen Services Block', phone: '1947', hours: 'Mon-Sat, 09:30-17:30', map: 'https://maps.google.com/?q=Aadhaar+Seva+Kendra', documents: ['Appointment slip', 'Proof of identity', 'Proof of address'] },
  kyc: { name: 'Bank KYC Resolution Desk', address: 'Your branch operations counter', phone: '1800 123 4567', hours: 'Mon-Sat, 09:00-16:00', map: 'https://maps.google.com/?q=bank+branch', documents: ['PAN card', 'Address proof', 'Original identity document'] }
};

const sectors = [
  { key: 'scholarship', name: 'Student scholarship', prefixes: ['SCH', 'EDU', 'NSP'], responseDays: 10, risk: 'Medium', reason: 'Institute verification is pending', office: offices.scholarship },
  { key: 'aadhaar', name: 'Aadhaar application', prefixes: ['AAD', 'UID', 'ENR'], responseDays: 10, risk: 'Low', reason: 'Biometric quality review is in progress', office: offices.aadhaar },
  { key: 'kyc', name: 'KYC update', prefixes: ['KYC', 'BNK', 'FIN'], responseDays: 3, risk: 'High', reason: 'Address proof does not match profile records', office: offices.kyc }
];

const applications = new Map([
  ['SCH-2026-00421', { id: 'SCH-2026-00421', sector: 'scholarship', applicant: 'Aarav Mehta', submitted: '2026-09-11', lastUpdate: '2026-09-15', status: 'Stuck', progress: 62, missing: ['Institute verification stamp'], confidence: 96 }],
  ['AAD-8841-1902', { id: 'AAD-8841-1902', sector: 'aadhaar', applicant: 'Priya Nair', submitted: '2026-09-13', lastUpdate: '2026-09-18', status: 'Under review', progress: 78, missing: [], confidence: 91 }],
  ['KYC-2026-7731', { id: 'KYC-2026-7731', sector: 'kyc', applicant: 'Kabir Singh', submitted: '2026-09-17', lastUpdate: '2026-09-17', status: 'Action required', progress: 34, missing: ['Updated address proof'], confidence: 98 }]
]);

function safeError(res, status, message) { return res.status(status).json({ error: message }); }
function signUser(user) { return jwt.sign({ sub: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '20m' }); }
function auth(req, res, next) {
  const header = req.header('authorization');
  if (!header || !header.startsWith('Bearer ')) return safeError(res, 401, 'Login required');
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch { return safeError(res, 401, 'Session expired'); }
}
function adminOnly(req, res, next) { return req.user.role === 'admin' ? next() : safeError(res, 403, 'Admin access required'); }
function input(schema, source = 'body') {
  return (req, res, next) => {
    const result = schema.safeParse(req[source]);
    if (!result.success) return safeError(res, 400, 'Input did not match the required format');
    req.validated = result.data;
    next();
  };
}
const applicationNumber = z.string().trim().toUpperCase().regex(/^[A-Z]{3}-[0-9]{4}(?:-[0-9]{4,6})?$/, 'Invalid application number');
const lookupSchema = z.object({ applicationNumber });
const signupSchema = z.object({ email: z.string().email().max(120), password: z.string().min(12).max(72) });
const sectorSchema = z.object({ key: z.string().regex(/^[a-z0-9-]{2,30}$/), name: z.string().trim().min(2).max(80), prefixes: z.array(z.string().regex(/^[A-Z]{2,8}$/)).min(1).max(8), responseDays: z.number().int().min(1).max(365) });

app.post('/api/auth/login', loginLimiter, input(signupSchema), async (req, res) => {
  const user = users.get(req.validated.email.toLowerCase());
  if (!user || !(await bcrypt.compare(req.validated.password, user.passwordHash))) return safeError(res, 401, 'Invalid email or password');
  res.json({ token: signUser(user), user: { email: user.email, role: user.role } });
});
app.post('/api/auth/signup', signupLimiter, input(signupSchema), async (req, res) => {
  const email = req.validated.email.toLowerCase();
  if (users.has(email)) return safeError(res, 409, 'Account already exists');
  const user = { id: `usr_${crypto.randomUUID()}`, email, role: 'applicant', passwordHash: await bcrypt.hash(req.validated.password, 12) };
  users.set(email, user);
  res.status(201).json({ token: signUser(user), user: { email, role: user.role } });
});

app.get('/api/me', auth, (req, res) => res.json({ email: req.user.email, role: req.user.role }));
app.post('/api/applications/lookup', auth, input(lookupSchema), (req, res) => {
  const record = applications.get(req.validated.applicationNumber);
  if (!record) return safeError(res, 404, 'No local demo record found for that application number');
  const sector = sectors.find((item) => item.key === record.sector);
  res.json({ application: record, sector, office: sector.office, eta: `${sector.responseDays} days`, escalation: ['Verify the missing document', `Visit the ${sector.office.name}`, 'Ask for a receipt or escalation reference'] });
});
app.get('/api/applications/:id/report', auth, (req, res) => {
  const id = req.params.id.toUpperCase();
  if (!applicationNumber.safeParse(id).success) return safeError(res, 400, 'Invalid application number');
  const record = applications.get(id);
  if (!record) return safeError(res, 404, 'Application not found');
  const sector = sectors.find((item) => item.key === record.sector);
  res.json({ generatedAt: new Date().toISOString(), application: record, sector, office: sector.office, note: 'Demo report. Confirm final timelines with the responsible office.' });
});
app.post('/api/reminders', auth, (req, res) => res.json({ ok: true, message: 'Demo reminder scheduled. Connect an email/SMS provider for live delivery.' }));
app.get('/api/admin/analytics', auth, adminOnly, (req, res) => res.json({ sectors: sectors.map(({ key, name, responseDays }) => ({ key, name, responseDays, applications: [...applications.values()].filter((item) => item.sector === key).length })), commonReasons: sectors.map(({ name, reason }) => ({ name, reason, count: 1 })) }));
app.post('/api/admin/sectors', auth, adminOnly, input(sectorSchema), (req, res) => { sectors.push({ ...req.validated, risk: 'Medium', reason: 'Additional verification is pending', office: offices.scholarship }); res.status(201).json({ ok: true, sector: req.validated }); });

app.use((err, req, res, next) => { console.error(err); safeError(res, 500, isProduction ? 'Something went wrong' : err.message); });
app.listen(PORT, () => console.log(`Zenvora running at http://localhost:${PORT}`));
