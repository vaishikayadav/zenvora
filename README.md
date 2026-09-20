# Zenvora

A local/demo application intelligence website for tracking scholarship, Aadhaar, KYC, and future government-service applications.

## Run locally

```powershell
Copy-Item .env.example .env
npm install
npm start
```

Open `http://localhost:3000`.

Demo admin login:

- Email: `admin@zenvora.local`
- Password: `demo-admin-2026`

Change the password and `JWT_SECRET` in `.env` before sharing the app or deploying it.

## Included

- Application-number recognition for `SCH`, `AAD`, and `KYC` demo records.
- Stuck reason, confidence, risk flag, predicted response time, and office guidance.
- Office map link, phone number, hours, required-document context, escalation path, reminders, and downloadable JSON status report.
- Local document mismatch check and protected admin analytics/add-sector controls.
- Single-file responsive frontend with the requested dark video-backed visual direction, reduced-motion support, tabs, and mobile layout.

## Security checklist

- Passwords are stored as bcrypt hashes.
- JWT login tokens expire after 20 minutes.
- Login and signup have separate rate limits.
- API routes require authentication; admin routes require the admin role.
- Zod validates email, password, application numbers, and admin sector inputs.
- Helmet adds security headers; production requests redirect to HTTPS.
- CORS is limited to `CLIENT_ORIGIN`.
- Production error responses hide implementation details.
- Secrets are read from environment variables.
- `npm install` resolves the declared current package versions.

## Manual production work

- Replace the in-memory maps with a private database with authentication, network restrictions, backups, migrations, and encrypted connections.
- Set a long random `JWT_SECRET`, strong admin password, `NODE_ENV=production`, and your real HTTPS `CLIENT_ORIGIN`.
- Put the app behind TLS termination and a reverse proxy with the correct `X-Forwarded-Proto` behavior.
- Add real email/SMS provider credentials outside the repository and implement delivery retries/audit logs.
- Perform a dependency audit (`npm audit`), penetration test, privacy review, and authorization tests before handling real applicant data.
- Do not upload real identity documents until encrypted object storage, retention rules, malware scanning, and access logs are implemented.
