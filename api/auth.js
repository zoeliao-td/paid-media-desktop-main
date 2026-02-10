import crypto from 'crypto';

const COOKIE_NAME = 'auth_token';
const SALT = process.env.AUTH_SALT || 'campaigns_dashboard_salt_2024';

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
}

function generateToken(password) {
  const timestamp = Date.now();
  const hash = hashPassword(password + timestamp, SALT);
  return Buffer.from(`${timestamp}:${hash}`).toString('base64');
}

export default function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { password } = req.body;
  const sitePassword = process.env.SITE_PASSWORD;

  if (!sitePassword) {
    return res.status(500).json({ error: 'Site password not configured' });
  }

  if (password !== sitePassword) {
    return res.status(401).json({ error: 'Invalid password' });
  }

  // Generate secure token
  const token = generateToken(password);

  // Set secure cookie
  res.setHeader('Set-Cookie', [
    `${COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${24 * 60 * 60}`
  ]);

  const redirectTo = req.query.redirect || '/';
  return res.status(200).json({ success: true, redirectTo });
}