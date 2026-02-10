import { NextResponse } from 'next/server';
import crypto from 'crypto';

const LOGIN_PATH = '/login';
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

function verifyToken(token, password) {
  try {
    const decoded = Buffer.from(token, 'base64').toString();
    const [timestamp, hash] = decoded.split(':');
    const expectedHash = hashPassword(password + timestamp, SALT);

    // Token expires after 24 hours
    const isExpired = Date.now() - parseInt(timestamp) > 24 * 60 * 60 * 1000;

    return hash === expectedHash && !isExpired;
  } catch {
    return false;
  }
}

export function middleware(request) {
  const { pathname } = request.nextUrl;

  // Skip middleware for static assets
  if (pathname.startsWith('/_next') ||
      pathname.startsWith('/api') ||
      pathname.includes('.css') ||
      pathname.includes('.js') ||
      pathname.includes('.ico') ||
      pathname.includes('.png') ||
      pathname.includes('.jpg') ||
      pathname.includes('.svg')) {
    return NextResponse.next();
  }

  const sitePassword = process.env.SITE_PASSWORD;

  // If no password is set, allow access
  if (!sitePassword) {
    return NextResponse.next();
  }

  // Allow access to login page
  if (pathname === LOGIN_PATH) {
    return NextResponse.next();
  }

  // Check for authentication token
  const authToken = request.cookies.get(COOKIE_NAME)?.value;

  if (!authToken || !verifyToken(authToken, sitePassword)) {
    // Redirect to login page
    const url = request.nextUrl.clone();
    url.pathname = LOGIN_PATH;
    url.searchParams.set('redirect', pathname);
    return NextResponse.redirect(url);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)']
};