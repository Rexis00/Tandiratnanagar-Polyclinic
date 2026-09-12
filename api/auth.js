const crypto = require('crypto');

module.exports = (req, res) => {
  const clientId = process.env.OAUTH_GITHUB_CLIENT_ID;
  if (!clientId) {
    res.setHeader('Content-Type', 'text/plain');
    res.status(500).send('Missing OAUTH_GITHUB_CLIENT_ID environment variable.');
    return;
  }

  const host = req.headers.host;
  const protocol = host && host.includes('localhost') ? 'http' : 'https';
  const redirectUri = `${protocol}://${host}/api/callback`;
  const state = crypto.randomBytes(16).toString('hex');

  // Bind the state to this browser via a short-lived, httpOnly cookie so
  // callback.js can verify the redirect actually belongs to this flow (CSRF protection).
  res.setHeader('Set-Cookie', `oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`);

  const authorizeUrl =
    'https://github.com/login/oauth/authorize' +
    `?client_id=${encodeURIComponent(clientId)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    '&scope=repo,user' +
    `&state=${state}`;

  res.writeHead(302, { Location: authorizeUrl });
  res.end();
};
