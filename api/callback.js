function getCookie(req, name) {
  const header = req.headers.cookie || '';
  const match = header.split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
  return match ? match.slice(name.length + 1) : null;
}

module.exports = async (req, res) => {
  const { code, state, error } = req.query;
  const clientId = process.env.OAUTH_GITHUB_CLIENT_ID;
  const clientSecret = process.env.OAUTH_GITHUB_CLIENT_SECRET;

  // Clear the state cookie either way; it's single-use.
  res.setHeader('Set-Cookie', 'oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
  res.setHeader('Content-Type', 'text/plain');

  if (error) {
    // Never reflect GitHub's error/error_description text into the response body —
    // treat it as an opaque signal only, to avoid reflected XSS from a crafted link.
    res.status(401).send('GitHub denied access to the OAuth request.');
    return;
  }
  if (!code) {
    res.status(400).send('Missing authorization code from GitHub.');
    return;
  }

  const expectedState = getCookie(req, 'oauth_state');
  if (!state || !expectedState || state !== expectedState) {
    res.status(400).send('Invalid or missing OAuth state. Please try logging in again.');
    return;
  }

  if (!clientId || !clientSecret) {
    res.status(500).send('Missing OAUTH_GITHUB_CLIENT_ID / OAUTH_GITHUB_CLIENT_SECRET environment variables.');
    return;
  }

  try {
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code }),
    });
    const tokenData = await tokenRes.json();

    if (tokenData.error || !tokenData.access_token) {
      res.status(401).send('GitHub token exchange failed.');
      return;
    }

    const payload = JSON.stringify({ token: tokenData.access_token, provider: 'github' });

    res.setHeader('Content-Type', 'text/html');
    res.status(200).send(`<!doctype html><html><body>
<script>
(function() {
  var payload = ${payload};
  function receiveMessage(e) {
    window.opener.postMessage('authorization:github:success:' + JSON.stringify(payload), e.origin);
    window.removeEventListener('message', receiveMessage, false);
  }
  window.addEventListener('message', receiveMessage, false);
  window.opener.postMessage('authorizing:github', '*');
})();
</script>
</body></html>`);
  } catch (err) {
    res.setHeader('Content-Type', 'text/plain');
    res.status(500).send('OAuth callback error.');
  }
};
