module.exports = async (req, res) => {
  const { code, error, error_description } = req.query;
  const clientId = process.env.OAUTH_GITHUB_CLIENT_ID;
  const clientSecret = process.env.OAUTH_GITHUB_CLIENT_SECRET;

  if (error) {
    res.status(401).send(`GitHub denied access: ${error_description || error}`);
    return;
  }
  if (!code) {
    res.status(400).send('Missing authorization code from GitHub.');
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

    if (tokenData.error) {
      res.status(401).send(`GitHub token exchange failed: ${tokenData.error_description || tokenData.error}`);
      return;
    }

    const payload = JSON.stringify({ token: tokenData.access_token, provider: 'github' }).replace(/'/g, "\\'");

    res.setHeader('Content-Type', 'text/html');
    res.status(200).send(`<!doctype html><html><body>
<script>
(function() {
  function receiveMessage(e) {
    window.opener.postMessage('authorization:github:success:${payload}', e.origin);
    window.removeEventListener('message', receiveMessage, false);
  }
  window.addEventListener('message', receiveMessage, false);
  window.opener.postMessage('authorizing:github', '*');
})();
</script>
</body></html>`);
  } catch (err) {
    res.status(500).send('OAuth callback error: ' + err.message);
  }
};
