global.ggScripts = global.ggScripts || new Map();

function isAntiFetchValid(req) {
  const ua = req.headers['user-agent'] || '';
  const robloxId = req.headers['roblox-id'];
  const accept = (req.headers['accept'] || '').toLowerCase();

  if (!robloxId || !/^\d+$/.test(String(robloxId))) {
    return false;
  }

  if (
    req.headers['sec-fetch-site'] ||
    req.headers['sec-fetch-mode'] ||
    req.headers['sec-fetch-dest'] ||
    req.headers['sec-ch-ua'] ||
    req.headers['referer'] ||
    req.headers['origin'] ||
    req.headers['x-forwarded-host'] ||
    req.headers['cookie'] ||
    accept.includes('text/html')
  ) {
    return false;
  }

  return /^Roblox\/WinInet\b/i.test(ua) || /^RobloxStudio\b/i.test(ua) || ua === 'Roblox/WinInet';
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  if (req.method !== 'GET') {
    return res.status(405).send('');
  }

  if (!isAntiFetchValid(req)) {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    return res.status(403).send('');
  }

  const { id } = req.query;
  const entry = global.ggScripts.get(id);

  res.setHeader('Content-Type', 'text/plain; charset=utf-8');

  if (!entry) {
    return res.status(404).send('');
  }

  return res.status(200).send(entry.payload);
};
