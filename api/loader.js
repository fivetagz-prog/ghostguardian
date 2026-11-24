global.ggScripts = global.ggScripts || new Map();

function isAntiFetchValid(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const accept = (req.headers['accept'] || '').toLowerCase();
  const robloxId = req.headers['roblox-id'] || req.headers['x-roblox-id'];

  if (
    req.headers['sec-fetch-site'] ||
    req.headers['sec-fetch-mode'] ||
    req.headers['sec-fetch-dest'] ||
    req.headers['sec-ch-ua'] ||
    req.headers['referer'] ||
    req.headers['origin'] ||
    accept.includes('text/html')
  ) {
    return false;
  }

  if (robloxId && !/^\d+$/.test(String(robloxId))) {
    return false;
  }

  return ua.includes('roblox') || Boolean(robloxId);
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
