const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'gg_secret_key_change_in_prod_99482';
global.ggUsers = global.ggUsers || new Map();

module.exports = async (req, res) => {
  res.setHeader('Content-Type', 'application/json');

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { action, username, password } = req.body || {};

  if (!username || !password || username.length < 3 || password.length < 5) {
    return res.status(400).json({ error: 'Invalid credentials format' });
  }

  const cleanUser = username.trim().toLowerCase();

  if (action === 'register') {
    if (global.ggUsers.has(cleanUser)) {
      return res.status(409).json({ error: 'Account already exists' });
    }
    const hash = await bcrypt.hash(password, 10);
    global.ggUsers.set(cleanUser, { username: cleanUser, hash });
    const token = jwt.sign({ username: cleanUser }, JWT_SECRET, { expiresIn: '7d' });
    return res.status(201).json({ token, username: cleanUser });
  }

  if (action === 'login') {
    const user = global.ggUsers.get(cleanUser);
    if (!user) {
      return res.status(401).json({ error: 'Account not found' });
    }
    const valid = await bcrypt.compare(password, user.hash);
    if (!valid) {
      return res.status(401).json({ error: 'Incorrect password' });
    }
    const token = jwt.sign({ username: cleanUser }, JWT_SECRET, { expiresIn: '7d' });
    return res.status(200).json({ token, username: cleanUser });
  }

  return res.status(400).json({ error: 'Invalid action' });
};
