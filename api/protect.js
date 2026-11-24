const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'gg_secret_key_change_in_prod_99482';
global.ggStore = global.ggStore || { byUser: new Map(), latest: null };

function xorBytes(buf, keyBuf) {
  const out = [];
  for (let i = 0; i < buf.length; i++) {
    out.push(buf[i] ^ keyBuf[i % keyBuf.length]);
  }
  return out;
}

function buildProtectedPayload(rawLua, options) {
  const xorKey = crypto.randomBytes(16).toString('hex');
  const rawBuf = Buffer.from(rawLua, 'utf8');
  const encryptedBytes = xorBytes(rawBuf, Buffer.from(xorKey, 'utf8'));
  const byteArrayStr = `{${encryptedBytes.join(',')}}`;

  let layers = `
local _GG_ENV = getfenv and getfenv() or _ENV
local _GG_S = string
local _GG_T = table
local _GG_P = pcall
local _GG_TYPE = type
local _GG_CHAR = _GG_S.char
local _GG_BYTE = _GG_S.byte
local _GG_LEN = _GG_S.len
local _GG_CONCAT = _GG_T.concat
local _GG_INSERT = _GG_T.insert
`;

  if (options.antiHook) {
    layers += `
local function _GG_CHK_HOOK(fn)
  if _GG_TYPE(fn) ~= "function" then return true end
  if debug and debug.getinfo then
    local info = debug.getinfo(fn, "S")
    if info and info.what ~= "C" then return true end
  end
  if iscclosure and not iscclosure(fn) then return true end
  if isfunctionhooked and isfunctionhooked(fn) then return true end
  return false
end
if _GG_CHK_HOOK(loadstring) or _GG_CHK_HOOK(_GG_P) or _GG_CHK_HOOK(_GG_CHAR) then
  while true do end
end
`;
  }

  if (options.antiEnvLog) {
    layers += `
local _GG_RAW_G = getgenv and getgenv() or _G
if _GG_RAW_G ~= _GG_ENV then
  local mt = getmetatable(_GG_ENV)
  if mt and (mt.__index or mt.__newindex) then
    while true do end
  end
end
`;
  }

  if (options.antiDump) {
    layers += `
if getgc or getconstants or getprotos or getupvalues then
  _GG_P(function()
    if debug and debug.sethook then
      debug.sethook(function()
        if debug.getinfo(2, "S").what == "Lua" then
          error("GG_TAMPER_DETECTED", 0)
        end
      end, "c")
    end
  end)
end
`;
  }

  if (options.antiBootstrap) {
    layers += `
if not game or not game:GetService("Players") or game.PlaceId == 0 then
  return
end
local _GG_EXEC = identifyexecutor and identifyexecutor() or ""
if _GG_EXEC == "" or _GG_S.find(_GG_S.lower(_GG_EXEC), "studio") then
  return
end
`;
  }

  layers += `
local _GG_K = "${xorKey}"
local _GG_D = ${byteArrayStr}
local _GG_OUT = {}
local _GG_KL = _GG_LEN(_GG_K)
for i = 1, #_GG_D do
  local kByte = _GG_BYTE(_GG_K, ((i - 1) % _GG_KL) + 1)
  local dec = bit32 and bit32.bxor(_GG_D[i], kByte) or ((_GG_D[i] + kByte) % 256)
  _GG_INSERT(_GG_OUT, _GG_CHAR(dec))
end
if debug and debug.sethook then debug.sethook() end
local _GG_RUN = loadstring(_GG_CONCAT(_GG_OUT))
if _GG_RUN then
  _GG_RUN()
end
`;

  return layers.replace(/\n+/g, ' ').replace(/\s+/g, ' ').trim();
}

module.exports = async (req, res) => {
  res.setHeader('Content-Type', 'application/json');

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const authHeader = req.headers.authorization || '';
  const authJwt = authHeader.replace('Bearer ', '');

  let decoded;
  try {
    decoded = jwt.verify(authJwt, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Unauthorized session' });
  }

  const { script, options } = req.body || {};
  if (!script || typeof script !== 'string' || script.trim().length === 0) {
    return res.status(400).json({ error: 'Empty Lua source' });
  }

  const protectedSource = buildProtectedPayload(script, {
    antiBootstrap: Boolean(options?.antiBootstrap),
    antiDump: Boolean(options?.antiDump),
    antiEnvLog: Boolean(options?.antiEnvLog),
    antiHook: Boolean(options?.antiHook)
  });

  const userSlug = String(decoded.username || 'loader')
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, '');

  global.ggStore.byUser.set(userSlug, protectedSource);
  global.ggStore.latest = protectedSource;

  const host = req.headers.host || 'ghostguardian.vercel.app';
  const loaderUrl = `https://${host}/v1/loaders/${userSlug}`;
  const loadstring = `loadstring(game:HttpGet("${loaderUrl}"))()`;

  return res.status(200).json({
    id: userSlug,
    loaderUrl,
    loadstring
  });
};
