const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'gg_secret_key_change_in_prod_99482';
global.ggScripts = global.ggScripts || new Map();

function generateKey(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

function xorEncrypt(text, key) {
  const result = [];
  for (let i = 0; i < text.length; i++) {
    result.push(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return result;
}

function buildProtectedPayload(rawLua, options) {
  const xorKey = generateKey(16);
  const encryptedBytes = xorEncrypt(rawLua, xorKey);
  const byteArrayStr = `{${encryptedBytes.join(',')}}`;

  let layers = `
local _GG_ENV = getfenv and getfenv() or _ENV
local _GG_S = string
local _GG_T = table
local _GG_M = math
local _GG_P = pcall
local _GG_TYPE = type
local _GG_TONUM = tonumber
local _GG_CHAR = _GG_S.char
local _GG_BYTE = _GG_S.byte
local _GG_SUB = _GG_S.sub
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

if _GG_CHK_HOOK(loadstring) or _GG_CHK_HOOK(_GG_P) or _GG_CHK_HOOK(_GG_CHAR) or _GG_CHK_HOOK(game.HttpGet) then
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
  local _GG_GUARD = _GG_P(function()
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
local _GG_RUN, _GG_ERR = loadstring(_GG_CONCAT(_GG_OUT))
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
  const token = authHeader.replace('Bearer ', '');

  try {
    jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Unauthorized session' });
  }

  const { script, options } = req.body || {};
  if (!script || typeof script !== 'string' || script.trim().length === 0) {
    return res.status(400).json({ error: 'Empty Lua source' });
  }

  const scriptId = crypto.randomBytes(12).toString('hex');
  const protectedSource = buildProtectedPayload(script, {
    antiBootstrap: Boolean(options?.antiBootstrap),
    antiDump: Boolean(options?.antiDump),
    antiEnvLog: Boolean(options?.antiEnvLog),
    antiHook: Boolean(options?.antiHook)
  });

  global.ggScripts.set(scriptId, {
    payload: protectedSource,
    createdAt: Date.now()
  });

  const host = req.headers.host || 'ghostguardian.vercel.app';
  const loaderUrl = `https://${host}/v1/loaders/${scriptId}`;
  const loadstring = `loadstring(game:HttpGet("${loaderUrl}"))()`;

  return res.status(200).json({
    id: scriptId,
    loaderUrl,
    loadstring
  });
};
