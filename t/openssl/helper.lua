local pkey = require "resty.openssl.pkey"
local x509 = require "resty.openssl.x509"
local name = require "resty.openssl.x509.name"
local bn = require "resty.openssl.bn"

local function create_self_signed(key_opts, names)
  local key = pkey.new(key_opts or {
    type = 'RSA',
    bits = 1024,
  })

  local cert = x509.new()
  cert:set_pubkey(key)
  cert:set_version(3)

  local now = os.time()
  cert:set_not_before(now)
  cert:set_not_after(now + 86400)

  local nm = name.new()
  for k, v in ipairs(names or {}) do
    nm:add(k, v)
  end

  cert:set_subject_name(nm)
  cert:set_issuer_name(nm)

  cert:sign(key)

  return cert, key
end

local function to_hex(bin)
  local hex, err = bn.from_binary(bin):to_hex()
  if err then
    error(err)
  end
  return hex
end

local function myassert(...)
  local ret = {...}
  local err = ret[#ret]
  if #ret > 1 and err then
    ngx.log(ngx.ERR, tostring(err))
    ngx.exit(0)
  end
  return ...
end


return {
  create_self_signed = create_self_signed,
  to_hex = to_hex,
  myassert = myassert,
}