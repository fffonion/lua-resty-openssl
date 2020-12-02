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
    assert(nm:add(k, v))
  end

  assert(cert:set_subject_name(nm))
  assert(cert:set_issuer_name(nm))

  assert(cert:sign(key))

  -- make sure the private key is not included
  cert = x509.new(cert:to_PEM())

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

-- https://github.com/openresty/lua-cjson/blob/461c7ef23a49062d4b1bf0e1afb3be294d007861/tests/sort_json.lua

-- NOTE: This will only work for simple tests. It doesn't parse strings so if
-- you put any symbols like {?[], inside of a string literal then it will break
-- The point of this function is to test basic structures, and not test JSON
-- strings

local function sort_callback(str)
  local inside = str:sub(2, -2)

  local parts = {}
  local buffer = ""
  local pos = 1

  while true do
    if pos > #inside then
      break
    end

    local append

    local parens = inside:match("^%b{}", pos)
    if parens then
      pos = pos + #parens
      append = sort_callback(parens)
    else
      local array = inside:match("^%b[]", pos)
      if array then
        pos = pos + #array
        append = array
      else
        local front = inside:sub(pos, pos)
        pos = pos + 1

        if front == "," then
          table.insert(parts, buffer)
          buffer = ""
        else
          append = front
        end
      end
    end

    if append then
      buffer = buffer .. append
    end
  end

  if buffer ~= "" then
    table.insert(parts, buffer)
  end

  table.sort(parts)

  return "{" .. table.concat(parts, ",") .. "}"
end

local function sort_json(str)
  return (str:gsub("%b{}", sort_callback))
end

local function encode_sorted_json(tbl)
  return sort_json(require("cjson").encode(tbl))
end


return {
  create_self_signed = create_self_signed,
  to_hex = to_hex,
  myassert = myassert,
  encode_sorted_json = encode_sorted_json,
}