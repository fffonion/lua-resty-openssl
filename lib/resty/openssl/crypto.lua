local ffi = require "ffi"
local buffer = require "string.buffer"
local ffi_cast = ffi.cast
local C = ffi.C
require "resty.openssl.include.crypto"

local _M = {}

function _M.memcmp(a, b, len)
  if type(len) ~= "number" or len < 1 then
    return nil, "crypto:memcmp arg 'len' must be a number > 0"
  end
  local err

  if type(a) ~= "string" and type(a) ~= "cdata" then
    a, err = buffer.encode(a)
    if err ~= nil then
      return nil, "crypto:memcmp buffer.encode " .. err
    end
  end

  if type(b) ~= "string" and type(b) ~= "cdata" then
    b, err = buffer.encode(b)
    if err ~= nil then
      return nil, "crypto:memcmp buffer.encode " .. err
    end
  end

  return C.CRYPTO_memcmp(ffi_cast("void*", a), ffi_cast("void*", b), len)
end

return _M
