local ffi = require "ffi"
local ffi_cast = ffi.cast
local C = ffi.C
require "resty.openssl.include.crypto"

local _M = {}

function _M.memcmp(a, b, len)
  if type(a) ~= "string" or type(b) ~= "string" or type(len) ~= "number" or len < 1 then
    return nil, "crypto:memcmp invalid args"
  end

  return C.CRYPTO_memcmp(ffi_cast("void*", a), ffi_cast("void*", b), len)
end

return _M
