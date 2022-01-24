local ffi = require "ffi"
local C = ffi.C
local ffi_str = ffi.string

require "resty.openssl.include.rand"
local ctx_lib = require "resty.openssl.ctx"
local ctypes = require "resty.openssl.auxiliary.ctypes"
local format_error = require("resty.openssl.err").format_error
local OPENSSL_30 = require("resty.openssl.version").OPENSSL_30

local function bytes(length, private, strength)
  if type(length) ~= "number" then
    return nil, "rand.bytes: expect a number at #1"
  elseif strength and type(strength) ~= "number" then
    return nil, "rand.bytes: expect a number at #3"
  end
  -- generally we don't need manually reseed rng
  -- https://www.openssl.org/docs/man1.1.1/man3/RAND_seed.html
  local buf = ctypes.uchar_array(length)
  local code
  if OPENSSL_30 then
    if private then
      code = C.RAND_priv_bytes_ex(ctx_lib.get_libctx(), buf, length, strength or 0)
    else
      code = C.RAND_bytes_ex(ctx_lib.get_libctx(), buf, length, strength or 0)
    end
  else
    if private then
      code = C.RAND_priv_bytes(buf, length)
    else
      code = C.RAND_bytes(buf, length)
    end
  end
  if code ~= 1 then
    return nil, format_error("rand.bytes", code)
  end

  return ffi_str(buf, length)
end

return {
  bytes = bytes,
}
