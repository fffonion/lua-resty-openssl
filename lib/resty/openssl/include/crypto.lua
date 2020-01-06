local ffi = require "ffi"
local C = ffi.C

local OPENSSL_10 = require("resty.openssl.version").OPENSSL_10
local OPENSSL_11 = require("resty.openssl.version").OPENSSL_11

local OPENSSL_free
if OPENSSL_10 then
  ffi.cdef [[
    void CRYPTO_free(void *ptr);
  ]]
  OPENSSL_free = C.CRYPTO_free
elseif OPENSSL_11 then
  ffi.cdef [[
    void CRYPTO_free(void *ptr, const char *file, int line);
  ]]
  OPENSSL_free = function(ptr)
    -- file and line is for debuggin only, since we can't know the c file info
    -- the macro is expanded, just ignore this
    C.CRYPTO_free(ptr, "", 0)
  end
end

return {
  OPENSSL_free = OPENSSL_free,
}
