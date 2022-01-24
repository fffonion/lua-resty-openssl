local ffi = require "ffi"

require "resty.openssl.include.ossl_typ"
local OPENSSL_30 = require("resty.openssl.version").OPENSSL_30

ffi.cdef [[
  int RAND_bytes(unsigned char *buf, int num);
  int RAND_priv_bytes(unsigned char *buf, int num);
]]

if OPENSSL_30 then
  ffi.cdef [[
    int RAND_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num,
                      unsigned int strength);
    int RAND_priv_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num,
                      unsigned int strength);
  ]]
end
