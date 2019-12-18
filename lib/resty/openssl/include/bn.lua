local ffi = require "ffi"

require "resty.openssl.include.ossl_typ"

local BN_ULONG
if ffi.abi('64bit') then
  BN_ULONG = 'unsigned long long'
else -- 32bit
  BN_ULONG = 'unsigned int'
end

ffi.cdef(
[[
  BIGNUM *BN_new(void);
  void BN_free(BIGNUM *a);
  BIGNUM *BN_dup(const BIGNUM *a);
  int BN_add_word(BIGNUM *a, ]] .. BN_ULONG ..[[ w);
  int BN_set_word(BIGNUM *a, ]] .. BN_ULONG ..[[ w);
  int BN_num_bits(const BIGNUM *a);
  BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
  int BN_bn2bin(const BIGNUM *a, unsigned char *to);
  char *BN_bn2hex(const BIGNUM *a);
]]
)