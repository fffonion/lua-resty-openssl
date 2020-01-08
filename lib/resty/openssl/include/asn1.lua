local ffi = require "ffi"
local C = ffi.C

require "resty.openssl.include.ossl_typ"

ffi.cdef [[
  typedef struct ASN1_VALUE_st ASN1_VALUE;

  typedef struct asn1_type_st ASN1_TYPE;

  ASN1_IA5STRING *ASN1_IA5STRING_new();

  ASN1_STRING *ASN1_STRING_type_new(int type);
  int ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);

  ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai);
  BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai, BIGNUM *bn);

  typedef int time_t;
  ASN1_TIME *ASN1_TIME_set(ASN1_TIME *s, time_t t);

  int ASN1_INTEGER_set(ASN1_INTEGER *a, long v);
  long ASN1_INTEGER_get(const ASN1_INTEGER *a);
]]

local function declare_asn1_functions(typ)
  local t = {}
  for i=1, 7 do
    t[i] = typ
  end

  ffi.cdef(string.format([[
    %s *%s_new(void);
    void %s_free(%s *a);
    %s *%s_dup(%s *a);
  ]], unpack(t))
  )
end

declare_asn1_functions("ASN1_INTEGER")
declare_asn1_functions("ASN1_OBJECT")
declare_asn1_functions("ASN1_STRING")

local OPENSSL_10 = require("resty.openssl.version").OPENSSL_10
local OPENSSL_11 = require("resty.openssl.version").OPENSSL_11

local ASN1_STRING_get0_data
if OPENSSL_11 then
  ffi.cdef[[
    const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x);
  ]]
  ASN1_STRING_get0_data = C.ASN1_STRING_get0_data
elseif OPENSSL_10 then
  ffi.cdef[[
    unsigned char *ASN1_STRING_data(ASN1_STRING *x);
  ]]
  ASN1_STRING_get0_data = C.ASN1_STRING_data
end

return {
  ASN1_STRING_get0_data = ASN1_STRING_get0_data,
  declare_asn1_functions = declare_asn1_functions,
}
