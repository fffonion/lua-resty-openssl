local ffi = require "ffi"

local C = ffi.C
local ffi_gc = ffi.gc
local ffi_new = ffi.new
local ffi_str = ffi.string

local floor = math.floor

local _M = {}
local mt = {__index = _M}

require "resty.openssl.ossl_typ"

ffi.cdef [[
  typedef struct ASN1_VALUE_st ASN1_VALUE;

  typedef struct asn1_type_st ASN1_TYPE;

  // macro in asn1.h
  ASN1_OBJECT *ASN1_OBJECT_new(void);
  void ASN1_OBJECT_free(ASN1_OBJECT *a);

  void ASN1_INTEGER_free(ASN1_INTEGER *a);

  ASN1_STRING *ASN1_STRING_type_new(int type);
  int ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);

  ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai);

  typedef int time_t;
  ASN1_TIME *ASN1_TIME_set(ASN1_TIME *s, time_t t);

  long ASN1_INTEGER_get(const ASN1_INTEGER *a);
]]

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

-- https://github.com/wahern/luaossl/blob/master/src/openssl.c
local function isleap(year)
	return (year % 4) == 0 and ((year % 100) > 0 or (year % 400) == 0)
end

local past = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 }
local function yday(year, mon, mday)
	local d = past[mon] + mday - 1
  if mon > 2 and isleap(year) then
    d = d + 1
  end
	return d
end

local function leaps(year)
  return floor(year / 400) + floor(year / 4) - floor(year / 100)
end

-- make sure this code works after 100 years
local yyyy = tonumber(ngx.today():sub(1, 4))
local yy00 = yyyy - yyyy % 100

local function asn1_to_unix(asn1)
  local s = ASN1_STRING_get0_data(asn1)
  local s = ffi_str(s)
  -- 190303223958Z
  local year = yy00 + tonumber(s:sub(1, 2))
  local month = tonumber(s:sub(3, 4))
  local day = tonumber(s:sub(5, 6))
  local hour = tonumber(s:sub(7, 8))
  local minute = tonumber(s:sub(9, 10))
  local second = tonumber(s:sub(11, 12))

  local tm = 0
  tm = (year - 1970) * 365
  tm = tm + leaps(year - 1) - leaps(1969)
  tm = (tm + yday(year, month, day)) * 24
  tm = (tm + hour) * 60
  tm = (tm + minute) * 60
  tm = tm + second
  return tm
end

return {
  asn1_to_unix = asn1_to_unix,
}
  
