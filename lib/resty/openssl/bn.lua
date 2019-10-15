local ffi = require "ffi"

local C = ffi.C
local ffi_gc = ffi.gc
local ffi_new = ffi.new
local ffi_str = ffi.string
local floor = math.floor

local _M = {}
local mt = {__index = _M}

require "resty.openssl.ossl_typ"
local format_error = require("resty.openssl.err").format_error

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
]]
)

local bn_ptr_ct = ffi.typeof('BIGNUM*')

function _M.new(bn)
  local ctx = C.BN_new()
  ffi_gc(ctx, C.BN_free)

  if type(bn) == 'number' then
    if C.BN_set_word(ctx, bn) ~= 1 then
      return nil, format_error("bn.new")
    end
  elseif bn then
    return nil, "expect nil or a number at #1"
  end

  return setmetatable( { ctx = ctx }, mt), nil
end

function _M.istype(l)
  return l and l.ctx and ffi.istype(bn_ptr_ct, l.ctx)
end

function _M:to_binary()
  local length = (C.BN_num_bits(self.ctx)+7)/8
  -- align to bytes
  length = floor(length)
  local buf = ffi_new('unsigned char[?]', length)
  local sz = C.BN_bn2bin(self.ctx, buf)
  if sz == 0 then
    return nil, format_error("bn:to_binary")
  end
  buf = ffi_str(buf, length)
  return buf, nil
end

function _M.from_binary(s)
  if not s or type(s) ~= "string" then
    return nil, "expect a string at #1"
  end

  local ctx = C.BN_bin2bn(s, #s, nil)
  if ctx == nil then
    return nil, format_error("bn.from_binary")
  end
  ffi_gc(ctx, C.BN_free)
  return setmetatable( { ctx = ctx }, mt), nil
end

function _M.dup(ctx)
  if not ffi.istype(bn_ptr_ct, ctx) then
    return nil, "expect a bn ctx at #1"
  end
  local ctx = C.BN_dup(ctx)
  ffi_gc(ctx, C.BN_free)

  local self = setmetatable({
    ctx = ctx,
  }, mt)

  return self, nil
end

return _M
