local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc
local ffi_new = ffi.new
local ffi_str = ffi.string
local floor = math.floor

require "resty.openssl.include.bn"
local crypto_macro = require("resty.openssl.include.crypto")
local format_error = require("resty.openssl.err").format_error

local _M = {}
local mt = {__index = _M}

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

function _M:to_hex()
  local buf = C.BN_bn2hex(self.ctx)
  if buf == nil then
    return nil, format_error("bn:to_hex")
  end
  local s = ffi_str(buf)
  crypto_macro.OPENSSL_free(buf)
  return s, nil
end

function _M.from_binary(s)
  if type(s) ~= "string" then
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
