local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc
local ffi_new = ffi.new
local ffi_str = ffi.string

require "resty.openssl.include.hmac"
local evp_macro = require "resty.openssl.include.evp"
local format_error = require("resty.openssl.err").format_error
local OPENSSL_10 = require("resty.openssl.version").OPENSSL_10
local OPENSSL_11 = require("resty.openssl.version").OPENSSL_11

local _M = {}
local mt = {__index = _M}

local hmac_ctx_ptr_ct = ffi.typeof('HMAC_CTX*')

function _M.new(key, typ)
  local ctx
  if OPENSSL_11 then
    ctx = C.HMAC_CTX_new()
    ffi_gc(ctx, C.HMAC_CTX_free)
  elseif OPENSSL_10 then
    ctx = ffi.new('HMAC_CTX')
    C.HMAC_CTX_init(ctx)
    ffi_gc(ctx, C.HMAC_CTX_cleanup)
  end
  if ctx == nil then
    return nil, "hmac.new: failed to create HMAC_CTX"
  end

  local dtyp = C.EVP_get_digestbyname(typ or 'sha1')
  if dtyp == nil then
    return nil, string.format("hmac.new: invalid digest type \"%s\"", typ)
  end

  local code = C.HMAC_Init_ex(ctx, key, #key, dtyp, nil)
  if code ~= 1 then
    return nil, format_error("hmac.new")
  end

  return setmetatable({
    ctx = ctx,
    md_size = C.EVP_MD_size(dtyp),
  }, mt), nil
end

function _M.istype(l)
  return l and l.ctx and ffi.istype(hmac_ctx_ptr_ct, l.ctx)
end

function _M:update(...)
  for _, s in ipairs({...}) do
    if C.HMAC_Update(self.ctx, s, #s) ~= 1 then
      return false, format_error("hmac:update")
    end
  end
  return true, nil
end

local uint_ptr = ffi.typeof("unsigned int[1]")

function _M:final(s)
  if s then
    local _, err = self:update(s)
    if err then
      return nil, err
    end
  end

  local buf = ffi_new('unsigned char[?]', self.md_size)
  local length = uint_ptr()
  if C.HMAC_Final(self.ctx, buf, length) ~= 1 then
    return nil, format_error("hmac:final: HMAC_Final")
  end
  return ffi_str(buf, length[0])
end

return _M
