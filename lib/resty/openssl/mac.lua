local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc
local ffi_str = ffi.string

require "resty.openssl.include.evp.mac"
local params_macro = require "resty.openssl.include.param"
local ctypes = require "resty.openssl.auxiliary.ctypes"
local format_error = require("resty.openssl.err").format_error
local OPENSSL_30 = require("resty.openssl.version").OPENSSL_30

local _M = {}
local mt = {__index = _M}

local mac_ctx_ptr_ct = ffi.typeof('EVP_MAC*')
local param_types = {
  cipher = params_macro.OSSL_PARAM_UTF8_STRING,
  digest = params_macro.OSSL_PARAM_UTF8_STRING,
}
local params = {}

function _M.new(key, typ, cipher, digest, properties)
  if not OPENSSL_30 then
    return false, "EVP_MAC is only supported from OpenSSL 3.0"
  end

  local dtyp = C.EVP_MAC_fetch(nil, typ, properties)
  if dtyp == nil then
    return nil, format_error(string.format("mac.new: invalid mac type \"%s\"", typ))
  end

  local ctx = C.EVP_MAC_CTX_new(dtyp)
  if ctx == nil then
    return nil, "mac.new: failed to create EVP_MAC_CTX"
  end
  ffi_gc(ctx, C.EVP_MAC_CTX_free)
  
  params.digest = digest
  params.cipher = cipher
  local p = params_macro.construct(params, 2, param_types)

  local code = C.EVP_MAC_init(ctx, key, #key, p)
  if code ~= 1 then
    return nil, format_error(string.format("mac.new: invalid cipher or digest type"))
  end

  local md_size = C.EVP_MAC_CTX_get_mac_size(ctx)

  return setmetatable({
    ctx = ctx,
    dtyp = dtyp,
    buf = ctypes.uchar_array(md_size),
    buf_size = md_size,
  }, mt), nil
end

function _M.istype(l)
  return l and l.ctx and ffi.istype(mac_ctx_ptr_ct, l.ctx)
end

function _M:get_provider_name()
  local p = C.EVP_MAC_get0_provider(self.dtyp)
  if p == nil then
    return nil
  end
  return ffi_str(C.OSSL_PROVIDER_get0_name(p))
end

function _M:update(...)
  for _, s in ipairs({...}) do
    if C.EVP_MAC_update(self.ctx, s, #s) ~= 1 then
      return false, format_error("digest:update")
    end
  end
  return true, nil
end

function _M:final(s)
  if s then
    local _, err = self:update(s)
    if err then
      return nil, err
    end
  end

  local length = ctypes.ptr_of_size_t()
  -- no return value of EVP_DigestFinal_ex
  C.EVP_MAC_final(self.ctx, self.buf, length, self.buf_size)
  if length[0] == nil or length[0] <= 0 then
    return nil, format_error("digest:final: EVP_MAC_final")
  end
  return ffi_str(self.buf, length[0])
end

return _M
