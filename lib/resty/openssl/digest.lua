local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc
local ffi_str = ffi.string

require "resty.openssl.include.evp"
local ctypes = require "resty.openssl.aux.ctypes"
local format_error = require("resty.openssl.err").format_error
local OPENSSL_10 = require("resty.openssl.version").OPENSSL_10
local OPENSSL_11_OR_LATER = require("resty.openssl.version").OPENSSL_11_OR_LATER

local _M = {}
local mt = {__index = _M}

local md_ctx_ptr_ct = ffi.typeof('EVP_MD_CTX*')

function _M.new(typ)
  local ctx
  if OPENSSL_11_OR_LATER then
    ctx = C.EVP_MD_CTX_new()
    ffi_gc(ctx, C.EVP_MD_CTX_free)
  elseif OPENSSL_10 then
    ctx = C.EVP_MD_CTX_create()
    ffi_gc(ctx, C.EVP_MD_CTX_destroy)
  end
  if ctx == nil then
    return nil, "digest.new: failed to create EVP_MD_CTX"
  end

  local dtyp
  if typ == "null" then
    dtyp = C.EVP_md_null()
  else
    dtyp = C.EVP_get_digestbyname(typ or 'sha1')
    if dtyp == nil then
      return nil, string.format("digest.new: invalid digest type \"%s\"", typ)
    end
  end

  local code = C.EVP_DigestInit_ex(ctx, dtyp, nil)
  if code ~= 1 then
    return nil, format_error("digest.new")
  end

  return setmetatable({
    ctx = ctx,
    dtyp = dtyp,
    buf = ctypes.uchar_array(C.EVP_MD_size(dtyp)),
  }, mt), nil
end

function _M.istype(l)
  return l and l.ctx and ffi.istype(md_ctx_ptr_ct, l.ctx)
end

function _M:update(...)
  for _, s in ipairs({...}) do
    if C.EVP_DigestUpdate(self.ctx, s, #s) ~= 1 then
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

  local length = ctypes.ptr_of_uint()
  -- no return value of EVP_DigestFinal_ex
  C.EVP_DigestFinal_ex(self.ctx, self.buf, length)
  if length[0] == nil or length[0] <= 0 then
    return nil, format_error("digest:final: EVP_DigestFinal_ex")
  end
  return ffi_str(self.buf, length[0])
end

function _M:reset()
  local code = C.EVP_DigestInit_ex(self.ctx, self.dtyp, nil)
  if code ~= 1 then
    return false, format_error("digest:reset")
  end

  return true
end

return _M
