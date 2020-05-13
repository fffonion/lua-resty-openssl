local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc
local ffi_new = ffi.new
local ffi_str = ffi.string

require "resty.openssl.include.evp"
local format_error = require("resty.openssl.err").format_error
local OPENSSL_10 = require("resty.openssl.version").OPENSSL_10
local OPENSSL_11 = require("resty.openssl.version").OPENSSL_11

local _M = {}
local mt = {__index = _M}

local md_ctx_ptr_ct = ffi.typeof('EVP_MD_CTX*')

function _M.new(typ)
  local ctx
  if OPENSSL_11 then
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
    md_size = C.EVP_MD_size(dtyp),
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
  -- no return value of EVP_DigestFinal_ex
  C.EVP_DigestFinal_ex(self.ctx, buf, length)
  if length[0] == nil or length[0] <= 0 then
    return nil, format_error("digest:final: EVP_DigestFinal_ex")
  end
  return ffi_str(buf, length[0])
end

return _M
