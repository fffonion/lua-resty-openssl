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

local cipher_ctx_ptr_ct = ffi.typeof('EVP_CIPHER_CTX*')

function _M.new(typ)
  if not typ then
    return nil, "expect type to be defined"
  end

  local ctx
  if OPENSSL_11 then
    ctx = C.EVP_CIPHER_CTX_new()
    ffi_gc(ctx, C.EVP_CIPHER_CTX_free)
  elseif OPENSSL_10 then
    ctx = ffi.new('EVP_CIPHER_CTX')
    C.EVP_CIPHER_CTX_init(ctx)
    ffi_gc(ctx, C.EVP_CIPHER_CTX_cleanup)
  end
  if ctx == nil then
    return nil, "failed to create EVP_CIPHER_CTX"
  end

  local dtyp = C.EVP_get_cipherbyname(typ)
  if dtyp == nil then
    return nil, string.format("invalid cipher type \"%s\"", typ)
  end

  local code = C.EVP_CipherInit_ex(ctx, dtyp, nil, "", nil, -1)
  if code ~= 1 then
    return nil, format_error("cipher.new")
  end

  return setmetatable({
    ctx = ctx,
    initialized = false,
    block_size = tonumber(C.EVP_CIPHER_CTX_block_size(ctx)),
    key_size = tonumber(C.EVP_CIPHER_CTX_key_length(ctx)),
    iv_size = tonumber(C.EVP_CIPHER_CTX_iv_length(ctx)),
  }, mt), nil
end

function _M.istype(l)
  return l and l.ctx and ffi.istype(cipher_ctx_ptr_ct, l.ctx)
end

function _M:init(key, iv, opts)
  opts = opts or {}
  if not key or #key ~= self.key_size then
    return string.format("incorrect key size, expect %d", self.key_size)
  end
  if not iv or #iv ~= self.iv_size then
    return string.format("incorrect iv size, expect %d", self.iv_size)
  end

  if C.EVP_CipherInit_ex(self.ctx, nil, nil, key, iv, opts.is_encrypt and 1 or 0) == 0 then
    return format_error("cipher:init")
  end

  if opts.no_padding then
    -- EVP_CIPHER_CTX_set_padding() always returns 1.
    C.EVP_CIPHER_CTX_set_padding(self.ctx, 0)
  end

  self.initialized = true
end

function _M:encrypt(key, iv, s, no_padding)
  local err = self:init(key, iv, {
    is_encrypt = true,
    no_padding = no_padding,
  })
  if err then
    return nil, err
  end
  return self:final(s)
end

function _M:decrypt(key, iv, s, no_padding)
  local err = self:init(key, iv, {
    is_encrypt = false,
    no_padding = no_padding,
  })
  if err then
    return nil, err
  end
  return self:final(s)
end

local int_ptr = ffi.typeof("int[1]")
function _M:update(...)
  if not self.initialized then
    return nil, "cipher not initalized, call cipher:init first"
  end

  local ret = {}
  local max_length = 0
  for _, s in ipairs({...}) do
    local len = #s
    if len > max_length then
      max_length = len
    end
  end
  if max_length == 0 then
    return nil
  end
  local out = ffi_new('unsigned char[?]', max_length + self.block_size)
  local outl = int_ptr()
  for _, s in ipairs({...}) do
    if C.EVP_CipherUpdate(self.ctx, out, outl, s, #s) ~= 1 then
      return nil, format_error("cipher:update")
    end
    table.insert(ret, ffi_str(out, outl[0]))
  end
  return table.concat(ret, "")
end

function _M:final(s)
  local ret, err
  if s then
    ret, err = self:update(s)
    if err then
      return nil, err
    end
  end
  local outm = ffi_new('unsigned char[?]', self.block_size)
  local outl = int_ptr()
  if C.EVP_CipherFinal(self.ctx, outm, outl) ~= 1 then
    return nil, format_error("cipher:final: EVP_CipherFinal")
  end
  return (ret or "") .. ffi_str(outm, outl[0])
end

return _M
