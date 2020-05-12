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
    return nil, "cipher.new: expect type to be defined"
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
    return nil, "cipher.new: failed to create EVP_CIPHER_CTX"
  end

  local dtyp = C.EVP_get_cipherbyname(typ)
  if dtyp == nil then
    return nil, string.format("cipher.new: invalid cipher type \"%s\"", typ)
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
    return false, string.format("cipher:init: incorrect key size, expect %d", self.key_size)
  end
  if not iv or #iv ~= self.iv_size then
    return false, string.format("cipher:init: incorrect iv size, expect %d", self.iv_size)
  end

  if C.EVP_CipherInit_ex(self.ctx, nil, nil, key, iv, opts.is_encrypt and 1 or 0) == 0 then
    return false, format_error("cipher:init")
  end

  if opts.no_padding then
    -- EVP_CIPHER_CTX_set_padding() always returns 1.
    C.EVP_CIPHER_CTX_set_padding(self.ctx, 0)
  end

  self.initialized = true

  return true
end

function _M:encrypt(key, iv, s, no_padding)
  local _, err = self:init(key, iv, {
    is_encrypt = true,
    no_padding = no_padding,
  })
  if err then
    return nil, err
  end
  return self:final(s)
end

function _M:decrypt(key, iv, s, no_padding)
  local _, err = self:init(key, iv, {
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
    return nil, "cipher:update: cipher not initalized, call cipher:init first"
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

function _M:derive(key, salt, count, md)
  if type(key) ~= "string" then
    return nil, nil, "cipher:derive: expect a string at #1"
  elseif salt and type(salt) ~= "string" then
    return nil, nil, "cipher:derive: expect a string at #2"
  elseif count then
    count = tonumber(count)
    if not count then
      return nil, nil, "cipher:derive: expect a number at #3"
    end
  elseif md and type(md) ~= "string" then
    return nil, nil, "cipher:derive: expect a string or nil at #4"
  end

  if salt then
    if #salt > 8 then
      ngx.log(ngx.WARN, "cipher:derive: salt is too long, truncate salt to 8 bytes")
      salt = salt:sub(0, 8)
    elseif #salt < 8 then
      ngx.log(ngx.WARN, "cipher:derive: salt is too short, padding with zero bytes to length")
      salt = salt .. string.rep('\000', 8 - #salt)
    end
  end

  local mdt = C.EVP_get_digestbyname(md or 'sha1')
  if mdt == nil then
    return nil, nil, string.format("cipher:derive: invalid digest type \"%s\"", md)
  end
  local cipt = C.EVP_CIPHER_CTX_cipher(self.ctx)
  local keyb = ffi_new('unsigned char[?]', self.key_size)
  local ivb = ffi_new('unsigned char[?]', self.iv_size)

  local size = C.EVP_BytesToKey(cipt, mdt, salt,
                                key, #key, count or 1,
                                keyb, ivb)
  if size == 0 then
    return nil, nil, format_error("cipher:derive: EVP_BytesToKey")
  end

  return ffi_str(keyb, size), ffi_str(ivb, self.iv_size)
end

return _M
