local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc
local ffi_new = ffi.new
local ffi_str = ffi.string
local ffi_cast = ffi.cast
local ffi_copy = ffi.copy
local null = ngx.null

local rsa_macro = require "resty.openssl.include.rsa"
require "resty.openssl.include.ec"
require "resty.openssl.include.bio"
require "resty.openssl.include.pem"
require "resty.openssl.include.objects"
require "resty.openssl.include.x509"
local evp_macro = require "resty.openssl.include.evp"
local bn_lib = require "resty.openssl.bn"
local util = require "resty.openssl.util"
local digest_lib = require "resty.openssl.digest"
local format_error = require("resty.openssl.err").format_error

local OPENSSL_10 = require("resty.openssl.version").OPENSSL_10
local OPENSSL_11 = require("resty.openssl.version").OPENSSL_11

local function generate_key(config)
  local ctx = C.EVP_PKEY_new()
  if ctx == nil then
    return nil, "EVP_PKEY_new() failed"
  end

  local type = config.type or 'RSA'

  local code, key, key_type

  if type == "RSA" then
    key_type = evp_macro.EVP_PKEY_RSA
    local bits = config.bits or 2048
    if bits > 4294967295 then
      return nil, "bits out of range"
    end
    local exp = C.BN_new()
    ffi_gc(exp, C.BN_free)
    if exp == nil then
      return nil, "BN_new() failed"
    end
    C.BN_set_word(exp, config.exp or 65537)

    key = C.RSA_new()
    if key == nil then
      return nil, "RSA_new() failed"
    end
    code = C.RSA_generate_key_ex(key, bits, exp, nil)
    if code ~= 1 then
      C.RSA_free(key)
      return nil, "RSA_generate_key_ex() failed"
    end
  elseif type == "EC" then
    key_type = evp_macro.EVP_PKEY_EC
    local curve = config.curve or 'prime192v1'
    local nid = C.OBJ_ln2nid(curve)
    if nid == 0 then
      return nil, "unknown curve " .. curve
    end
    local group = C.EC_GROUP_new_by_curve_name(nid)
    if group == nil then
      return nil, "EC_GROUP_new_by_curve_name() failed"
    end
    ffi_gc(group, C.EC_GROUP_free)
    -- # define OPENSSL_EC_NAMED_CURVE     0x001
    C.EC_GROUP_set_asn1_flag(group, 1)
    C.EC_GROUP_set_point_conversion_form(group, C.POINT_CONVERSION_UNCOMPRESSED)

    key = C.EC_KEY_new()
    if key == nil then
      return nil, "EC_KEY_new() failed"
    end
    C.EC_KEY_set_group(key, group)
    code = C.EC_KEY_generate_key(key)
    if code == 0 then
      C.EC_KEY_free(key)
      return nil, "EC_KEY_generate_key() failed"
    end
  else
    return nil, "unsupported type " .. type
  end

  -- don't need to free `key`, it will be freed together with EVP_PKEY_free
  code = C.EVP_PKEY_assign(ctx, key_type, key)
  if code ~= 1 then
    C.EVP_PKEY_free(ctx)
    return nil, "EVP_PKEY_assign() failed"
  end

  return ctx, nil
end

local load_pkey_try_args_pem = { null, null, null }
local load_pkey_try_args_der = { null }

local load_pkey_try_funcs = {
  PEM = {
    -- Note: make sure we always try load priv key first
    pr = {
      ['PEM_read_bio_PrivateKey'] = load_pkey_try_args_pem,
    },
    pu = {
      ['PEM_read_bio_PUBKEY'] = load_pkey_try_args_pem,
    },
  },
  DER = {
    pr = {
      ['d2i_PrivateKey_bio'] = load_pkey_try_args_der,
    },
    pu = {
      ['d2i_PUBKEY_bio'] = load_pkey_try_args_der,
    },
  }
}
-- populate * funcs
local all_funcs = {}
local typ_funcs = {}
for fmt, ffs in pairs(load_pkey_try_funcs) do
  local funcs = {}
  for typ, fs in pairs(ffs) do
    for f, arg in pairs(fs) do
      funcs[f] = arg
      all_funcs[f] = arg
      if not typ_funcs[typ] then
        typ_funcs[typ] = {}
      end
      typ_funcs[typ] = arg
    end
  end
  load_pkey_try_funcs[fmt]["*"] = funcs
end
load_pkey_try_funcs["*"] = {}
load_pkey_try_funcs["*"]["*"] = all_funcs
for typ, fs in pairs(typ_funcs) do
  load_pkey_try_funcs[typ] = fs
end

local function load_pkey(txt, opts)
  local fmt = opts.format or '*'
  if fmt ~= 'PEM' and fmt ~= 'DER' and fmt ~= '*' then
    return nil, "expecting 'DER', 'PEM' or '*' at #2"
  end

  local typ = opts.type or '*'
  if typ ~= 'pu' and typ ~= 'pr' and typ ~= '*' then
    return nil, "expecting 'pr', 'pu' or '*' at #3"
  end

  ngx.log(ngx.DEBUG, "load key using fmt: ", fmt, ", type: ", typ)

  local bio = C.BIO_new_mem_buf(txt, #txt)
  if bio == nil then
    return "BIO_new_mem_buf() failed"
  end
  ffi_gc(bio, C.BIO_free)

  local ctx

  local fs = load_pkey_try_funcs[fmt][typ]
  local passphrase_cb
  for f, arg in pairs(fs) do
    -- #define BIO_CTRL_RESET 1
    local code = C.BIO_ctrl(bio, 1, 0, nil)
    if code ~= 1 then
      return nil, "BIO_ctrl() failed"
    end

    if fmt == "PEM" or fmt == "*" then
      if opts.passphrase then
        local passphrase = opts.passphrase
        if type(passphrase) ~= "string" then
          return nil, "passphrase must be a string"
        end
        arg = { null, nil, passphrase }
      elseif opts.passphrase_cb then
        passphrase_cb = ffi_cast("pem_password_cb*", function(buf, size)
          local p = opts.passphrase_cb()
          local len = #p -- 1 byte for \0
          if len > size then
            ngx.log(ngx.WARN, "passphrase truncated from ", len, " to ", size)
            len = size
          end
          ffi_copy(buf, p, len)
          return len
        end)
        arg = { null, passphrase_cb, null }
      end
    end

    ctx = C[f](bio, unpack(arg))
    if ctx ~= nil then
      ngx.log(ngx.DEBUG, "loaded pkey using ", f)
      break
    end
  end
  if passphrase_cb ~= nil then
    passphrase_cb:free()
  end

  if ctx == nil then
    return nil, format_error("pkey.new:load_pkey")
  end
  -- clear errors occur when trying
  C.ERR_clear_error()
  return ctx, nil
end

local function tostring(self, fmt)
  if fmt == 'private' or fmt == 'PrivateKey' then
    return util.read_using_bio(C.PEM_write_bio_PrivateKey,
      self.ctx,
      nil, nil, 0, nil, nil)
  elseif not fmt or fmt == 'public' or fmt == 'PublicKey' then
    return util.read_using_bio(C.PEM_write_bio_PUBKEY, self.ctx)
  else
    return nil, "can only export private or public key, not " .. fmt
  end

end

local _M = {}
local mt = { __index = _M, __tostring = tostring }

local empty_table = {}
local evp_pkey_ptr_ct = ffi.typeof('EVP_PKEY*')

function _M.new(s, opts)
  local ctx, err
  s = s or {}
  if type(s) == 'table' then
    ctx, err = generate_key(s)
  elseif type(s) == 'string' then
    ctx, err = load_pkey(s, opts or empty_table)
  elseif type(s) == 'cdata' then
    if ffi.istype(evp_pkey_ptr_ct, s) then
      ctx = s
    else
      return nil, "expect a EVP_PKEY* cdata at #1"
    end
  else
    return nil, "unexpected type " .. type(s) .. " at #1"
  end

  if err then
    return nil, err
  end

  local key_size = C.EVP_PKEY_size(ctx)
  local key_type = C.EVP_PKEY_base_id(ctx)

  if err then
    return nil, err
  end

  local self = setmetatable({
    ctx = ctx,
    pkey_ctx = nil,
    rsa_padding = nil,
    buf = ffi_new('unsigned char[?]', key_size),
    key_type = key_type,
    key_size = key_size,
  }, mt)

  ffi_gc(ctx, C.EVP_PKEY_free)

  return self, nil
end

function _M.istype(l)
  return l and l.ctx and ffi.istype(evp_pkey_ptr_ct, l.ctx)
end

local bn_ptrptr_ct = ffi.typeof("const BIGNUM *[1]")
local function get_rsa_params_11(pkey)
  -- {"n", "e", "d", "p", "q", "dmp1", "dmq1", "iqmp"}
  local rsa_st = C.EVP_PKEY_get0_RSA(pkey)
  if rsa_st == nil then
    return nil, "EVP_PKEY_get0_RSA() failed"
  end

  return setmetatable(empty_table, {
    __index = function(tbl, k)
      if k == 'n' then
        local ptr = bn_ptrptr_ct()
        C.RSA_get0_key(rsa_st, ptr, nil, nil)
        return bn_lib.dup(ptr[0])
      elseif k == 'e' then
        local ptr = bn_ptrptr_ct()
        C.RSA_get0_key(rsa_st, nil, ptr, nil)
        return bn_lib.dup(ptr[0])
      elseif k == 'd' then
        local ptr = bn_ptrptr_ct()
        C.RSA_get0_key(rsa_st, nil, nil, ptr)
        return bn_lib.dup(ptr[0])
      end
    end
  }), nil
end

local function get_rsa_params_10(pkey)
  -- {"n", "e", "d", "p", "q", "dmp1", "dmq1", "iqmp"}

  return setmetatable(empty_table, {
    __index = function(_, k)
      if k == 'n' then
        return bn_lib.dup(pkey.pkey.rsa.n)
      elseif k == 'e' then
        return bn_lib.dup(pkey.pkey.rsa.e)
      elseif k == 'd' then
        return bn_lib.dup(pkey.pkey.rsa.d)
      end
    end
  }), nil
end

function _M:get_parameters()
  if self.key_type == evp_macro.EVP_PKEY_RSA then
    if OPENSSL_11 then
      return get_rsa_params_11(self.ctx)
    elseif OPENSSL_10 then
      return get_rsa_params_10(self.ctx)
    end
  elseif self.key_type == evp_macro.EVP_PKEY_EC then
    return nil, "parameters of EC not supported"
  end

  return nil, "key type not supported"
end

local size_t_ptr = ffi.typeof("size_t[1]")

local function asymmetric_routine(self, s, is_encrypt, padding)
  local pkey_ctx

  if self.key_type == evp_macro.EVP_PKEY_RSA then
    if padding then
      padding = tonumber(padding)
      if not padding then
        return nil, "invalid padding: " .. tostring(padding)
      end
    else
      padding = rsa_macro.paddings.RSA_PKCS1_PADDING
    end
  end

  if self.pkey_ctx ~= nil and
      (self.key_type ~= evp_macro.EVP_PKEY_RSA or self.rsa_padding == padding) then
        pkey_ctx = self.pkey_ctx
  else
    pkey_ctx = C.EVP_PKEY_CTX_new(self.ctx, nil)
    if pkey_ctx == nil then
      return nil, format_error("pkey: EVP_PKEY_CTX_new()")
    end
    ffi_gc(pkey_ctx, C.EVP_PKEY_CTX_free)
    self.pkey_ctx = pkey_ctx
  end

  local f, fint
  if is_encrypt then
    fint = C.EVP_PKEY_encrypt_init
    f = C.EVP_PKEY_encrypt
  else
    fint = C.EVP_PKEY_decrypt_init
    f = C.EVP_PKEY_decrypt
  end

  local code = fint(pkey_ctx)
  if code < 1 then
    return nil, format_error("pkey: EVP_PKEY_encrypt/decrypt_init", code)
  end

  -- EVP_PKEY_CTX_ctrl must be called after *_init
  if self.key_type == evp_macro.EVP_PKEY_RSA and padding then
    local code = C.EVP_PKEY_CTX_ctrl(pkey_ctx, evp_macro.EVP_PKEY_RSA, -1,
                          evp_macro.EVP_PKEY_CTRL_RSA_PADDING,
                          padding, nil)
    if code ~= 1 then
      return nil, format_error("pkey: EVP_PKEY_CTX_ctrl")
    end
    self.rsa_padding = padding
  end

  local length = size_t_ptr()
  length[0] = self.key_size

  if f(pkey_ctx, self.buf, length, s, #s) <= 0 then
    return nil, format_error("pkey: EVP_PKEY_encrypt/decrypt")
  end

  return ffi_str(self.buf, length[0]), nil
end

_M.PADDINGS = rsa_macro.paddings

function _M:encrypt(s, padding)
  return asymmetric_routine(self, s, true, padding)
end

function _M:decrypt(s, padding)
  return asymmetric_routine(self, s, false, padding)
end

local uint_ptr = ffi.typeof("unsigned int[1]")

function _M:sign(digest)
  if not digest_lib.istype(digest) then
    return nil, "expect a digest instance at #1"
  end
  local length = uint_ptr()
  if C.EVP_SignFinal(digest.ctx, self.buf, length, self.ctx) ~= 1 then
    return nil, format_error("pkey:sign")
  end
  return ffi_str(self.buf, length[0]), nil
end

function _M:verify(signature, digest)
  if not digest_lib.istype(digest) then
    return nil, "expect a digest instance at #2"
  end
  local code = C.EVP_VerifyFinal(digest.ctx, signature, #signature, self.ctx)
  if code == 0 then
    return false, nil
  elseif code == 1 then
    return true, nil
  end
  return false, format_error("pkey:verify")
end

function _M:to_PEM(pub_or_priv)
  return tostring(self, pub_or_priv)
end

return _M