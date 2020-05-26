local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc
local ffi_new = ffi.new
local ffi_str = ffi.string
local ffi_cast = ffi.cast
local ffi_copy = ffi.copy
local null = ngx.null

local rsa_macro = require "resty.openssl.include.rsa"
require "resty.openssl.include.bio"
require "resty.openssl.include.pem"
require "resty.openssl.include.x509"
local evp_macro = require "resty.openssl.include.evp"
local util = require "resty.openssl.util"
local digest_lib = require "resty.openssl.digest"
local rsa_lib = require "resty.openssl.rsa"
local ec_lib = require "resty.openssl.ec"
local ecx_lib = require "resty.openssl.ecx"
local objects_lib = require "resty.openssl.objects"
local jwk_lib = require "resty.openssl.aux.jwk"
local ctypes = require "resty.openssl.aux.ctypes"
local format_error = require("resty.openssl.err").format_error

local OPENSSL_10 = require("resty.openssl.version").OPENSSL_10
local OPENSSL_11_OR_LATER = require("resty.openssl.version").OPENSSL_11_OR_LATER
local OPENSSL_30 = require("resty.openssl.version").OPENSSL_30

local ptr_of_uint = ctypes.ptr_of_uint
local ptr_of_size_t = ctypes.ptr_of_size_t

-- TODO: rewrite using EVP_PKEY_keygen_*
-- https://www.openssl.org/docs/manmaster/man7/Ed25519.html
local function generate_key(config)

  local type = config.type or 'RSA'

  local code, key, key_type

  local key_free
  if type == "RSA" then
    key_type = evp_macro.EVP_PKEY_RSA
    if key_type == 0 then
      return nil, "the linked OpenSSL library doesn't support RSA key"
    end
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
    key_free = C.RSA_free
  elseif type == "EC" then
    key_type = evp_macro.EVP_PKEY_EC
    if key_type == 0 then
      return nil, "the linked OpenSSL library doesn't support EC key"
    end
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
    key_free = C.EC_KEY_free
  elseif evp_macro.ecx_curves[type] then
    key_type = evp_macro.ecx_curves[type]
    if key_type == 0 then
      return nil, string.format("the linked OpenSSL library doesn't support %s key", type)
    end
    local pctx = C.EVP_PKEY_CTX_new_id(key_type, nil)
    if pctx == nil then
      return nil, format_error("EVP_PKEY_CTX_new_id")
    end
    ffi_gc(pctx, C.EVP_PKEY_CTX_free)
    if C.EVP_PKEY_keygen_init(pctx) ~= 1 then
      return nil, format_error("EVP_PKEY_keygen_init")
    end
    local ctx_ptr = ffi_new("EVP_PKEY*[1]")
    -- TODO: move to use EVP_PKEY_gen after drop support for <1.1.1
    if C.EVP_PKEY_keygen(pctx, ctx_ptr) ~= 1 then
      return nil, format_error("EVP_PKEY_gen")
    end
    return ctx_ptr[0]
  else
    return nil, "unsupported type " .. type
  end

  local ctx = C.EVP_PKEY_new()
  if ctx == nil then
    key_free(key)
    return nil, "EVP_PKEY_new() failed"
  end

  code = C.EVP_PKEY_assign(ctx, key_type, key)
  if code ~= 1 then
    key_free(key)
    C.EVP_PKEY_free(ctx)
    return nil, "EVP_PKEY_assign() failed"
  end

  return ctx, nil
end

local load_key_try_args_pem = { null, null, null }
local load_key_try_args_der = { null }

local load_key_try_funcs = {
  PEM = {
    -- Note: make sure we always try load priv key first
    pr = {
      ['PEM_read_bio_PrivateKey'] = load_key_try_args_pem,
    },
    pu = {
      ['PEM_read_bio_PUBKEY'] = load_key_try_args_pem,
    },
  },
  DER = {
    pr = {
      ['d2i_PrivateKey_bio'] = load_key_try_args_der,
    },
    pu = {
      ['d2i_PUBKEY_bio'] = load_key_try_args_der,
    },
  },
  JWK = {
    pr = {
      ['load_jwk'] = {},
    },
  }
}
-- populate * funcs
local all_funcs = {}
local typ_funcs = {}
for fmt, ffs in pairs(load_key_try_funcs) do
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
  load_key_try_funcs[fmt]["*"] = funcs
end
load_key_try_funcs["*"] = {}
load_key_try_funcs["*"]["*"] = all_funcs
for typ, fs in pairs(typ_funcs) do
  load_key_try_funcs[typ] = fs
end

local function load_key(txt, opts)
  local fmt = opts.format or '*'
  if fmt ~= 'PEM' and fmt ~= 'DER' and fmt ~= "JWK" and fmt ~= '*' then
    return nil, "expecting 'DER', 'PEM', 'JWK' or '*' as \"format\""
  end

  local typ = opts.type or '*'
  if typ ~= 'pu' and typ ~= 'pr' and typ ~= '*' then
    return nil, "expecting 'pr', 'pu' or '*' as \"type\""
  end

  if fmt == "JWK" and (typ == "pu" or type == "pr") then
    return nil, "explictly load private or public key from JWK format is not supported"
  end

  ngx.log(ngx.DEBUG, "load key using fmt: ", fmt, ", type: ", typ)

  local bio = C.BIO_new_mem_buf(txt, #txt)
  if bio == nil then
    return "BIO_new_mem_buf() failed"
  end
  ffi_gc(bio, C.BIO_free)

  local ctx

  local fs = load_key_try_funcs[fmt][typ]
  local passphrase_cb
  for f, arg in pairs(fs) do
    -- don't need BIO when loading JWK key: we parse it in Lua land
    if f == "load_jwk" then
      local err
      ctx, err = jwk_lib[f](txt)
      if ctx == nil then
        -- if fmt is explictly set to JWK, we should return an error now
        if fmt == "JWK" then
          return nil, err
        end
        ngx.log(ngx.DEBUG, "jwk decode failed: ", err, ", continuing")
      end
    else
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
              ngx.log(ngx.WARN, "pkey.new:load_key: passphrase truncated from ", len, " to ", size)
              len = size
            end
            ffi_copy(buf, p, len)
            return len
          end)
          arg = { null, passphrase_cb, null }
        end
      end

      ctx = C[f](bio, unpack(arg))
    end

    if ctx ~= nil then
      ngx.log(ngx.DEBUG, "pkey.new:load_key: loaded pkey using function ", f)
      break
    end
  end
  if passphrase_cb ~= nil then
    passphrase_cb:free()
  end

  if ctx == nil then
    return nil, format_error()
  end
  -- clear errors occur when trying
  C.ERR_clear_error()
  return ctx, nil
end

local function tostring(self, is_priv, fmt)
  if fmt == "JWK" then
    return jwk_lib.dump_jwk(self, is_priv)
  end
  if is_priv then
    if fmt == "DER" then
      return util.read_using_bio(C.i2d_PrivateKey_bio, self.ctx)
    end
    return util.read_using_bio(C.PEM_write_bio_PrivateKey,
      self.ctx,
      nil, nil, 0, nil, nil)
  else
    if fmt == "DER" then
      return util.read_using_bio(C.i2d_PUBKEY_bio, self.ctx)
    end
    return util.read_using_bio(C.PEM_write_bio_PUBKEY, self.ctx)
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
    if err then
      err = "pkey.new:generate_key: " .. err
    end
  elseif type(s) == 'string' then
    ctx, err = load_key(s, opts or empty_table)
    if err then
      err = "pkey.new:load_key: " .. err
    end
  elseif type(s) == 'cdata' then
    if ffi.istype(evp_pkey_ptr_ct, s) then
      ctx = s
    else
      return nil, "pkey.new: expect a EVP_PKEY* cdata at #1"
    end
  else
    return nil, "pkey.new: unexpected type " .. type(s) .. " at #1"
  end

  if err then
    return nil, err
  end

  ffi_gc(ctx, C.EVP_PKEY_free)

  local key_type = C.EVP_PKEY_base_id(ctx)
  if key_type == 0 then
    return nil, "pkey.new: cannot get key_type"
  end
  local key_type_is_ecx = (key_type == evp_macro.EVP_PKEY_ED25519) or
                          (key_type == evp_macro.EVP_PKEY_X25519) or
                          (key_type == evp_macro.EVP_PKEY_ED448) or
                          (key_type == evp_macro.EVP_PKEY_X448)

  -- although OpenSSL discourages to use this size for digest/verify
  -- but this is good enough for now
  local buf_size = C.EVP_PKEY_size(ctx)

  local self = setmetatable({
    ctx = ctx,
    pkey_ctx = nil,
    rsa_padding = nil,
    key_type = key_type,
    key_type_is_ecx = key_type_is_ecx,
    buf = ctypes.uchar_array(buf_size),
    buf_size = buf_size,
  }, mt)

  return self, nil
end

function _M.istype(l)
  return l and l.ctx and ffi.istype(evp_pkey_ptr_ct, l.ctx)
end

function _M:get_key_type()
  return objects_lib.nid2table(self.key_type)
end

local function get_pkey_key(self)
  if self.key_type == evp_macro.EVP_PKEY_RSA then
    local rsa_st
    if OPENSSL_11_OR_LATER then
      rsa_st = C.EVP_PKEY_get0_RSA(self.ctx)
      if rsa_st == nil then
        return nil, "pkey:get_pkey_key EVP_PKEY_get0_RSA() failed"
      end
    elseif OPENSSL_10 then
      rsa_st = self.ctx.pkey and self.ctx.pkey.rsa
    end
    return rsa_st
  elseif self.key_type == evp_macro.EVP_PKEY_EC then
    local ec_key_st
    if OPENSSL_11_OR_LATER then
      ec_key_st = C.EVP_PKEY_get0_EC_KEY(self.ctx)
      if ec_key_st == nil then
        return nil, "pkey:get_pkey_key: EVP_PKEY_get0_EC_KEY() failed"
      end
    elseif OPENSSL_10 then
      ec_key_st = self.ctx.pkey and self.ctx.pkey.ec
    end
    return ec_key_st
  end

  return nil, string.format("pkey:get_pkey_key: key type %d not supported", self.key_type)
end

function _M:get_parameters()
  if not self.key_type_is_ecx then
    local key, err = get_pkey_key(self)
    if err then
      return nil, err
    end

    if self.key_type == evp_macro.EVP_PKEY_RSA then
      return rsa_lib.get_parameters(key)
    elseif self.key_type == evp_macro.EVP_PKEY_EC then
      return ec_lib.get_parameters(key)
    end
  else
    return ecx_lib.get_parameters(self.ctx)
  end
end

function _M:set_parameters(opts)
  if not self.key_type_is_ecx then
    local key, err = get_pkey_key(self)
    if err then
      return false, err
    end

    if self.key_type == evp_macro.EVP_PKEY_RSA then
      return rsa_lib.set_parameters(key, opts)
    elseif self.key_type == evp_macro.EVP_PKEY_EC then
      return ec_lib.set_parameters(key, opts)
    end
  else
    -- for ecx keys we always create a new EVP_PKEY and release the old one
    local ctx, err = ecx_lib.set_parameters(self.key_type, self.ctx, opts)
    if err then
      return false, err
    end
    self.ctx = ctx
  end
end

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
      return nil, format_error("pkey:asymmetric_routine EVP_PKEY_CTX_new()")
    end
    ffi_gc(pkey_ctx, C.EVP_PKEY_CTX_free)
    self.pkey_ctx = pkey_ctx
  end

  local f, fint, op_name
  if is_encrypt then
    fint = C.EVP_PKEY_encrypt_init
    f = C.EVP_PKEY_encrypt
    op_name = "encrypt"
  else
    fint = C.EVP_PKEY_decrypt_init
    f = C.EVP_PKEY_decrypt
    op_name = "decrypt"
  end

  local code = fint(pkey_ctx)
  if code < 1 then
    return nil, format_error("pkey:asymmetric_routine EVP_PKEY_" .. op_name .. "_init", code)
  end

  -- EVP_PKEY_CTX_ctrl must be called after *_init
  if self.key_type == evp_macro.EVP_PKEY_RSA and padding then
    local code
    if OPENSSL_30 then
      code = C.EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding)
    else
      code = C.EVP_PKEY_CTX_ctrl(pkey_ctx, evp_macro.EVP_PKEY_RSA, -1,
                          evp_macro.EVP_PKEY_CTRL_RSA_PADDING,
                          padding, nil)
    end
    if code ~= 1 then
      return nil, format_error("pkey:asymmetric_routine EVP_PKEY_CTX_ctrl")
    end
    self.rsa_padding = padding
  end

  local length = ptr_of_size_t(self.buf_size)

  if f(pkey_ctx, self.buf, length, s, #s) <= 0 then
    return nil, format_error("pkey:asymmetric_routine EVP_PKEY_" .. op_name)
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

function _M:sign(digest)
  if not self.key_type_is_ecx then
    if not digest_lib.istype(digest) then
      return nil, "pkey:sign: expect a digest instance at #1"
    end
    local length = ptr_of_uint()
    if C.EVP_SignFinal(digest.ctx, self.buf, length, self.ctx) ~= 1 then
      return nil, format_error("pkey:sign: EVP_SignFinal")
    end
    return ffi_str(self.buf, length[0]), nil
  else
    if type(digest) ~= "string" then
      return nil, "pkey:sign expect a string at #1"
    end
    -- use on shot signing for Ed keys
    local md_ctx = C.EVP_MD_CTX_new()
    if md_ctx == nil then
      return nil, "pkey:sign: EVP_MD_CTX_new() failed"
    end
    ffi_gc(md_ctx, C.EVP_MD_CTX_free)
    if C.EVP_DigestSignInit(md_ctx, nil, nil, nil, self.ctx) ~= 1 then
      return nil, format_error("pkey:sign: EVP_DigestSignInit")
    end
    local length = ptr_of_size_t(self.buf_size)
    if C.EVP_DigestSign(md_ctx, self.buf, length, digest, #digest) ~= 1 then
      return nil, format_error("pkey:sign: EVP_DigestSign")
    end
    return ffi_str(self.buf, length[0]), nil
  end
end

function _M:verify(signature, digest)
  local code
  if not self.key_type_is_ecx then
    if not digest_lib.istype(digest) then
      return nil, "pkey:verify: expect a digest instance at #2"
    end
    code = C.EVP_VerifyFinal(digest.ctx, signature, #signature, self.ctx)
  else
    if type(digest) ~= "string" then
      return nil, "pkey:verify expect a string at #2"
    end
    -- use on shot verification for Ed keys
    local md_ctx = C.EVP_MD_CTX_new()
    if md_ctx == nil then
      return nil, "pkey:verify: EVP_MD_CTX_new() failed"
    end
    ffi_gc(md_ctx, C.EVP_MD_CTX_free)
    if C.EVP_DigestVerifyInit(md_ctx, nil, nil, nil, self.ctx) ~= 1 then
      return nil, format_error("pkey:verify: EVP_DigestSignInit")
    end
    code = C.EVP_DigestVerify(md_ctx, signature, #signature, digest, #digest)
  end

  if code == 0 then
    return false, nil
  elseif code == 1 then
    return true, nil
  end
  return false, format_error("pkey:verify")
end

function _M:derive(peerkey)
  if not self.istype(peerkey) then
    return nil, "pkey:derive: expect a pkey instance at #1"
  end
  local pctx = C.EVP_PKEY_CTX_new(self.ctx, nil)
  if pctx == nil then
    return nil, "pkey:derive: EVP_PKEY_CTX_new() failed"
  end
  ffi_gc(pctx, C.EVP_PKEY_CTX_free)
  local code = C.EVP_PKEY_derive_init(pctx)
  if code <= 0 then
    return nil, format_error("pkey:derive: EVP_PKEY_derive_init", code)
  end

  code = C.EVP_PKEY_derive_set_peer(pctx, peerkey.ctx)
  if code <= 0 then
    return nil, format_error("pkey:derive: EVP_PKEY_derive_set_peer", code)
  end

  local buflen = ptr_of_size_t()
  code = C.EVP_PKEY_derive(pctx, nil, buflen)
  if code <= 0 then
    return nil, format_error("pkey:derive: EVP_PKEY_derive check buffer size", code)
  end

  local buf = ctypes.uchar_array(buflen[0])
  code = C.EVP_PKEY_derive(pctx, buf, buflen)
  if code <= 0 then
    return nil, format_error("pkey:derive: EVP_PKEY_derive", code)
  end

  return ffi_str(buf, buflen[0])
end

local function pub_or_priv_is_pri(pub_or_priv)
  if pub_or_priv == 'private' or pub_or_priv == 'PrivateKey' then
    return true
  elseif not pub_or_priv or pub_or_priv == 'public' or pub_or_priv == 'PublicKey' then
    return false
  else
    return nil, string.format("can only export private or public key, not %s", pub_or_priv)
  end
end

function _M:tostring(pub_or_priv, fmt)
  local is_priv, err = pub_or_priv_is_pri(pub_or_priv)
  if err then
    return nil, "pkey:tostring: " .. err
  end
  return tostring(self, is_priv, fmt)
end

function _M:to_PEM(pub_or_priv)
  return self:tostring(pub_or_priv, "PEM")
end

return _M