local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc
local ffi_str = ffi.string
local ffi_cast = ffi.cast

require("resty.openssl.objects")
local kdf_macro = require "resty.openssl.include.kdf"
local format_error = require("resty.openssl.err").format_error
local version_num = require("resty.openssl.version").version_num
local version_text = require("resty.openssl.version").version_text
local ctypes = require "resty.openssl.aux.ctypes"
local EVP_PKEY_OP_DERIVE = require("resty.openssl.include.evp").EVP_PKEY_OP_DERIVE

--[[
https://wiki.openssl.org/index.php/EVP_Key_Derivation

OpenSSL 1.0.2 and above provides PBKDF2 by way of PKCS5_PBKDF2_HMAC and PKCS5_PBKDF2_HMAC_SHA1.
OpenSSL 1.1.0 and above additionally provides HKDF and TLS1 PRF KDF by way of EVP_PKEY_derive and Scrypt by way of EVP_PBE_scrypt
OpenSSL 1.1.1 and above additionally provides Scrypt by way of EVP_PKEY_derive.
OpenSSL 3.0 additionally provides Single Step KDF, SSH KDF, PBKDF2, Scrypt, HKDF, ANSI X9.42 KDF, ANSI X9.63 KDF and TLS1 PRF KDF by way of EVP_KDF.
From OpenSSL 3.0 the recommended way of performing key derivation is to use the EVP_KDF functions. If compatibility with OpenSSL 1.1.1 is required then a limited set of KDFs can be used via EVP_PKEY_derive.
]]

local NID_id_pbkdf2 = -1
local NID_id_scrypt = -2
local NID_tls1_prf = -3
local NID_hkdf = -4
if version_num >= 0x10002000 then
  NID_id_pbkdf2 = C.OBJ_txt2nid("PBKDF2")
  assert(NID_id_pbkdf2 > 0)
end
if version_num >= 0x10100000 then
  NID_hkdf = C.OBJ_txt2nid("HKDF")
  assert(NID_hkdf > 0)
  NID_tls1_prf = C.OBJ_txt2nid("TLS1-PRF")
  assert(NID_tls1_prf > 0)
  -- we use EVP_PBE_scrypt to do scrypt, so this is supported >= 1.1.0
  NID_id_scrypt = C.OBJ_txt2nid("id-scrypt")
  assert(NID_id_scrypt > 0)
end

local _M = {
  HKDEF_MODE_EXTRACT_AND_EXPAND = kdf_macro.EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND,
  HKDEF_MODE_EXTRACT_ONLY       = kdf_macro.EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY,
  HKDEF_MODE_EXPAND_ONLY        = kdf_macro.EVP_PKEY_HKDEF_MODE_EXPAND_ONLY,

  PBKDF2   = NID_id_pbkdf2,
  SCRYPT   = NID_id_scrypt,
  TLS1_PRF = NID_tls1_prf,
  HKDF     = NID_hkdf,
}

local type_literals = {
  [NID_id_pbkdf2] = "PBKDF2",
  [NID_id_scrypt] = "scrypt",
  [NID_tls1_prf]  = "TLS-1PRF",
  [NID_hkdf]      = "HKDF",
}

local TYPE_NUMBER = 0x1
local TYPE_STRING = 0x2

local function check_options(opt, nid, field, typ, is_optional, required_only_if_nid)
  local v = opt[field]
  if not v then
    if is_optional or (required_only_if_nid and required_only_if_nid ~= nid) then
      return typ == TYPE_NUMBER and 0 or nil
    else
      return nil, "\"" .. field .. "\" must be set"
    end
  end

  if typ == TYPE_NUMBER then
    v = tonumber(v)
    if not typ then
      return nil, "except a number as \"" .. field .. "\""
    end
  elseif typ == TYPE_STRING then
    if type(v) ~= "string" then
      return nil, "except a string as \"" .. field .. "\""
    end
  else
    error("don't known how to check " .. typ, 2)
  end

  return v
end

local options_schema = {
  outlen = { TYPE_NUMBER },
  pass   = { TYPE_STRING, true },
  salt   = { TYPE_STRING, true },
  md     = { TYPE_STRING, true },
  -- pbkdf2 only
  pbkdf2_iter = { TYPE_NUMBER, true },
  -- hkdf only
  hkdf_key  = { TYPE_STRING, nil, NID_hkdf },
  hkdf_mode = { TYPE_NUMBER, true },
  hkdf_info = { TYPE_STRING, true },
  -- tls1-prf
  tls1_prf_secret = { TYPE_STRING, nil, NID_tls1_prf },
  tls1_prf_seed   = { TYPE_STRING, nil, NID_tls1_prf },
  -- scrypt only
  scrypt_maxmem = { TYPE_NUMBER, true },
  scrypt_N      = { TYPE_NUMBER, nil, NID_id_scrypt },
  scrypt_r      = { TYPE_NUMBER, nil, NID_id_scrypt },
  scrypt_p      = { TYPE_NUMBER, nil, NID_id_scrypt },
}

local void_ptr = ctypes.void_ptr

function _M.derive(options)
  local typ = options.type
  if not typ then
    return nil, "kdf.derive: \"type\" must be set"
  elseif type(typ) ~= "number" then
    return nil, "kdf.derive: expect a number as \"type\""
  end

  if typ <= 0 then
    return nil, "kdf.derive: kdf type " ..  (type_literals[typ] or tostring(typ)) ..
                " not supported in " .. version_text
  end

  for k, v in pairs(options_schema) do
    local v, err = check_options(options, typ, k, unpack(v))
    if err then
      return nil, "kdf.derive: " .. err
    end
    options[k] = v
  end

  local salt_len = 0
  if options.salt then
    salt_len = #options.salt
  end
  local pass_len = 0
  if options.pass then
    pass_len = #options.pass
  end

  local md
  md = C.EVP_get_digestbyname(options.md or "sha1")
  if md == nil then
    return nil, string.format("kdf.derive: invalid digest type \"%s\"", md)
  end

  local buf = ctypes.uchar_array(options.outlen)

  -- begin legacay low level routines
  local code
  if typ == NID_id_pbkdf2 then
    -- make openssl 1.0.2 happy
    if version_num < 0x10100000 and not options.pass then
      options.pass = ""
      pass_len = 0
    end
    -- https://www.openssl.org/docs/man1.1.0/man3/PKCS5_PBKDF2_HMAC.html
    local iter = options.pbkdf2_iter
    if iter < 1 then
      iter = 1
    end
    code = C.PKCS5_PBKDF2_HMAC(
      options.pass, pass_len,
      options.salt, salt_len, iter,
      md, options.outlen, buf
    )
  elseif typ == NID_id_scrypt then
    code = C.EVP_PBE_scrypt(
      options.pass, pass_len,
      options.salt, salt_len,
      options.scrypt_N, options.scrypt_r, options.scrypt_p, options.scrypt_maxmem,
      buf, options.outlen
    )
  elseif typ ~= NID_tls1_prf and typ ~= NID_hkdf then
    return nil, string.format("kdf.derive: unknown type %d", typ)
  end
  if code then
    if code ~= 1 then
      return nil, format_error("kdf.derive")
    else
      return ffi_str(buf, options.outlen)
    end
  end
  -- end legacay low level routines

  -- begin EVP_PKEY_derive routines
  md = ffi_cast(void_ptr, md)
  local outlen = ctypes.ptr_of_uint64(options.outlen)

  local ctx = C.EVP_PKEY_CTX_new_id(typ, nil)
  if ctx == nil then
    return nil, format_error("kdf.derive: EVP_PKEY_CTX_new_id")
  end
  ffi_gc(ctx, C.EVP_PKEY_CTX_free)
  if C.EVP_PKEY_derive_init(ctx) ~= 1 then
    return nil, format_error("kdf.derive: EVP_PKEY_derive_init")
  end

  if typ == NID_tls1_prf then
    if 1 ~= C.EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE,
        kdf_macro.EVP_PKEY_CTRL_TLS_MD, 0, md) then
      return nil, format_error("kdf.derive: EVP_PKEY_CTRL_TLS_MD")
    end
    if 1 ~= C.EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE,
        kdf_macro.EVP_PKEY_CTRL_TLS_SECRET,
        #options.tls1_prf_secret, ffi_cast(void_ptr, options.tls1_prf_secret)) then
      return nil, format_error("kdf.derive: EVP_PKEY_CTRL_TLS_SECRET")
    end
    if 1 ~= C.EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE,
        kdf_macro.EVP_PKEY_CTRL_TLS_SEED,
        #options.tls1_prf_seed, ffi_cast(void_ptr, options.tls1_prf_seed)) then
      return nil, format_error("kdf.derive: EVP_PKEY_CTRL_TLS_SEED")
    end
  elseif typ == NID_hkdf then
    if 1 ~= C.EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE,
        kdf_macro.EVP_PKEY_CTRL_HKDF_MD, 0, md) then
      return nil, format_error("kdf.derive: EVP_PKEY_CTRL_HKDF_MD")
    end
    if options.salt and 1 ~= C.EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE,
        kdf_macro.EVP_PKEY_CTRL_HKDF_SALT,
        #options.salt, ffi_cast(void_ptr, options.salt)) then
      return nil, format_error("kdf.derive: EVP_PKEY_CTRL_HKDF_SALT")
    end
    if options.hkdf_key and 1 ~= C.EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE,
        kdf_macro.EVP_PKEY_CTRL_HKDF_KEY,
        #options.hkdf_key, ffi_cast(void_ptr, options.hkdf_key)) then
      return nil, format_error("kdf.derive: EVP_PKEY_CTRL_HKDF_KEY")
    end
    if options.hkdf_info and 1 ~= C.EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE,
        kdf_macro.EVP_PKEY_CTRL_HKDF_INFO,
        #options.hkdf_info, ffi_cast(void_ptr, options.hkdf_info)) then
      return nil, format_error("kdf.derive: EVP_PKEY_CTRL_HKDF_INFO")
    end
    if options.hkdf_mode then
      if version_num >= 0x10101000 then
        if 1 ~= C.EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE,
          kdf_macro.EVP_PKEY_CTRL_HKDF_MODE,
          options.hkdf_mode, nil) then
          return nil, format_error("kdf.derive: EVP_PKEY_CTRL_HKDF_MODE")
        end
      else
        ngx.log(ngx.WARN, "hkdf_mode is not effective in ", version_text)
      end
    end
  else
    return nil, string.format("kdf.derive: unknown type %d", typ)
  end
  code = C.EVP_PKEY_derive(ctx, buf, outlen)
  if code == -2 then
    return nil, "kdf.derive: operation is not supported by the public key algorithm"
  end
  -- end EVP_PKEY_derive routines

  return ffi_str(buf, options.outlen)
end

return _M