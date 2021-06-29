local ffi = require("ffi")
local C = ffi.C
local ffi_cast = ffi.cast
local ffi_str = ffi.string

require "resty.openssl.include.crypto"
require "resty.openssl.include.evp"
require "resty.openssl.include.objects"
local OPENSSL_30 = require("resty.openssl.version").OPENSSL_30
local format_error = require("resty.openssl.err").format_error


local _M = {
  _VERSION = '0.7.3',
}

function _M.load_modules()
  _M.bn = require("resty.openssl.bn")
  _M.cipher = require("resty.openssl.cipher")
  _M.digest = require("resty.openssl.digest")
  _M.hmac = require("resty.openssl.hmac")
  _M.kdf = require("resty.openssl.kdf")
  _M.pkey = require("resty.openssl.pkey")
  _M.objects = require("resty.openssl.objects")
  _M.rand = require("resty.openssl.rand")
  _M.version = require("resty.openssl.version")
  _M.x509 = require("resty.openssl.x509")
  _M.altname = require("resty.openssl.x509.altname")
  _M.chain = require("resty.openssl.x509.chain")
  _M.csr = require("resty.openssl.x509.csr")
  _M.crl = require("resty.openssl.x509.crl")
  _M.extension = require("resty.openssl.x509.extension")
  _M.extensions = require("resty.openssl.x509.extensions")
  _M.name = require("resty.openssl.x509.name")
  _M.revoked = require("resty.openssl.x509.revoked")
  _M.store = require("resty.openssl.x509.store")
  _M.pkcs12 = require("resty.openssl.pkcs12")
  _M.ssl = require("resty.openssl.ssl")
  _M.ssl_ctx = require("resty.openssl.ssl_ctx")

  if OPENSSL_30 then
    _M.provider = require("resty.openssl.provider")
  end

  _M.bignum = _M.bn
end

function _M.luaossl_compat()
  _M.load_modules()

  _M.csr.setSubject = _M.csr.set_subject_name
  _M.csr.setPublicKey = _M.csr.set_pubkey

  _M.x509.setPublicKey = _M.x509.set_pubkey
  _M.x509.getPublicKey = _M.x509.get_pubkey
  _M.x509.setSerial = _M.x509.set_serial_number
  _M.x509.getSerial = _M.x509.get_serial_number
  _M.x509.setSubject = _M.x509.set_subject_name
  _M.x509.getSubject = _M.x509.get_subject_name
  _M.x509.setIssuer = _M.x509.set_issuer_name
  _M.x509.getIssuer = _M.x509.get_issuer_name
  _M.x509.getOCSP = _M.x509.get_ocsp_url

  local pkey_new = _M.pkey.new
  _M.pkey.new = function(a, b)
    if type(a) == "string" then
      return pkey_new(a, b and unpack(b))
    else
      return pkey_new(a, b)
    end
  end

  _M.cipher.encrypt = function(self, key, iv, padding)
    return self, _M.cipher.init(self, key, iv, true, not padding)
  end
  _M.cipher.decrypt = function(self, key, iv, padding)
    return self, _M.cipher.init(self, key, iv, false, not padding)
  end

  local digest_update = _M.digest.update
  _M.digest.update = function(self, ...)
    local ok, err = digest_update(self, ...)
    if ok then
      return self
    else
      return nil, err
    end
  end

  local store_verify = _M.store.verify
  _M.store.verify = function(...)
    local ok, err = store_verify(...)
    if err then
      return false, err
    else
      return true, ok
    end
  end

  local kdf_derive = _M.kdf.derive
  local kdf_keys_mappings = {
    iter = "pbkdf2_iter",
    key = "hkdf_key",
    info = "hkdf_info",
    secret = "tls1_prf_secret",
    seed = "tls1_prf_seed",
    maxmem_bytes = "scrypt_maxmem",
    N = "scrypt_N",
    r = "scrypt_r",
    p = "scrypt_p",
  }
  _M.kdf.derive = function(o)
    for k1, k2 in pairs(kdf_keys_mappings) do
      o[k1] = o[k2]
      o[k2] = nil
    end
    local hkdf_mode = o.hkdf_mode
    if hkdf_mode == "extract_and_expand" then
      o.hkdf_mode = _M.kdf.HKDEF_MODE_EXTRACT_AND_EXPAND
    elseif hkdf_mode == "extract_only" then
      o.hkdf_mode = _M.kdf.HKDEF_MODE_EXTRACT_ONLY
    elseif hkdf_mode == "expand_only" then
      o.hkdf_mode = _M.kdf.HKDEF_MODE_EXPAND_ONLY
    end
    return kdf_derive(o)
  end

  _M.pkcs12.new = function(tbl)
    local certs = {}
    local passphrase = tbl.passphrase
    if not tbl.key then
      return nil, "key must be set"
    end
    for _, cert in ipairs(tbl.certs) do
      if not _M.x509.istype(cert) then
        return nil, "certs must contains only x509 instance"
      end
      if cert:check_private_key(tbl.key) then
        tbl.cert = cert
      else
        certs[#certs+1] = cert
      end
    end
    tbl.cacerts = certs
    return _M.pkcs12.encode(tbl, passphrase)
  end

  for mod, tbl in pairs(_M) do
    if type(tbl) == 'table' then

      -- avoid using a same table as the iterrator will change
      local new_tbl = {}
      -- luaossl always error() out
      for k, f in pairs(tbl) do
        if type(f) == 'function' then
          local of = f
          new_tbl[k] = function(...)
            local ret = { of(...) }
            if ret and #ret > 1 and ret[#ret] then
              error(mod .. "." .. k .. "(): " .. ret[#ret])
            end
            return unpack(ret)
          end
        end
      end

      for k, f in pairs(new_tbl) do
        tbl[k] = f
      end

      setmetatable(tbl, {
        __index = function(t, k)
          local tok
          -- handle special case
          if k == 'toPEM' then
            tok = 'to_PEM'
          else
            tok = k:gsub("(%l)(%u)", function(a, b) return a .. "_" .. b:lower() end)
            if tok == k then
              return
            end
          end
          if type(tbl[tok]) == 'function' then
            return tbl[tok]
          end
        end
      })
    end
  end

  -- skip error() conversion
  _M.pkcs12.parse = function(p12, passphrase)
    local r, err = _M.pkcs12.decode(p12, passphrase)
    if err then error(err) end
    return r.key, r.cert, r.cacerts
  end
end

function _M.set_fips_mode(enable)
  if not not enable == _M.get_fips_mode() then
    return true
  end

  if C.FIPS_mode_set(enable and 1 or 0) == 0 then
    return false, format_error("openssl.set_fips_mode")
  end

  return true
end

function _M.get_fips_mode()
  return C.FIPS_mode() == 1
end

local function get_list_func(cf, l)
  return function(elem, from, to, arg)
    if elem ~= nil then
      local nid = cf(elem)
      table.insert(l, ffi_str(C.OBJ_nid2sn(nid)))
    end
  end
end

function _M.list_cipher_algorithms()
  local ret = {}
  local fn = ffi_cast("fake_openssl_cipher_list_fn*",
                      get_list_func(C.EVP_CIPHER_nid, ret))

  C.EVP_CIPHER_do_all_sorted(fn, nil)

  fn:free()

  return ret
end

function _M.list_digest_algorithms()
  local ret = {}
  local fn = ffi_cast("fake_openssl_md_list_fn*",
                      get_list_func(C.EVP_MD_type, ret))

  C.EVP_MD_do_all_sorted(fn, nil)

  fn:free()

  return ret
end

return _M
