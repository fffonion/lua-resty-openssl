local OPENSSL_30 = require("resty.openssl.version").OPENSSL_30


local _M = {
  _VERSION = '0.6.5',
  bn = require("resty.openssl.bn"),
  cipher = require("resty.openssl.cipher"),
  digest = require("resty.openssl.digest"),
  hmac = require("resty.openssl.hmac"),
  kdf = require("resty.openssl.kdf"),
  pkey = require("resty.openssl.pkey"),
  objects = require("resty.openssl.objects"),
  rand = require("resty.openssl.rand"),
  version = require("resty.openssl.version"),
  x509 = require("resty.openssl.x509"),
  altname = require("resty.openssl.x509.altname"),
  chain = require("resty.openssl.x509.chain"),
  csr = require("resty.openssl.x509.csr"),
  crl = require("resty.openssl.x509.crl"),
  extension = require("resty.openssl.x509.extension"),
  extensions = require("resty.openssl.x509.extensions"),
  name = require("resty.openssl.x509.name"),
  revoked = require("resty.openssl.x509.revoked"),
  store = require("resty.openssl.x509.store"),
}

if OPENSSL_30 then
  _M.provider = require("resty.openssl.provider")
end

_M.bignum = _M.bn

function _M.luaossl_compat()
  for mod, tbl in pairs(_M) do
    if type(tbl) == 'table' then
      -- luaossl always error() out
      for k, f in pairs(tbl) do
        if type(f) == 'function' then
          local of = f
          tbl[k] = function(...)
            local ret = { of(...) }
            if ret and #ret > 1 and ret[#ret] then
              error(mod .. "." .. k .. "(): " .. ret[#ret])
            end
            return unpack(ret)
          end
        end
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
end

-- we made a typo sometime, this is going to be removed in next major release
_M.luaossl_compact = _M.luaossl_compat

local resty_hmac_compat_patched = false
function _M.resty_hmac_compat()
  if resty_hmac_compat_patched then
    return
  end
  if _M.version.OPENSSL_10 then
    error("use resty_hmac_compat in OpenSSL 1.0 is not supported")
  end

  require("resty.openssl.include.evp")
  require("ffi").cdef [[
    // originally named evp_cipher_ctx_st in evp.lua
    struct evp_md_ctx_st {
      const EVP_MD *digest;
      ENGINE *engine;             /* functional reference if 'digest' is
                                  * ENGINE-provided */
      unsigned long flags;
      void *md_data;
      /* Public key context for sign/verify */
      EVP_PKEY_CTX *pctx;
      /* Update function: usually copied from EVP_MD */
      int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
    }/* EVP_MD_CTX */ ;
  ]]
  resty_hmac_compat_patched = true
end

return _M
