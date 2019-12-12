
local version_num = require("resty.openssl.version").version_num
if not version_num or version_num < 0x10000000 then
  error(string.format("OpenSSL version %x is not supported", version_num or 0))
end


local _M = {
  _VERSION = '0.2.1',
  version = require("resty.openssl.version"),
  pkey = require("resty.openssl.pkey"),
  digest = require("resty.openssl.digest"),
  hmac = require("resty.openssl.hmac"),
  bn = require("resty.openssl.bn"),
  x509 = require("resty.openssl.x509"),
  name = require("resty.openssl.x509.name"),
  altname = require("resty.openssl.x509.altname"),
  csr = require("resty.openssl.x509.csr"),
  extension = require("resty.openssl.x509.extension"),
}

_M.bignum = _M.bn

function _M.luaossl_compact()
  for _, tbl in pairs(_M) do
    if type(tbl) == 'table' then
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

  _M.cipher.encrypt = function(self, key, iv, padding)
    return self, _M.cipher.init(self, key, iv, true, not padding)
  end
  _M.cipher.decrypt = function(self, key, iv, padding)
    return self, _M.cipher.init(self, key, iv, false, not padding)
  end
end

return _M
