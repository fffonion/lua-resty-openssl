
local version_num = require("resty.openssl.version").version_num
if not version_num or version_num < 0x10000000 then
  error(string.format("OpenSSL version %x is not supported", version_num or 0))
end


local _M = {
  _VERSION = '0.1.0',
  version = require("resty.openssl.version"),
  pkey = require("resty.openssl.pkey"),
  digest = require("resty.openssl.digest"),
  x509 = require("resty.openssl.x509"),
  name = require("resty.openssl.x509.name"),
  altname = require("resty.openssl.x509.altname"),
  csr = require("resty.openssl.x509.csr"),
}

function _M.luaossl_compact()
  for tn, tbl in pairs(_M) do
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
end

return _M