
local version_num = require("resty.openssl.version").version_num
if not version_num or version_num < 0x10000000 then
  error(string.format("OpenSSL version %x is not supported", version_num or 0))
end

return {
  _VERSION = '0.1.0',
  version = require("resty.openssl.version"),
  pkey = require("resty.openssl.pkey"),
  x509 = require("resty.openssl.x509"),
  name = require("resty.openssl.x509.name"),
  altname = require("resty.openssl.x509.altname"),
  csr = require("resty.openssl.x509.csr"),
  digest = require("resty.openssl.digest")
}
