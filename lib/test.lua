local ffi = require "ffi"
package.path = "/home/nasrullo/CLionProjects/lua-resty-openssl/lib/?.lua" .. ";" .. package.path
print(package.path)
do
    local ok = pcall(ffi.C, "X509_STORE_new")
    if not ok then
        ffi.load("libssl", true)
    end
end
require('resty.openssl.include.evp')
local ctypes = require "resty.openssl.aux.ctypes"
local extension = require "resty.openssl.x509.extension"
local csr = require "resty.openssl.x509.csr"
local C = ffi.C
local ffi_cast = ffi.cast
local utils = require('pl.utils')
--local csr_str = utils.readfile('../t/fixtures/test.csr')
local csr_str = [[-----BEGIN CERTIFICATE REQUEST-----
MIIDFTCCAf0CAQAwejELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEx
FDASBgNVBAcTC0xvcyBBbmdlbGVzMRQwEgYDVQQKEwtTU0wgU3VwcG9ydDEUMBIG
A1UECxMLU1NMIFN1cHBvcnQxFDASBgNVBAMTC2V4YW1wbGUuY29tMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwPOIBIoblSLFv/ifj8GDCNL5NhDX2JVU
QKcWC19KtWYQg1HPnaGIy+Dj9tYSBw8T8xc9hbJ1TYGbBIMKfBUzKoTt5yLdVIM/
HJm3m9ImvAbK7TYcx1U9TJEMxN6686whAUMBr4B7ql4VTXqu6TgDcdbcQ5wsPVOi
FHJTTwgVwt7eVCBMFAkZn+qQz+WigM5HEp8KFrzwAK142H2ucuyfgGS4+XQSsUdw
NWh9GPRZgRt3R2h5ymYkQB/cbg596alCquoizI6QCfwQx3or9Dg1f3rlwf8H5HIV
H3hATGIr7GpbKka/JH2PYNGfi5KqsJssVQfu84m+5WXDB+90KHJEcwIDAQABoFYw
VAYJKoZIhvcNAQkOMUcwRTAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DATBgNVHSUE
DDAKBggrBgEFBQcDATAWBgNVHREEDzANggtleGFtcGxlLmNvbTANBgkqhkiG9w0B
AQUFAAOCAQEAgBSVMeTB9pfgZCllMPBFffeduMePyDA1SzLYjSFkh660sFFiwGAV
MTnnYFHH3k6ueRVal3gzxZJ6ehr+ms1/CRO8rlY+B6geMCbGCbCvcAET0n505aYH
v8vlvqrdSx8Ur/9sisbynCkdk2qgc3rbnDbsAAonZIXf+blacaYTZdGUxso6qtY6
6mhI+ulqmkDk3Quc02ityvuGEbN8UuUGxc+kg0aIqMWWNKUGpTq/aRWpC7kuCUFZ
fmvPwnMhzgKBPzOXwyauVxAV0Mm/1uwPu9GNVQDgewy4Rjbm5bNwIjce3W1tVMWT
FR+x0BtV+D2A62fJWB2Yv9oERJbZQnvLqw==
-----END CERTIFICATE REQUEST-----]]
local util = require "resty.openssl.util"
local stack = require "resty.openssl.include.stack"
local extension_lib = require "resty.openssl.x509.extension"
local extensions = require("resty.openssl.x509.extensions").new()
local ostack = require('resty.openssl.stack')
local r = csr.new(csr_str)
local sn = r:get_subject_name()
local sns = sn:_tostring()
local exts = C.X509_REQ_get_extensions(r.ctx)
local aa = ctypes.ptr_of_int()
local bb = ctypes.ptr_of_int()
local ad = ostack.dup_of()(exts)
local n = C.OPENSSL_sk_num(ad)
for i= 0, n- 1 do
    local ext = C.OPENSSL_sk_value(ad, i)
    local typ_ptr = "X509_EXTENSION" .. "*"
    local dup, err = extension_lib.dup(ffi_cast(typ_ptr, ext))
    if not err then
        extensions:add(dup)
        local s = dup:tostring()
        local asns = C.X509_EXTENSION_get_object(dup.ctx)
        local nid = C.OBJ_obj2nid(asns);
        print(dup:tostring())
    end
end
local res = extensions:all()
local gens = C.X509V3_get_d2i(exts, 85, aa, bb)
local revoked = require "resty.openssl.revoked"
local rvn = revoked.new(12, 1234567, 2)