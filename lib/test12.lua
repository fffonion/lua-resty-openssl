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
local pkey = require "resty.openssl.pkey"
local x509 = require "resty.openssl.x509.init"
local extension = require "resty.openssl.x509.extension"
local csr = require "resty.openssl.x509.csr"
local name = require "resty.openssl.x509.name"
local bn = require "resty.openssl.bn"
local format_error = require("resty.openssl.err").format_error
local C = ffi.C
local ffi_str = ffi.string
local uchar_array = ctypes.uchar_array
--[[local function encode_b64(s)
    local size = 64
    local buf = uchar_array(size)
    if C.EVP_EncodeBlock(buf, s, #s) == 0 then
        return nil, format_error("cipher:get_aead_tag")
    end

    return ffi_str(buf, size)
end
local function decode_b64(s)
    s = s:gsub("-", "+")
         :gsub("_", "/")
    local size = #s
    local rem = size % 4
    if rem > 0 then
        s = s .. (("="):rep(4 - rem))
    end
    size = #s * 2
    local buf = uchar_array(size)
    local res = C.EVP_DecodeBlock(buf, s, #s)
    if res == 0 then
        return nil, format_error("cipher:get_aead_tag")
    end

    return ffi_str(buf, size)
end
local function create_self_signed(key_opts, names)
    local key = pkey.new(key_opts or {
        type = 'RSA',
        bits = 1024,
    })

    local cert = x509.new()
    cert:set_pubkey(key)
    cert:set_version(3)

    local now = os.time()
    cert:set_not_before(now)
    cert:set_not_after(now + 86400)

    local nm = name.new()
    for k, v in ipairs(names or {}) do
        nm:add(k, v)
    end

    cert:set_subject_name(nm)
    cert:set_issuer_name(nm)

    cert:sign(key)

    return cert, key
end

local function to_hex(bin)
    local hex, err = bn.from_binary(bin):to_hex()
    if err then
        error(err)
    end
    return hex
end

local function myassert(...)
    local ret = { ... }
    local err = ret[#ret]
    if #ret > 1 and err then
        ngx.log(ngx.ERR, tostring(err))
        ngx.exit(0)
    end
    return ...
end

create_self_signed()
local n = "pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w"
local a = encode_b64("Salom")
local qi = "pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w"
local b = decode_b64(qi)
print(b)]]
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
local extensions = require ("resty.openssl.x509.extensions").new()
local r = csr.new(csr_str)
local exts = C.X509_REQ_get_extensions(r.ctx)
extensions.stack_of = exts
local ext = extension.from_data(r, 86)
-- extensions:add(ext)
local bd = extensions:all()
local o = ext:get_object()
local d = C.X509V3_EXT_d2i(ext.ctx)
local st = util.read_using_bio(C.X509_REQ_print_ex, csr.ctx, 0, 0)
print("EXt:" .. ext:tostring())
print("EXtt:" .. tostring(ext))
local buf = ffi.new('char[?]', 100)