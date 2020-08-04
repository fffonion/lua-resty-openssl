local ffi = require "ffi"
local C = ffi.C
require "resty.openssl.include.provider"
local OPENSSL_30 = require("resty.openssl.version").OPENSSL_30
local format_error = require("resty.openssl.err").format_error

if not OPENSSL_30 then
  error("provider is only supported since OpenSSL 3.0")
end

local _M = {}

function _M.is_available(name)
  return C.ossl_provider_available(nil, name) == 1
end

function _M.load(name)
  if C.ossl_provider_load(nil, name) == nil then
    return false, format_error("provider.load")
  end
  return true
end

return _M