local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc
local ffi_new = ffi.new

require "resty.openssl.ossl_typ"
require "resty.openssl.x509v3"
require "resty.openssl.x509"
local format_error = require("resty.openssl.err").format_error

local _M = {}
local mt = { __index = _M, __tostring = tostring }

ffi.cdef [[
  void X509_EXTENSION_free(X509_EXTENSION *extension);

  struct v3_ext_ctx {
      int flags;
      X509 *issuer_cert;
      X509 *subject_cert;
      X509_REQ *subject_req;
      X509_CRL *crl;
      /*X509V3_CONF_METHOD*/ void *db_meth;
      void *db;
  };
]]

local x509_extension_ptr_ct = ffi.typeof("X509_EXTENSION*")

local extension_types = {
  issuer  = "resty.openssl.x509",
  subject = "resty.openssl.x509",
  request = "resty.openssl.csr",
  -- crl     = "", -- NYI
  -- db,           -- NYI
}
function _M.new(name, value, data)
  -- get a ptr and also zerofill the struct
  local x509_ctx_ptr = ffi_new('X509V3_CTX[1]')
  if type(name) ~= 'string' or type(value) ~= 'string' then
    return nil, "expect both strings at #1 and #2"
  end

  if type(data) == 'table' then
    local args = {}
    for k, t in pairs(extension_types) do
      if data[k] then
        local lib = require(t)
        if not lib.istype(data[k]) then
          return nil, "expect data." .. k .. " to be a " .. t .. " instance"
        end
        args[k] = data[k].ctx
      end
    end
    C.X509V3_set_ctx(x509_ctx_ptr[0], args.issuer, args.subject, args.request, nil, 0)
  elseif data then
    return nil, "expect nil or a table at #3"
  end

  local ctx = C.X509V3_EXT_nconf(nil, x509_ctx_ptr[0], name, value)
  if ctx == nil then
    return nil, format_error("x509.extension.new")
  end
  ffi_gc(ctx, C.X509_EXTENSION_free)

  local self = setmetatable({
    ctx = ctx,
  }, mt)

  return self, nil
end

function _M.istype(l)
  return l and l.ctx and ffi.istype(x509_extension_ptr_ct, l.ctx)
end


return _M
