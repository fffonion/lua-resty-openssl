local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc
local ffi_new = ffi.new

require "resty.openssl.include.x509"
require "resty.openssl.include.x509.extension"
local objects_lib = require "resty.openssl.objects"
local util = require "resty.openssl.util"
local format_error = require("resty.openssl.err").format_error

local _M = {}
local mt = { __index = _M }

local x509_extension_ptr_ct = ffi.typeof("X509_EXTENSION*")

local extension_types = {
  issuer  = "resty.openssl.x509",
  subject = "resty.openssl.x509",
  request = "resty.openssl.x509.csr",
  crl     = "resty.openssl.x509.crl",
  -- db,           -- NYI
}
function _M.new(txtnid, value, data)
  local nid, err = objects_lib.txtnid2nid(txtnid)
  if err then
    return nil, err
  end
  if type(value) ~= 'string' then
    return nil, "expect string at #2"
  end
  -- get a ptr and also zerofill the struct
  local x509_ctx_ptr = ffi_new('X509V3_CTX[1]')

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

  local ctx = C.X509V3_EXT_nconf_nid(nil, x509_ctx_ptr[0], nid, value)
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

function _M.dup(ctx)
  if not ffi.istype(x509_extension_ptr_ct, ctx) then
    return nil, "expect a x509.extension ctx at #1"
  end
  local ctx = C.X509_EXTENSION_dup(ctx)
  if ctx == nil then
    return nil, "X509_EXTENSION_dup() failed"
  end

  ffi_gc(ctx, C.X509_EXTENSION_free)

  local self = setmetatable({
    ctx = ctx,
  }, mt)

  return self, nil
end

function _M.from_data(any, nid, crit)
  if type(any) ~= "table" or type(any.ctx) ~= "cdata" then
    return nil, "expect a table with ctx at #1"
  elseif type(nid) ~= "number" then
    return nil, "expect a table at #2"
  end

  local ctx = C.X509V3_EXT_i2d(nid, crit and 1 or 0, any.ctx)
  if ctx == nil then
    return nil, format_error("extension:from_data: X509V3_EXT_i2d")
  end
  ffi_gc(ctx, C.X509_EXTENSION_free)

  local self = setmetatable({
    ctx = ctx,
  }, mt)

  return self, nil
end

function _M:get_object()
  -- retruns the internal pointer
  local asn1 = C.X509_EXTENSION_get_object(self.ctx)

  return objects_lib.obj2table(asn1)
end

function _M:get_critical()
  return C.X509_EXTENSION_get_critical(self.ctx) == 1
end

function _M:set_critical(crit)
  if C.X509_EXTENSION_set_critical(self.ctx, crit and 1 or 0) ~= 1 then
    return false, format_error("x509.extension:set_critical")
  end
  return true
end

function _M:tostring()
  return util.read_using_bio(C.X509V3_EXT_print, self.ctx, 0, 0)
end

_M.text = _M.tostring

mt.__tostring = function(tbl)
  local txt, err = _M.text(tbl)
  if err then
    error(err)
  end
  return txt
end


return _M
