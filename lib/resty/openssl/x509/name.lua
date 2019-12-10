local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc

require "resty.openssl.ossl_typ"
require "resty.openssl.asn1"
require "resty.openssl.objects"

ffi.cdef [[
  X509_NAME * X509_NAME_new(void);
  void X509_NAME_free(X509_NAME *name);
  X509_NAME *X509_NAME_dup(X509_NAME *xn);
  int X509_NAME_add_entry_by_OBJ(X509_NAME *name, const ASN1_OBJECT *obj, int type,
                               const unsigned char *bytes, int len, int loc,
                               int set);
]]

local MBSTRING_FLAG = 0x1000
local MBSTRING_ASC  = 0x1001 -- (MBSTRING_FLAG|1)

local _M = {}
local mt = { __index = _M, __tostring = tostring }

local x509_name_ptr_ct = ffi.typeof("X509_NAME*")

function _M.new()
  local ctx = C.X509_NAME_new()
  if ctx == nil then
    return nil, "X509_NAME_new() failed"
  end
  ffi_gc(ctx, C.X509_NAME_free)

  local self = setmetatable({
    ctx = ctx,
  }, mt)

  return self, nil
end

function _M.istype(l)
  return l and l.ctx and ffi.istype(x509_name_ptr_ct, l.ctx)
end

function _M:add(nid, txt)
  local asn1 = C.OBJ_txt2obj(nid, 0)
  if asn1 == nil then
    return nil, "invalid NID text " .. (nid or "nil")
  end

  local code = C.X509_NAME_add_entry_by_OBJ(self.ctx, asn1, MBSTRING_ASC, txt, #txt, -1, 0)
  C.ASN1_OBJECT_free(asn1)

  if code ~= 1 then
    return nil, "X509_NAME_add_entry_by_OBJ() failed"
  end

  return self
end

function _M.dup(ctx)
  if not ffi.istype(x509_name_ptr_ct, ctx) then
    return nil, "expect a x509.name ctx at #1"
  end
  local ctx = C.X509_NAME_dup(ctx)
  ffi_gc(ctx, C.X509_NAME_free)

  local self = setmetatable({
    ctx = ctx,
  }, mt)

  return self, nil
end


return _M
