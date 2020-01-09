local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc
local ffi_cast = ffi.cast
local ffi_str = ffi.string

require "resty.openssl.include.x509"
require "resty.openssl.include.x509v3"
local asn1_macro = require "resty.openssl.include.asn1"
local stack_lib = require "resty.openssl.stack"
local altname_macro = require "resty.openssl.include.x509.altname"

local _M = {}

local general_names_ptr_ct = ffi.typeof("GENERAL_NAMES*")

local STACK = "GENERAL_NAME"
local new = stack_lib.new_of(STACK)
local add = stack_lib.add_of(STACK)
local dup = stack_lib.dup_of(STACK)

local types = altname_macro.types

local gn_decode = function(ctx)
  local typ = ctx.type
  local k = altname_macro.literals[typ]
  local v
  if typ == types.DNS then
    v = ffi_str(asn1_macro.ASN1_STRING_get0_data(ctx.d.dNSName))
  elseif typ == types.URI then
    v = ffi_str(asn1_macro.ASN1_STRING_get0_data(ctx.d.uniformResourceIdentifier))
  elseif typ == types.RFC822Name then
    v = ffi_str(asn1_macro.ASN1_STRING_get0_data(ctx.d.rfc822Name))
  elseif typ == types.IP then
    error("NYI")
  elseif typ == types.DirName then
    error("NYI")
  else
    error("unknown type" .. typ)
  end
  return { k, v }
end

-- shared with info_access
_M.gn_decode = gn_decode

local mt = stack_lib.mt_of(STACK, gn_decode, _M)
local mt__pairs = mt.__pairs
mt.__pairs = function(tbl)
  local f = mt__pairs(tbl)
  return function()
    local _, e = f()
    if not e then return end
    return unpack(e)
  end
end

function _M.new()
  local ctx = new()
  if ctx == nil then
    return nil, "OPENSSL_sk_new_null() failed"
  end
  local cast = ffi_cast("GENERAL_NAMES*", ctx)

  local self = setmetatable({
    ctx = ctx,
    cast = cast,
    _is_dup = false,
  }, mt)

  return self, nil
end

function _M.istype(l)
  return l and l.cast and ffi.istype(general_names_ptr_ct, l.cast)
end

function _M.dup(ctx)
  if ctx == nil or not ffi.istype(general_names_ptr_ct, ctx) then
    return nil, "expect a GENERAL_NAMES* ctx at #1"
  end
  ctx = dup(ctx)

  return setmetatable({
    cast = ffi_cast("GENERAL_NAMES*", ctx),
    ctx = ctx,
    _is_dup = true,
    _elem_refs = {},
    _elem_refs_idx = 1,
  }, mt), nil
end

local function gn_set(gn, typ, value)
  if not typ then
    return "expect a string at #1"
  end
  typ = typ:lower()
  if type(value) ~= 'string' then
    return "except a string at #2"
  end

  local txt = value
  local gn_type = types[typ]
  if not gn_type then
    return "unknown type " .. typ
  end

  gn.type = gn_type

  local asn1_string = C.ASN1_IA5STRING_new()
  if asn1_string == nil then
    C.GENERAL_NAME_free(gn)
    return "ASN1_STRING_type_new() failed"
  end

  gn.d.ia5 = asn1_string

  local code = C.ASN1_STRING_set(gn.d.ia5, txt, #txt)
  if code ~= 1 then
    C.GENERAL_NAME_free(gn)
    return "ASN1_STRING_set() failed: " .. code
  end
end

-- shared with info_access
_M.gn_set = gn_set

function _M:add(typ, value)

  -- the stack element stays with stack
  -- we shouldn't add gc handler if it's already been
  -- pushed to stack. instead, rely on the gc handler
  -- of the stack to release all memories
  local gn = C.GENERAL_NAME_new()
  if gn == nil then
    return nil, "GENERAL_NAME_new() failed"
  end

  local err = gn_set(gn, typ, value)
  if err then
    return err
  end

  local _, err = add(self.ctx, gn)
  if err then
    C.GENERAL_NAME_free(gn)
    return nil, err
  end

  -- if the stack is duplicated, the gc handler is not pop_free
  -- handle the gc by ourselves
  if self._is_dup then
    ffi_gc(gn, C.GENERAL_NAME_free)
    self._elem_refs[self._elem_refs_idx] = gn
    self._elem_refs_idx = self._elem_refs_idx + 1
  end
  return self
end

_M.all = function(self)
  local ret = {}
  local _next = mt.__pairs(self)
  while true do
    local k, v = _next()
    if k then
      ret[k] = v
    else
      break
    end
  end
  return ret
end

_M.each = mt.__pairs
_M.index = mt.__index
_M.count = mt.__len

return _M
