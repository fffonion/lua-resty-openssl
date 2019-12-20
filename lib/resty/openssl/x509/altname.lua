local ffi = require "ffi"
local C = ffi.C
local ffi_cast = ffi.cast

require "resty.openssl.include.x509v3"
require "resty.openssl.include.asn1"
local stack_lib = require "resty.openssl.stack"
local altname_macro = require "resty.openssl.include.x509.altname"

local _M = {}
local mt = { __index = _M }

local general_names_ptr_ct = ffi.typeof("GENERAL_NAMES*")

local STACK = "GENERAL_NAME"
local new = stack_lib.new_of(STACK)
local add = stack_lib.add_of(STACK)

local types = altname_macro.types

function _M.new()
  local raw = new()
  if raw == nil then
    return nil, "OPENSSL_sk_new_null() failed"
  end
  local ctx = ffi_cast("GENERAL_NAMES*", raw)

  local self = setmetatable({
    ctx = ctx,
    raw = raw
  }, mt)

  return self, nil
end

function _M.istype(l)
  return l and l.ctx and ffi.istype(general_names_ptr_ct, l.ctx)
end

function _M:add(typ, value)
  if not typ then
    return nil, "expect a string at #1"
  end
  typ = typ:lower()
  if type(value) ~= 'string' then
    return nil, "except a string at #2"
  end

  local txt = value
  local gen_type = types[typ]
  if not gen_type then
    return nil, "unknown type " .. typ
  end

  -- the stack element stays with stack
  -- we shouldn't add gc handler if it's already been
  -- pushed to stack. instead, rely on the gc handler
  -- of the stack to release all memories
  local gen = C.GENERAL_NAME_new()
  if gen == nil then
    return nil, "GENERAL_NAME_new() failed"
  end

  gen.type = gen_type

  -- #define V_ASN1_IA5STRING                22
  local asn1_string = C.ASN1_STRING_type_new(22)
  if asn1_string == nil then
    C.GENERAL_NAME_free(gen)
    return nil, "ASN1_STRING_type_new() failed"
  end

  gen.d.ia5 = asn1_string

  local code = C.ASN1_STRING_set(gen.d.ia5, txt, #txt)
  if code ~= 1 then
    C.GENERAL_NAME_free(gen)
    return nil, "ASN1_STRING_set() failed: " .. code
  end

  local _, err = add(self.ctx, gen)
  if err then
    C.GENERAL_NAME_free(gen)
    return nil, err
  end
  return self
end

return _M
