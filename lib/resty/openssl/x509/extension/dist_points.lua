local ffi = require "ffi"
local C = ffi.C
local ffi_cast = ffi.cast
local ffi_str = ffi.string

require "resty.openssl.include.x509"
require "resty.openssl.include.x509v3"
local altname_lib = require "resty.openssl.x509.altname"
local stack_lib = require "resty.openssl.stack"

local _M = {}
local mt

local stack_ptr_ct = ffi.typeof("OPENSSL_STACK*")

local STACK = "DIST_POINT"
local new = stack_lib.new_of(STACK)
local dup = stack_lib.dup_of(STACK)

-- TODO: return other attributes?
local cdp_decode_fullname = function(ctx)
  return altname_lib.dup(ctx.distpoint.name.fullname)
end

mt = stack_lib.mt_of(STACK, cdp_decode_fullname, _M)

function _M.new()
  local ctx = new()
  if ctx == nil then
    return nil, "OPENSSL_sk_new_null() failed"
  end

  local self = setmetatable({
    ctx = ctx,
    _is_dup = false,
  }, mt)

  return self, nil
end

function _M.istype(l)
  return l and l.cast and ffi.istype(stack_ptr_ct, l.cast)
end

function _M.dup(ctx)
  if ctx == nil or not ffi.istype(stack_ptr_ct, ctx) then
    return nil, "expect a stack ctx at #1"
  end
  ctx = dup(ctx)

  return setmetatable({
    ctx = ctx,
    _is_dup = true,
    _elem_refs = {},
    _elem_refs_idx = 1,
  }, mt), nil
end

_M.all = function(stack)
  local ret = {}
  local _next = mt.__ipairs(stack)
  while true do
    local i, e = _next()
    if i then
      ret[i] = e
    else
      break
    end
  end
  return ret
end

return _M
