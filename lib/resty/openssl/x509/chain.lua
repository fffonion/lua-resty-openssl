local ffi = require "ffi"
local C = ffi.C

local stack_lib = require "resty.openssl.stack"
local x509_lib = require "resty.openssl.x509"
local format_error = require("resty.openssl.err").format_error

local _M = {}

local stack_ptr_ct = ffi.typeof("OPENSSL_STACK*")

local STACK_OF = "X509"
local mt = stack_lib.mt_of(STACK_OF, x509_lib, _M)
local new = stack_lib.new_of(STACK_OF)
local add = stack_lib.add_of(STACK_OF)

function _M.new()
  local raw = new()

  local self = setmetatable({
    stack_of = STACK_OF,
    ctx = raw,
  }, mt)

  return self, nil
end

function _M.istype(l)
  return l and l.ctx and ffi.istype(stack_ptr_ct, l.ctx)
            and l.stack_of and l.stack_of == STACK_OF
end

function _M:add(x509)
  if not x509_lib.istype(x509) then
    return nil, "expect a x509 instance at #1"
  end

  local dup = C.X509_dup(x509.ctx)
  if dup == nil then
    return nil, format_error("chain:add: X509_dup")
  end

  local _, err = add(self.ctx, dup)
  if err then
    C.X509_free(dup)
    return nil, err
  end

  return true
end

return _M
