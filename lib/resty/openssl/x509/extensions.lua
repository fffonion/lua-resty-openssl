local ffi = require "ffi"
local C = ffi.C

local stack_lib = require "resty.openssl.stack"
local extension_lib = require "resty.openssl.x509.extension"
local format_error = require("resty.openssl.err").format_error

local _M = {}

local stack_ptr_ct = ffi.typeof("OPENSSL_STACK*")

local STACK = "X509_EXTENSION"
local new = stack_lib.new_of(STACK)
local add = stack_lib.add_of(STACK)
local mt = stack_lib.mt_of(STACK, extension_lib.dup, _M)

_M.all = stack_lib.all_func(mt)
_M.index = mt.__index
_M.count = mt.__len

function _M.new()
  local raw = new()

  local self = setmetatable({
    stack_of = STACK,
    ctx = raw,
  }, mt)

  return self, nil
end

function _M.istype(l)
  return l and l.ctx and ffi.istype(stack_ptr_ct, l.ctx)
            and l.stack_of and l.stack_of == STACK
end


function _M:add(extension)
  if not extension_lib.istype(extension) then
    return nil, "expect a x509.extension instance at #1"
  end

  local dup = C.X509_EXTENSION_dup(extension.ctx)
  if dup == nil then
    return nil, format_error("extensions:add: X509_EXTENSION_dup")
  end

  local _, err = add(self.ctx, dup)
  if err then
    C.X509_EXTENSION_free(dup)
    return nil, err
  end

  return true
end

return _M
