local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc

local stack_lib = require "resty.openssl.stack"
local crl_lib = require "resty.openssl.x509.crl"
local format_error = require("resty.openssl.err").format_error

local _M = {}

local stack_ptr_ct = ffi.typeof("OPENSSL_STACK*")

local STACK = "X509_CRL"
local new = stack_lib.new_of(STACK)
local add = stack_lib.add_of(STACK)
local dup = stack_lib.dup_of(STACK)
local mt = stack_lib.mt_of(STACK, crl_lib.dup, _M)

function _M.new()
  local raw, err = new()
  if raw == nil then
    return nil, err
  end

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

function _M.dup(ctx)
  if ctx == nil or not ffi.istype(stack_ptr_ct, ctx) then
    return nil, "x509.crl_stack.dup: expect a stack ctx at #1, got " .. type(ctx)
  end
  -- sk_X509_dup plus up ref for each X509 element
  local dup_ctx, err = dup(ctx)
  if dup_ctx == nil then
    return nil, "x509.crl_stack.dup: " .. err
  end

  return setmetatable({
    stack_of = STACK,
    ctx = dup_ctx,
    -- don't let lua gc the original stack to keep its elements
    _dupped_from = ctx,
    _is_shallow_copy = true,
    _elem_refs = {},
    _elem_refs_idx = 1,
  }, mt)
end

function _M:add(crl)
  if not crl_lib.istype(crl) then
    return nil, "x509.crl_stack:add: expect a crl instance at #1"
  end

  local dup = C.X509_CRL_dup(crl.ctx)
  if dup == nil then
    return nil, format_error("x509.crl_stack:add: X509_CRL_dup")
  end

  local res, err = add(self.ctx, dup)
  if not res then
    C.X509_CRL_free(dup)
    return nil, err
  end

  -- if the stack is duplicated, the gc handler is not pop_free
  -- handle the gc by ourselves
  if self._is_shallow_copy then
    ffi_gc(dup, C.X509_CRL_free)
    self._elem_refs[self._elem_refs_idx] = dup
    self._elem_refs_idx = self._elem_refs_idx + 1
  end

  return true
end

_M.all = stack_lib.all_func(mt)
_M.each = mt.__ipairs
_M.index = mt.__index
_M.count = mt.__len

return _M
