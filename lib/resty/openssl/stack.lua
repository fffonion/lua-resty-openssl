
--[[
  The OpenSSL stack library. Note `safestack` is not usable here in ffi because
  those symbols are eaten after preprocessing.
  Instead, we should do a Lua land type checking by having a nested field indicating
  which type of cdata its ctx holds.
]]
local ffi = require "ffi"
local C = ffi.C
local ffi_cast = ffi.cast
local ffi_gc = ffi.gc

local stack_macro = require "resty.openssl.include.stack"
local format_error = require("resty.openssl.err").format_error

local _M = {}

local function gc_of(typ)
  if not C[typ .. "_free"] then
    error(typ .. "_free is not defined in ffi.cdef")
  end
  local f = C[typ .. "_free"]
  return function (st)
    stack_macro.OPENSSL_sk_pop_free(st, f)
  end
end

_M.gc_of = gc_of

_M.mt_of = function(typ, element_lib, index_tbl)
  if type(typ) ~= "string" then
    error("expect a string at #1")
  elseif type(element_lib) ~= "table" then
    error("expect a table at #2")
  elseif not element_lib.dup then
    error("dup() must be implemented in the stack element type")
  end

  local typ_ptr = typ .. "*"

  -- starts from 0
  local function value_at(ctx, i)
    local elem = stack_macro.OPENSSL_sk_value(ctx, i)
    if elem == nil then
      error(format_error("OPENSSL_sk_value"))
    end
    local dup, err = element_lib.dup(ffi_cast(typ_ptr, elem))
    if err then
      error(err)
    end
    return dup
  end

  local function iter(tbl)
    local i = 0
    local n = tonumber(stack_macro.OPENSSL_sk_num(tbl.ctx))
    return function()
      i = i + 1
      if i <= n then
        return i, value_at(tbl.ctx, i-1)
      end
    end
  end

  return {
    __pairs = iter,
    __ipairs = iter,
    __len = function(tbl)
      return tonumber(stack_macro.OPENSSL_sk_num(tbl.ctx))
    end,
    __index = function(tbl, k)
      local i = tonumber(k)
      if not i then
        return index_tbl[k]
      end
      local n = stack_macro.OPENSSL_sk_num(tbl.ctx)
      if i <= 0 or i > n then
        return nil
      end
      return value_at(tbl.ctx, i-1)
    end,
    __gc = gc_of(typ),
  }
end

_M.new_of = function(typ)
  local gc = gc_of(typ)
  return function()
    local raw = stack_macro.OPENSSL_sk_new_null()
    if raw == nil then
      return nil, "OPENSSL_sk_new_null() failed"
    end
    ffi_gc(raw, gc)
    return raw
  end
end

_M.add_of = function(typ)
  local ptr = ffi.typeof(typ .. "*")
  return function(stack, ctx)
    if ctx == nil or not ffi.istype(ptr, ctx) then
      return false, "expect a " .. typ .. "* at #1"
    end
    local code = stack_macro.OPENSSL_sk_push(stack, ctx)
    if code == 0 then
      return false, "OPENSSL_sk_push() failed"
    end
    return true
  end
end

return _M