local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc
local ffi_str = ffi.string
local ffi_sizeof = ffi.sizeof

require "resty.openssl.include.x509.name"
local asn1_macro = require "resty.openssl.include.asn1"

-- local MBSTRING_FLAG = 0x1000
local MBSTRING_ASC  = 0x1001 -- (MBSTRING_FLAG|1)

local _M = {}

local x509_name_ptr_ct = ffi.typeof("X509_NAME*")

local char_ptr = ffi.typeof('char[?]')
-- starts from 0
local function value_at(ctx, i)
  local entry = C.X509_NAME_get_entry(ctx, i)
  local obj = C.X509_NAME_ENTRY_get_object(entry)
  local nid = C.OBJ_obj2nid(obj)

  local buf = char_ptr(100)
  local len = C.OBJ_obj2txt(buf, ffi_sizeof(buf), obj, 1)
  local oid = ffi_str(buf, len)

  local str = C.X509_NAME_ENTRY_get_data(entry)
  local blob
  if str ~= nil then
    blob = ffi_str(asn1_macro.ASN1_STRING_get0_data(str))
  end

  return {
    id = oid,
    nid = nid,
    sn = ffi_str(C.OBJ_nid2sn(nid)),
    ln = ffi_str(C.OBJ_nid2ln(nid)),
    blob = blob,
  }
end

local function iter(tbl)
  local i = 0
  local n = tonumber(C.X509_NAME_entry_count(tbl.ctx))
  return function()
    i = i + 1
    if i <= n then
      local obj = value_at(tbl.ctx, i-1)
      return obj.sn or obj.ln or obj.id, obj
    end
  end
end

local mt = {
  __index = _M,
  __pairs = iter,
  __len = function(tbl) return tonumber(C.X509_NAME_entry_count(tbl.ctx)) end,
}

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

function _M:find(nid, last_post)
  local asn1 = C.OBJ_txt2obj(nid, 0)
  if asn1 == nil then
    return nil, nil, "invalid NID text " .. (nid or "nil")
  end
  -- make 1-index array to 0-index
  last_post = (last_post or 0) - 1

  local idx = C.X509_NAME_get_index_by_OBJ(self.ctx, asn1, last_post)
  if idx == -1 then
    return nil, nil, nil
  end

  return value_at(self.ctx, idx), idx + 1
end

-- fallback function to iterate if LUAJIT_ENABLE_LUA52COMPAT not enabled
function _M:all()
  local ret = {}
  local next_ = iter(self)
  while true do
    local k, obj = next_()
    if obj then
      ret[k] = obj
    else
      break
    end
  end
  return ret
end

function _M:each()
  return iter(self)
end

return _M
