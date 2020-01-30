local ffi = require "ffi"
local C = ffi.C
local ffi_str = ffi.string
local ffi_sizeof = ffi.sizeof

require "resty.openssl.include.objects"

local char_ptr = ffi.typeof('char[?]')

local function obj2table(obj)
  local nid = C.OBJ_obj2nid(obj)

  local buf = char_ptr(100)
  local len = C.OBJ_obj2txt(buf, ffi_sizeof(buf), obj, 1)
  local oid = ffi_str(buf, len)

  return {
    id = oid,
    nid = nid,
    sn = ffi_str(C.OBJ_nid2sn(nid)),
    ln = ffi_str(C.OBJ_nid2ln(nid)),
  }
end

local function nid2table(nid)
  return obj2table(C.OBJ_nid2obj(nid))
end

local function txt2nid(txt)
  if type(txt) ~= "string" then
    return nil, "expect a string at #1"
  end
  local nid = C.OBJ_txt2nid(txt)
  if nid == 0 then
    return nil, "invalid NID text " .. nid
  end
  return nid
end

local function txtnid2nid(txt_nid)
  local nid
  if type(txt_nid) == "string" then
    nid = C.OBJ_txt2nid(txt_nid)
    if nid == 0 then
      return nil, "invalid NID text " .. nid
    end
  elseif type(txt_nid) == "number" then
    nid = txt_nid
  else
    return nil, "expect string or number at #1"
  end
  return nid
end

return {
  obj2table = obj2table,
  nid2table = nid2table,
  txt2nid = txt2nid,
  txtnid2nid = txtnid2nid,
}