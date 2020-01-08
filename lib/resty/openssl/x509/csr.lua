local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc

require "resty.openssl.include.x509.csr"
local stack_lib = require "resty.openssl.stack"
local pkey_lib = require "resty.openssl.pkey"
local altname_lib = require "resty.openssl.x509.altname"
local x509_name_lib = require "resty.openssl.x509.name"
local util = require "resty.openssl.util"
local format_error = require("resty.openssl.err").format_error

local function tostring(self, fmt)
  if not fmt or fmt == 'PEM' then
    return util.read_using_bio(C.PEM_write_bio_X509_REQ, self.ctx)
  elseif fmt == 'DER' then
    return util.read_using_bio(C.i2d_X509_REQ_bio, self.ctx)
  else
    return nil, "can only write PEM or DER format, not " .. fmt
  end
end

local _M = {}
local mt = { __index = _M, __tostring = tostring }

local x509_req_ptr_ct = ffi.typeof("X509_REQ*")

function _M.new()
  local ctx = C.X509_REQ_new()
  if ctx == nil then
    return nil, "X509_REQ_new() failed"
  end
  ffi_gc(ctx, C.X509_REQ_free)

  local self = setmetatable({
    ctx = ctx,
  }, mt)

  return self, nil
end

function _M.istype(l)
  return l and l and l.ctx and ffi.istype(x509_req_ptr_ct, l.ctx)
end

function _M:set_subject_name(name)
  if not x509_name_lib.istype(name) then
    return "expect a x509.name instance at #1"
  end
  local code = C.X509_REQ_set_subject_name(self.ctx, name.ctx)
  if code == 0 then
    return format_error("csr:setSubject")
  end
end

local X509_EXTENSION_stack_gc = stack_lib.gc_of("X509_EXTENSION")
local stack_ptr_type = ffi.typeof("struct stack_st *[1]")

-- https://github.com/wahern/luaossl/blob/master/src/openssl.c
local function xr_modifyRequestedExtension(csr, target_nid, value, crit, flags)
  local has_attrs = C.X509_REQ_get_attr_count(csr)
  if has_attrs > 0 then
    return "X509_REQ already has more than more attributes" ..
          "modifying is currently not supported"
  end

  local sk = stack_ptr_type()
  sk[0] = C.X509_REQ_get_extensions(csr)

  local code
  code = C.X509V3_add1_i2d(sk, target_nid, value, crit, flags)
  local err
  if code ~= 1 then
    err = "X509V3_add1_i2d() failed: " .. code
  end
  code = C.X509_REQ_add_extensions(csr, sk[0])
  if code ~= 1 then
    err = "X509_REQ_add_extensions() failed: " .. code
  end

  X509_EXTENSION_stack_gc(sk[0])
  return err
end

function _M:set_subject_alt_name(alt)
  if not altname_lib.istype(alt) then
    return "expect a x509.altname instance at #1"
  end
  -- #define NID_subject_alt_name            85
  -- #define X509V3_ADD_REPLACE              2L
  return xr_modifyRequestedExtension(self.ctx, 85, alt.ctx, 0, 2)
end

-- backward compatibility
_M.set_subject_alt = _M.set_subject_alt_name

function _M:set_pubkey(pkey)
  if not pkey_lib.istype(pkey) then
    return "expect a pkey instance at #1"
  end
  local code = C.X509_REQ_set_pubkey(self.ctx, pkey.ctx)
  if code ~= 1 then
    return "X509_REQ_set_pubkey() failed: " .. code
  end
end

local int_ptr = ffi.typeof("int[1]")
function _M:sign(pkey)
  if not pkey_lib.istype(pkey) then
    return "expect a pkey instance at #1"
  end

  local nid = int_ptr()
  local code = C.EVP_PKEY_get_default_digest_nid(pkey.ctx, nid)
  if code <= 0 then -- 1: advisory 2: mandatory
    return "EVP_PKEY_get_default_digest_nid() failed: " .. code
  end
  local name = C.OBJ_nid2sn(nid[0])
  if name == nil then
    return "OBJ_nid2sn() failed"
  end
  -- EVP_get_digestbynid is a macro
  local md = C.EVP_get_digestbyname(name)
  if md == nil then
    return "EVP_get_digestbyname() failed"
  end
  local sz = C.X509_REQ_sign(self.ctx, pkey.ctx, md)
  if sz == 0 then
    return "X509_REQ_sign() failed"
  end
end

function _M:tostring(fmt)
  return tostring(self, fmt)
end

function _M:toPEM()
  return tostring(self, "PEM")
end


return _M

