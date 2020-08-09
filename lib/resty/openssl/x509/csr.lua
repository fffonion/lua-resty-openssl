local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc
local ffi_cast = ffi.cast

require "resty.openssl.include.pem"
require "resty.openssl.include.x509v3"
require "resty.openssl.include.x509.csr"
require "resty.openssl.include.x509.extension"
require "resty.openssl.include.asn1"
local stack_macro = require "resty.openssl.include.stack"
local stack_lib = require "resty.openssl.stack"
local pkey_lib = require "resty.openssl.pkey"
local altname_lib = require "resty.openssl.x509.altname"
local digest_lib = require("resty.openssl.digest")
local extension_lib = require("resty.openssl.x509.extension")
local util = require "resty.openssl.util"
local txtnid2nid = require("resty.openssl.objects").txtnid2nid
local format_error = require("resty.openssl.err").format_error
local OPENSSL_10 = require("resty.openssl.version").OPENSSL_10
local OPENSSL_11_OR_LATER = require("resty.openssl.version").OPENSSL_11_OR_LATER
local ext_typ_ptr = "X509_EXTENSION*"
local accessors = {}

local push = table.insert
accessors.set_subject_name = C.X509_REQ_set_subject_name
accessors.get_pubkey = C.X509_REQ_get_pubkey
accessors.set_pubkey = C.X509_REQ_set_pubkey
accessors.set_version = C.X509_REQ_set_version

if OPENSSL_11_OR_LATER then
  accessors.get_subject_name = C.X509_REQ_get_subject_name -- returns internal ptr
  accessors.get_version = C.X509_REQ_get_version
elseif OPENSSL_10 then
  accessors.get_subject_name = function(csr)
    if csr == nil or csr.req_info == nil then
      return nil
    end
    return csr.req_info.subject
  end
  accessors.get_version = function(csr)
    if csr == nil or csr.req_info == nil then
      return nil
    end
    return C.ASN1_INTEGER_get(csr.req_info.version)
  end
end

local function tostring(self, fmt)
  if not fmt or fmt == 'PEM' then
    return util.read_using_bio(C.PEM_write_bio_X509_REQ, self.ctx)
  elseif fmt == 'DER' then
    return util.read_using_bio(C.i2d_X509_REQ_bio, self.ctx)
  else
    return nil, "x509.csr:tostring: can only write PEM or DER format, not " .. fmt
  end
end

local _M = {}
local mt = { __index = _M, __tostring = tostring }

local x509_req_ptr_ct = ffi.typeof("X509_REQ*")

function _M.new(csr, fmt)
  local ctx
  if not csr then
    ctx = C.X509_REQ_new()
    if ctx == nil then
      return nil, "x509.csr.new: X509_REQ_new() failed"
    end
  elseif type(csr) == "string" then
    -- routine for load an existing csr
    local bio = C.BIO_new_mem_buf(csr, #csr)
    if bio == nil then
      return nil, format_error("x509.csr.new: BIO_new_mem_buf")
    end

    fmt = fmt or "*"
    while true do
      if fmt == "PEM" or fmt == "*" then
        ctx = C.PEM_read_bio_X509_REQ(bio, nil, nil, nil)
        if ctx ~= nil then
          break
        elseif fmt == "*" then
          -- BIO_reset; #define BIO_CTRL_RESET 1
          local code = C.BIO_ctrl(bio, 1, 0, nil)
          if code ~= 1 then
              return nil, "x509.csr.new: BIO_ctrl() failed: " .. code
          end
          -- clear errors occur when trying
          C.ERR_clear_error()
        end
      end
      if fmt == "DER" or fmt == "*" then
        ctx = C.d2i_X509_REQ_bio(bio, nil)
      end
      break
    end
    C.BIO_free(bio)
    if ctx == nil then
      return nil, format_error("x509.csr.new")
    end
  else
    return nil, "x509.csr.new: expect nil or a string at #1"
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


local X509_EXTENSION_stack_gc = stack_lib.gc_of("X509_EXTENSION")
local stack_ptr_type = ffi.typeof("struct stack_st *[1]")

-- https://github.com/wahern/luaossl/blob/master/src/openssl.c
local function xr_modifyRequestedExtension(csr, target_nid, value, crit, flags)
  local has_attrs = C.X509_REQ_get_attr_count(csr)
  if has_attrs > 0 then
    return false, "x509.csr:xr_modifyRequestedExtension: X509_REQ already has more than more attributes" ..
          "modifying is currently not supported"
  end

  local sk = stack_ptr_type()
  sk[0] = C.X509_REQ_get_extensions(csr)

  local code
  code = C.X509V3_add1_i2d(sk, target_nid, value, crit, flags)
  local err
  if code ~= 1 then
    err = "x509.csr:xr_modifyRequestedExtension: X509V3_add1_i2d() failed: " .. code
  end
  code = C.X509_REQ_add_extensions(csr, sk[0])
  if code ~= 1 then
    err = "x509.csr:xr_modifyRequestedExtension: X509_REQ_add_extensions() failed: " .. code
  end

  X509_EXTENSION_stack_gc(sk[0])
  return true, err
end

function _M:set_subject_alt_name(alt)
  if not altname_lib.istype(alt) then
    return false, "x509.csr:set_subject_alt_name: expect a x509.altname instance at #1"
  end
  -- #define NID_subject_alt_name            85
  -- #define X509V3_ADD_REPLACE              2L
  return xr_modifyRequestedExtension(self.ctx, 85, alt.ctx, 0, 2)
end

-- backward compatibility
_M.set_subject_alt = _M.set_subject_alt_name

function _M:tostring(fmt)
  return tostring(self, fmt)
end

function _M:to_PEM()
  return tostring(self, "PEM")
end

--- Get all csr extensions
-- @tparam table self Instance of csr
-- @treturn List of parsed extension objects
function _M.get_extensions(self)
    local extensions = C.X509_REQ_get_extensions(self.ctx)
    ffi_gc(extensions, stack_macro.OPENSSL_sk_free)
    return extensions
end

--- Get a csr extension
-- @tparam table self Instance of csr
-- @tparam string|number Nid number or name of the extension
-- @treturn Parsed extension object or nil if not found
function _M.get_extension(self, nid)
    local i, err = txtnid2nid(nid)
    if err then
        return nil, err
    end
    local extensions = C.X509_REQ_get_extensions(self.ctx)
    if extensions == nil then
        return nil, format_error("csr.get_extension: X509_REQ_get_extensions")
    end
    ffi_gc(extensions, stack_macro.OPENSSL_sk_free)

    local ext_idx = C.X509v3_get_ext_by_NID(extensions, i, -1)
    if ext_idx == -1 then
        return nil, format_error(("x509.csr.get_extension: X509v3_get_ext_by_NID extension for %d not found"):format(nid))
    end

    local ctx = C.X509v3_get_ext(extensions, ext_idx)
    if ctx == nil then
        return nil, format_error("csr.get_extension: X509v3_get_ext")
    end
    ffi_gc(ctx, C.X509_EXTENSION_free)

    return extension_lib.dup(ctx)
end


-- START AUTO GENERATED CODE

-- AUTO GENERATED
function _M:sign(pkey, digest)
  if not pkey_lib.istype(pkey) then
    return false, "x509.csr:sign: expect a pkey instance at #1"
  end
  if not digest or not digest_lib.istype(digest) then
    return false, "x509.csr:sign: expect a digest instance at #2"
  end
  if not digest.dtyp then
    return false, "x509.csr:sign: expect a digest instance should have dtyp member"
  end

-- returns size of signature if success
  if C.X509_REQ_sign(self.ctx, pkey.ctx, digest.dtyp) == 0 then
    return false, format_error("x509.csr:sign")
  end

  return true
end

-- AUTO GENERATED
function _M:verify(pkey)
  if not pkey_lib.istype(pkey) then
    return false, "x509.csr:verify: expect a pkey instance at #1"
  end

  local code = C.X509_REQ_verify(self.ctx, pkey.ctx)
  if code == 1 then
    return true
  elseif code == 0 then
    return false
  else -- typically -1
    return false, format_error("x509.csr:verify", code)
  end

  return true
end
-- AUTO GENERATED
function _M:get_subject_name()
  local got = accessors.get_subject_name(self.ctx)
  if got == nil then
    return nil
  end
  local lib = require("resty.openssl.x509.name")
  -- the internal ptr is returned, ie we need to copy it
  return lib.dup(got)
end

-- AUTO GENERATED
function _M:set_subject_name(toset)
  local lib = require("resty.openssl.x509.name")
  if lib.istype and not lib.istype(toset) then
    return false, "x509.csr:set_subject_name: expect a x509.name instance at #1"
  end
  toset = toset.ctx
  if accessors.set_subject_name(self.ctx, toset) == 0 then
    return false, format_error("x509.csr:set_subject_name")
  end

  return true
end

-- AUTO GENERATED
function _M:get_pubkey()
  local got = accessors.get_pubkey(self.ctx)
  if got == nil then
    return nil
  end
  local lib = require("resty.openssl.pkey")
  -- returned a copied instance directly
  return lib.new(got)
end

-- AUTO GENERATED
function _M:set_pubkey(toset)
  local lib = require("resty.openssl.pkey")
  if lib.istype and not lib.istype(toset) then
    return false, "x509.csr:set_pubkey: expect a pkey instance at #1"
  end
  toset = toset.ctx
  if accessors.set_pubkey(self.ctx, toset) == 0 then
    return false, format_error("x509.csr:set_pubkey")
  end

  return true
end

-- AUTO GENERATED
function _M:get_version()
  local got = accessors.get_version(self.ctx)
  if got == nil then
    return nil
  end

  got = tonumber(got) + 1

  return got
end

-- AUTO GENERATED
function _M:set_version(toset)
  if type(toset) ~= "number" then
    return false, "x509.csr:set_version: expect a number at #1"
  end

  -- Note: this is defined by standards (X.509 et al) to be one less than the certificate version.
  -- So a version 3 certificate will return 2 and a version 1 certificate will return 0.
  toset = toset - 1

  if accessors.set_version(self.ctx, toset) == 0 then
    return false, format_error("x509.csr:set_version")
  end

  return true
end


-- END AUTO GENERATED CODE

return _M

