local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc
local ffi_new = ffi.new

require "resty.openssl.ossl_typ"
require "resty.openssl.bio"
require "resty.openssl.pem"
local asn1_lib = require("resty.openssl.asn1")
local digest_lib = require("resty.openssl.digest")
local x509_name_lib = require("resty.openssl.x509.name")
local util = require("resty.openssl.util")
local format_error = require("resty.openssl.err").format_error
local OPENSSL_10 = require("resty.openssl.version").OPENSSL_10
local OPENSSL_11 = require("resty.openssl.version").OPENSSL_11

ffi.cdef [[
  // DECLARE_ASN1_FUNCTIONS(X509), NYI
  X509* X509_new(void);
  void X509_free(X509 *a);

  typedef struct X509_extension_st X509_EXTENSION;
  X509_EXTENSION *X509_EXTENSION_new(void);
  X509_EXTENSION *X509_EXTENSION_dup(X509_EXTENSION *a);
  void X509_EXTENSION_free(X509_EXTENSION *a);

  int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);

  ASN1_TIME *X509_gmtime_adj(ASN1_TIME *s, long adj);

  int X509_add_ext(X509 *x, X509_EXTENSION *ex, int loc);
  X509_EXTENSION *X509_get_ext(const X509 *x, int loc);
  int X509_get_ext_by_NID(const X509 *x, int nid, int lastpos);

  int X509_EXTENSION_set_critical(X509_EXTENSION *ex, int crit);

  // needed by pkey
  EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a);
  EVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVP_PKEY **a);

]]

-- accessors provides an openssl version neutral interface to lua layer
-- it doesn't handle any error, expect that to be implemented in 
-- _M.set_X or _M.get_X
local accessors = {}
ffi.cdef [[
  int X509_set_pubkey(X509 *x, EVP_PKEY *pkey);
  int X509_set_version(X509 *x, long version);
  int X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial);
  int X509_set_subject_name(X509 *x, X509_NAME *name);
  int X509_set_issuer_name(X509 *x, X509_NAME *name);
]]
accessors.set_pubkey = C.X509_set_pubkey
accessors.set_version = C.X509_set_version
accessors.set_serial_number = C.X509_set_serialNumber
accessors.set_subject_name = C.X509_set_subject_name
accessors.set_issuer_name = C.X509_set_issuer_name

if OPENSSL_11 then
  ffi.cdef [[
    int X509_set1_notBefore(X509 *x, const ASN1_TIME *tm);
    int X509_set1_notAfter(X509 *x, const ASN1_TIME *tm);
    /*const*/ ASN1_TIME *X509_get0_notBefore(const X509 *x);
    /*const*/ ASN1_TIME *X509_get0_notAfter(const X509 *x);
    EVP_PKEY *X509_get_pubkey(X509 *x);
    long X509_get_version(const X509 *x);
    const ASN1_INTEGER *X509_get0_serialNumber(X509 *x);
    X509_NAME *X509_get_subject_name(const X509 *a);
    X509_NAME *X509_get_issuer_name(const X509 *a);
  ]]
  -- generally, use get1 if we return a lua table wrapped ctx which doesn't support dup.
  -- in that case, a new struct is returned from C api, and we will handle gc.
  -- openssl will increment the reference count for returned ptr, and won't free it when
  -- parent struct is freed.
  -- otherwise, use get0, which returns an internal pointer, we don't need to free it up.
  -- it will be gone together with the parent struct.
  accessors.set_not_before = C.X509_set1_notBefore
  accessors.get_not_before = C.X509_get0_notBefore -- returns internal ptr, we convert to number
  accessors.set_not_after = C.X509_set1_notAfter
  accessors.get_not_after = C.X509_get0_notAfter -- returns internal ptr, we convert to number
  accessors.get_pubkey = C.X509_get_pubkey -- returns new evp_pkey instance, don't need to dup
  accessors.get_version = C.X509_get_version -- returns int
  accessors.get_serial_number = C.X509_get0_serialNumber -- returns internal ptr, we convert to bn
  accessors.get_subject_name = C.X509_get_subject_name -- returns internal ptr, we dup it
  accessors.get_issuer_name = C.X509_get_issuer_name -- returns internal ptr, we dup it
elseif OPENSSL_10 then
  -- in openssl 1.0.x some getters are direct accessor to struct members (defiend by macros)
  ffi.cdef [[
    // crypto/x509/x509.h
    typedef struct X509_val_st {
      ASN1_TIME *notBefore;
      ASN1_TIME *notAfter;
    } X509_VAL;
    // Note: this struct is trimmed
    typedef struct x509_cinf_st {
      /*ASN1_INTEGER*/ void *version;
      /*ASN1_INTEGER*/ void *serialNumber;
      /*X509_ALGOR*/ void *signature;
      /*X509_NAME*/ void *issuer;
      X509_VAL *validity;
      // trimmed
    } X509_CINF;
    // Note: this struct is trimmed
    struct x509_st {
      X509_CINF *cert_info;
      // trimmed
    } X509;

    int X509_set_notBefore(X509 *x, const ASN1_TIME *tm);
    int X509_set_notAfter(X509 *x, const ASN1_TIME *tm);
    EVP_PKEY *X509_get_pubkey(X509 *x);
    ASN1_INTEGER *X509_get_serialNumber(X509 *x);
    X509_NAME *X509_get_subject_name(const X509 *a);
    X509_NAME *X509_get_issuer_name(const X509 *a);
  ]]
  accessors.set_not_before = C.X509_set_notBefore
  accessors.get_not_before = function(x509)
    if x509 == nil or x509.cert_info == nil or x509.cert_info.validity == nil then
      return nil
    end
    return x509.cert_info.validity.notBefore
  end
  accessors.set_not_after = C.X509_set_notAfter
  accessors.get_not_after = function(x509)
    if x509 == nil or x509.cert_info == nil or x509.cert_info.validity == nil then
      return nil
    end
    return x509.cert_info.validity.notAfter
  end
  accessors.get_pubkey = C.X509_get_pubkey -- returns new evp_pkey instance, don't need to dup
  accessors.get_version = function(x509)
    return C.ASN1_INTEGER_get(x509.cert_info.version)
  end
  accessors.get_serial_number = C.X509_get_serialNumber -- returns internal ptr, we convert to bn
  accessors.get_subject_name = C.X509_get_subject_name -- returns internal ptr, we dup it
  accessors.get_issuer_name = C.X509_get_issuer_name -- returns internal ptr, we dup it
end

local _M = {}
local mt = { __index = _M, __tostring = tostring }

local x509_ptr_ct = ffi.typeof("X509*")

-- only PEM format is supported for now
function _M.new(cert)
  local ctx
  if not cert then
    -- routine for create a new cert
    ctx = C.X509_new()
    if ctx == nil then
      return nil, format_error("x509.new")
    end
    ffi_gc(ctx, C.X509_free)

    C.X509_gmtime_adj(accessors.get_not_before(ctx), 0)
    C.X509_gmtime_adj(accessors.get_not_after(ctx), 0)
  elseif type(cert) == "string" then
    -- routine for load an existing cert
    local bio = C.BIO_new_mem_buf(cert, #cert)
    if bio == nil then
      return nil, format_error("x509.new: BIO_new_mem_buf")
    end

    ctx = C.PEM_read_bio_X509(bio, nil, nil, nil)
    C.BIO_free(bio)
    if ctx == nil then
      return nil, format_error("x509.new")
    end
    ffi_gc(ctx, C.X509_free)
  else
    return nil, "expect nil or a string at #1"
  end

  local self = setmetatable({
    ctx = ctx,
  }, mt)

  return self, nil
end

function _M.istype(l)
  return l and l.ctx and ffi.istype(x509_ptr_ct, l.ctx)
end

function _M:set_lifetime(not_before, not_after)
  local ok, err
  if not_before then
    ok, err = self:set_not_before(not_before)
    if err then
      return ok, err
    end
  end

  if not_after then
    ok, err = self:set_not_after(not_after)
    if err then
      return ok, err
    end
  end

  return true
end

function _M:get_lifetime()
  local err
  local not_before, err = self:get_not_before()
  if not_before == nil then
    return nil, nil, err
  end
  local not_after, err = self:get_not_after()
  if not_after == nil then
    return nil, nil, err
  end

  return not_before, not_after, nil
end

local number_to_asn1 = function(tm) return C.ASN1_TIME_set(nil, tm) end

-- Generate getter/setters
local attributes = {
  {
    -- name used in openssl
    field = "serial_number",
    -- attribute type
    typ = "resty.openssl.bn",
    -- the optional type converter
    from = function(bn_ctx)
      local ctx = C.BN_to_ASN1_INTEGER(bn_ctx, nil)
      if ctx == nil then
        return nil, format_error("x509:set: BN_to_ASN1_INTEGER")
      end
      -- "A copy of the serial number is used internally
      -- so serial should be freed up after use.""
      ffi_gc(ctx, C.ASN1_INTEGER_free)
      return ctx
    end,
    to = function(asn1_integer)
    end,
    dup = true,
  },
  {
    field = "not_before",
    typ = "number",
    from = number_to_asn1,
    to = asn1_lib.asn1_to_unix,
  },
  {
    field = "not_after",
    typ = "number",
    from = number_to_asn1,
    to = asn1_lib.asn1_to_unix,
  },
  {
    field = "pubkey",
    typ = "resty.openssl.pkey",
  },
  {
    field = "subject_name",
    typ = "resty.openssl.x509.name",
    dup = true,
  },
  {
    field = "issuer_name",
    typ = "resty.openssl.x509.name",
    dup = true,
  },
  {
    field = "version",
    typ = "number",
    -- Note: this is defined by standards (X.509 et al) to be one less than the certificate version.
    -- So a version 3 certificate will return 2 and a version 1 certificate will return 0.
    from = function(x)
      return x - 1
    end,
    to = tonumber,
  },
}

for _, attribute in ipairs(attributes) do
  local field = attribute.field
  local typ = attribute.typ

  local cfunc = "set_" .. field
  _M[cfunc] = function(self, i)
    local toset, err
    if typ == "number" or typ == "string" then
      if type(i) ~= typ then
        return false, "expect a " .. typ .. " at #1"
      end
      toset = i
    else
      local lib = require(typ)
      if lib.istype and not lib.istype(i) then
        return false, "expect a \"" ..  typ .. "\" instance at #1"
      end
      toset = i.ctx
    end

    if attribute.from then
      toset, err = attribute.from(toset)
      if err then
        return false, err
      end
    end

    if accessors[cfunc](self.ctx, toset) == 0 then
      return false, format_error("x509:set_" .. field)
    end

    return true
  end

  local cfunc = "get_" .. field
  _M[cfunc] = function(self)
    local ctx = accessors[cfunc](self.ctx)
    if ctx == nil then
      return nil, format_error("x509:get_" .. field)
    end

    if attribute.to then
      ctx = attribute.to(ctx)
    end
    if typ == "number" or typ == "string" then
      return ctx
    end

    local lib = require(typ)
    -- if the internal ptr is returned, ie we need copy it
    if attribute.dup then
      return lib.dup(ctx)
    -- otherwise just contruct a lua table
    else
      return lib.new(ctx)
    end
  end
  
end

function _M:add_extension(extension)
  local extension_lib = require("resty.openssl.x509.extension")
  if not extension_lib.istype(extension) then
    return false, "expect a x509.extension instance at #1"
  end

  -- X509_add_ext returnes the stack on success, and NULL on error
  if C.X509_add_ext(self.ctx, extension.ctx, -1) == nil then
    return false, format_error("x509:add_extension")
  end

  return true
end

function _M:set_basic_constraints(cfg)
  if type(cfg) ~= "table" then
    return false, "expect a table at #1"
  end

  local bc = C.BASIC_CONSTRAINTS_new()
  if bc == nil then
    return false, format_error("x509:set_basic_constraints")
  end

  bc.ca = cfg.CA and 0xFF or 0

  -- obj_mac.h: #define NID_basic_constraints           87
  -- x509v3.h: # define X509V3_ADD_REPLACE              2L
  local code = C.X509_add1_ext_i2d(self.ctx, 87, bc, 0, 0x2)
  C.BASIC_CONSTRAINTS_free(bc)
  if code ~= 1 then
    return false, format_error("x509:set_basic_constraints: X509_add1_ext_i2d", code)
  end

  return true
end

function _M:set_basic_constraints_critical(crit)
  local ext = ffi_new("X509_EXTENSION *")

  -- obj_mac.h: #define NID_basic_constraints           87
  local loc = C.X509_get_ext_by_NID(self.ctx, 87, -1)
  if loc == -1 then
    return false, format_error("x509:set_basic_constraints_critical: X509_get_ext_by_NID")
  end
  
  local ext = C.X509_get_ext(self.ctx, loc)
  if ext == nil then
    return false, format_error("x509:set_basic_constraints_critical: X509_get_ext")
  end

  if C.X509_EXTENSION_set_critical(ext, crit and 1 or 0) ~= 1 then
    return false, format_error("x509:set_basic_constraints_critical: X509_EXTENSION_set_critical")
  end

  return true
end

function _M:sign(pkey, digest)
  local pkey_lib = require("resty.openssl.pkey")
  if not pkey_lib.istype(pkey) then
    return false, "expect a pkey instance at #1"
  end
  if digest then
    if not digest_lib.istype(digest) then
      return false, "expect a digest instance at #2"
    end
  end

  -- returns size of signature if success
  if C.X509_sign(self.ctx, pkey.ctx, digest and digest.ctx) == 0 then
    return false, format_error("x509:sign")
  end

  return true
end

function _M:to_PEM()
  return util.read_using_bio(C.PEM_write_bio_X509, self.ctx)
end

return _M
