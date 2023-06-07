local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc
local ffi_str = ffi.string
local bor = bit.bor

local x509_vfy_macro = require "resty.openssl.include.x509_vfy"
local x509_lib = require "resty.openssl.x509"
local stack_lib = require "resty.openssl.stack"
local chain_lib = require "resty.openssl.x509.chain"
local crl_lib = require "resty.openssl.x509.crl"
local ctx_lib = require "resty.openssl.ctx"
local format_error = require("resty.openssl.err").format_error
local OPENSSL_11_OR_LATER = require("resty.openssl.version").OPENSSL_11_OR_LATER
local OPENSSL_3X = require("resty.openssl.version").OPENSSL_3X

local _M = {}
local mt = { __index = _M }

local store_ctx_ptr_ct = ffi.typeof('X509_STORE_CTX*')
local x509_store_ptr_ct = ffi.typeof('X509_STORE*')
local verify_flags = x509_vfy_macro.verify_flags
local flag_partial_chain = verify_flags.X509_V_FLAG_PARTIAL_CHAIN
local flag_crl_check = verify_flags.X509_V_FLAG_CRL_CHECK

local crl_stack_M = {}
local STACK = "X509_CRL"
local crl_stack_new = stack_lib.new_of(STACK)
local crl_stack_add = stack_lib.add_of(STACK)
local crl_stack_mt = stack_lib.mt_of(STACK, crl_lib.dup, crl_stack_M)

_M.verify_flags = verify_flags

-- to avoid circular reference among x509.store and x509.store_ctx,
-- we do this check by ourselves
local function istype_store(l)
  return l and l.ctx and ffi.istype(x509_store_ptr_ct, l.ctx)
end

function _M.new(store, x509, untrusted_chain, properties)
  local ctx

  if store and not istype_store(store) then
    return nil, "x509.store_ctx:new: expect a store instance at #1"
  elseif x509 and not x509_lib.istype(x509) then
    return nil, "x509.store_ctx:new: expect a x509 instance at #2"
  elseif untrusted_chain and not chain_lib.istype(untrusted_chain) then
    return nil, "x509.store_ctx:new: expect a x509.chain instance at #3"
  end

  if OPENSSL_3X then
    ctx = C.X509_STORE_CTX_new_ex(ctx_lib.get_libctx(), properties)
  else
    ctx = C.X509_STORE_CTX_new()
  end
  if ctx == nil then
    return nil, "x509.store_ctx.new: failed to create X509_STORE_CTX"
  end

  ffi_gc(ctx, C.X509_STORE_CTX_free)

  local chain_dup_ctx
  if untrusted_chain then
    local chain_dup, err = chain_lib.dup(untrusted_chain.ctx)
    if err then
      return nil, err
    end
    chain_dup_ctx = chain_dup.ctx
  end

  local store_ctx
  if store then
    store_ctx = store.ctx
  end

  local x509_ctx
  if x509 then
    x509_ctx = x509.ctx
  end

  if C.X509_STORE_CTX_init(ctx, store_ctx, x509_ctx, chain_dup_ctx) ~= 1 then
    return nil, format_error("x509.store_ctx:init: X509_STORE_CTX_init")
  end

  return setmetatable({
    ctx = ctx,
    verified = false,
  }, mt), nil
end

function _M.istype(l)
  return l and l.ctx and ffi.istype(store_ctx_ptr_ct, l.ctx)
end

function _M:set_default(verify_method)
  if verify_method and C.X509_STORE_CTX_set_default(self.ctx, verify_method) ~= 1 then
    return nil, "x509.store_ctx:set_default: invalid verify_method \"" .. verify_method .. "\""
  end

  return true
end

function _M:set_purpose(purpose)
  if type(purpose) ~= "string" then
    return nil, "x509.store:set_purpose: expect a string at #1"
  end

  local pchar = ffi.new("char[?]", #purpose, purpose)
  local idx = C.X509_PURPOSE_get_by_sname(pchar)
  idx = tonumber(idx)

  if idx == -1 then
    return nil, "invalid purpose \"" .. purpose .. "\""
  end

  local purp = C.X509_PURPOSE_get0(idx)
  local i = C.X509_PURPOSE_get_id(purp)

  if C.X509_STORE_CTX_set_purpose(self.ctx, i) ~= 1 then
    return false, format_error("x509.store_ctx:set_purpose: X509_STORE_set_purpose")
  end

  return true
end

function _M:set_flags(...)
  local flags = 0
  for _, f in ipairs({...}) do
    flags = bor(flags, f)
  end

  C.X509_STORE_CTX_set_flags(self.ctx, flags)

  return true
end

function _M:add_crl(crl)
  if not crl_lib.istype(crl) then
    return nil, "x509.store_ctx:add_crl: expect a x509.crl instance at #3"
  end

  if not self.crl_stack then
    local raw, err = crl_stack_new()
    if raw == nil then
      return nil, err
    end

    self.crl_stack = setmetatable({
      ctx = raw,
    }, crl_stack_mt)
  end

  local dup = C.X509_CRL_dup(crl.ctx)
  if dup == nil then
    return nil, format_error("x509.store_ctx:add_crl: X509_CRL_dup")
  end

  local ok, err = crl_stack_add(self.crl_stack.ctx, dup)
  if not ok then
    C.X509_CRL_free(dup)
    return nil, err
  end

  return true
end

function _M:verify(return_chain)
  if self.crl_stack then
    C.X509_STORE_CTX_set0_crls(self.ctx, self.crl_stack.ctx)

    -- auto-set the flag
    self:set_flags(flag_crl_check)
  end

  local code = C.X509_verify_cert(self.ctx)
  if code == 1 then -- verified
    self.verified = true
    if not return_chain then
      return true, nil
    end

    local chain_ctx = x509_vfy_macro.X509_STORE_CTX_get0_chain(self.ctx)
    return chain_lib.dup(chain_ctx)

  elseif code == 0 then -- unverified
    local vfy_code = C.X509_STORE_CTX_get_error(self.ctx)
    return nil, ffi_str(C.X509_verify_cert_error_string(vfy_code))
  end

  -- error
  return nil, format_error("x509.store_ctx:verify: X509_verify_cert", code)
end

function _M:check_revocation(verified_chain)
  if not OPENSSL_11_OR_LATER then
    return nil, "x509.store_ctx:check_revocation: this API is supported from OpenSSL 1.1.0"
  end

  if verified_chain then
    if not chain_lib.istype(verified_chain) then
      return nil, "x509.store_ctx:check_revocation: expect a x509.chain instance at #1"
    end

    C.X509_STORE_CTX_set0_verified_chain(self.ctx, verified_chain.ctx)
  else
    if not self.verified then
      return nil, "x509.store_ctx:check_revocation: store_ctx isn't verified and verified_chain argument isn't passed"
    end
  end

  if self.crl_stack then
    C.X509_STORE_CTX_set0_crls(self.ctx, self.crl_stack.ctx)
  end

  -- enables CRL checking for the certificate chain leaf certificate.
  -- An error occurs if a suitable CRL cannot be found.
  -- Note: this does not check for certificates in the chain.
  -- We just want to check the revocation of leaf certificate here,
  -- so there's no need to verify the complete chain.
  self:set_flags(flag_partial_chain + flag_crl_check)

  local check_revocation = ffi.cast("int (*)(X509_STORE_CTX *)",
                                    C.X509_STORE_CTX_get_check_revocation(self.ctx))

  local code = check_revocation(self.ctx)
  if code == 1 then -- succeess
    return true, nil
  else
    local vfy_code = C.X509_STORE_CTX_get_error(self.ctx)
    return nil, ffi_str(C.X509_verify_cert_error_string(vfy_code))
  end
end

return _M
