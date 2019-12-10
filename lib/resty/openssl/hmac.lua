local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc
local ffi_new = ffi.new
local ffi_str = ffi.string

require "resty.openssl.ossl_typ"
require "resty.openssl.evp"
local format_error = require("resty.openssl.err").format_error
local OPENSSL_10 = require("resty.openssl.version").OPENSSL_10
local OPENSSL_11 = require("resty.openssl.version").OPENSSL_11

ffi.cdef [[
  /*__owur*/ int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len,
  const EVP_MD *md, ENGINE *impl);
  /*__owur*/ int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data,
                            size_t len);
  /*__owur*/ int HMAC_Final(HMAC_CTX *ctx, unsigned char *md,
                            unsigned int *len);
]]

if OPENSSL_11 then
  ffi.cdef [[
    HMAC_CTX *HMAC_CTX_new(void);
    void HMAC_CTX_free(HMAC_CTX *ctx);
  ]]
elseif OPENSSL_10 then
  ffi.cdef [[
    // # define HMAC_MAX_MD_CBLOCK      128/* largest known is SHA512 */
    struct hmac_ctx_st {
      const EVP_MD *md;
      EVP_MD_CTX md_ctx;
      EVP_MD_CTX i_ctx;
      EVP_MD_CTX o_ctx;
      unsigned int key_length;
      unsigned char key[128];
    };

    void HMAC_CTX_init(HMAC_CTX *ctx);
    void HMAC_CTX_cleanup(HMAC_CTX *ctx);
  ]]
end


local _M = {}
local mt = {__index = _M}

local hmac_ctx_ptr_ct = ffi.typeof('HMAC_CTX*')

function _M.new(key, typ)
  local ctx
  if OPENSSL_11 then
    ctx = C.HMAC_CTX_new()
    ffi_gc(ctx, C.HMAC_CTX_free)
  elseif OPENSSL_10 then
    ctx = ffi.new('HMAC_CTX')
    C.HMAC_CTX_init(ctx)
    ffi_gc(ctx, C.HMAC_CTX_cleanup)
  end
  if ctx == nil then
    return nil, "failed to create HMAC_CTX"
  end

  local dtyp = C.EVP_get_digestbyname(typ or 'sha1')
  if dtyp == nil then
    return nil, string.format("invalid digest type \"%s\"", typ)
  end

  local code = C.HMAC_Init_ex(ctx, key, #key, dtyp, nil)
  if code ~= 1 then
    return nil, format_error("hmac.new")
  end

  return setmetatable({ ctx = ctx }, mt), nil
end

function _M.istype(l)
  return l and l.ctx and ffi.istype(hmac_ctx_ptr_ct, l.ctx)
end

function _M:update(...)
  for _, s in ipairs({...}) do
    if C.HMAC_Update(self.ctx, s, #s) ~= 1 then
      return format_error("hmac:update")
    end
  end
  return nil
end

local uint_ptr = ffi.typeof("unsigned int[1]")

function _M:final(s)
  if s then
    if C.HMAC_Update(self.ctx, s, #s) ~= 1 then
      return nil, format_error("hmac:final")
    end
  end
  -- # define EVP_MAX_MD_SIZE                 64/* longest known is SHA512 */
  local buf = ffi_new('unsigned char[?]', 64)
  local length = uint_ptr()
  if C.HMAC_Final(self.ctx, buf, length) ~= 1 then
    return nil, format_error("digest:final: HMAC_Final")
  end
  return ffi_str(buf, length[0])
end

return _M
