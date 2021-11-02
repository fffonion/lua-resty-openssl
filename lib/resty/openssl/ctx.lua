local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc

local format_error = require("resty.openssl.err").format_error

ffi.cdef [[
  typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;

  OSSL_LIB_CTX *OSSL_LIB_CTX_new(void);
  int OSSL_LIB_CTX_load_config(OSSL_LIB_CTX *ctx, const char *config_file);
  void OSSL_LIB_CTX_free(OSSL_LIB_CTX *ctx);
]]

local libcrypto_name
local ossl_lib_ctx

local lib_patterns = {
  "%s", "%s.so.3", "%s.so.1.1", "%s.so.1.0"
}

local function load_library()
  for _, pattern in ipairs(lib_patterns) do
    -- true: load to global namespae
    local pok, _ = pcall(ffi.load, string.format(pattern, "crypto"), true)
    if pok then
      libcrypto_name = string.format(pattern, "crypto")
      ffi.load(string.format(pattern, "ssl"), true)

      return true
    end
  end

  return false, "unable to load crypto library"
end

local function new(context_only, conf_file)
  local ctx = C.OSSL_LIB_CTX_new()
  ffi_gc(ctx, C.OSSL_LIB_CTX_free)

  if conf_file and C.OSSL_LIB_CTX_load_config(ctx, conf_file) ~= 1 then
    return false, format_error("ctx.new")
  end

  if context_only then
    ngx.ctx.ossl_lib_ctx = ctx
  else
    ossl_lib_ctx = ctx
  end
end

local function free(context_only)
  if context_only then
    ngx.ctx.ossl_lib_ctx = nil
  else
    ossl_lib_ctx = nil
  end
end

return {
  new = new,
  free = free,
  load_library = load_library,
  get_library_name = function() return libcrypto_name end,
  get_libctx = function() return ngx.ctx.ossl_lib_ctx or ossl_lib_ctx end,
}