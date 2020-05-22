
local ffi = require "ffi"

require "resty.openssl.include.ossl_typ"

ffi.cdef [[
  typedef struct ossl_provider_st OSSL_PROVIDER;
  typedef struct openssl_ctx_st OPENSSL_CTX;

  void OSSL_PROVIDER_set_default_search_path(OPENSSL_CTX *libctx,
                                             const char *path);
 
  
  // HACK: the OSSL_PROVIDER_load symbol is not exported
  OSSL_PROVIDER *OSSL_PROVIDER_load(OPENSSL_CTX *libctx, const char *name);
  int OSSL_PROVIDER_unload(OSSL_PROVIDER *prov);
  // HACK: the OSSL_PROVIDER_available symbol is not exported
  int OSSL_PROVIDER_available(OPENSSL_CTX *libctx, const char *name);
 
  //const OSSL_PARAM *OSSL_PROVIDER_gettable_params(OSSL_PROVIDER *prov);
  //int OSSL_PROVIDER_get_params(OSSL_PROVIDER *prov, OSSL_PARAM params[]);
 
  // int OSSL_PROVIDER_add_builtin(OPENSSL_CTX *libctx, const char *name,
  //                              ossl_provider_init_fn *init_fn);
 
  const char *OSSL_PROVIDER_name(const OSSL_PROVIDER *prov);
]]
