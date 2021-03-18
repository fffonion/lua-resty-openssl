local ffi = require "ffi"

require "resty.openssl.include.ossl_typ"

ffi.cdef [[
  typedef struct ossl_provider_st OSSL_PROVIDER;
  typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;

  typedef struct ossl_param_st {
    const char *key;             /* the name of the parameter */
    unsigned int data_type;      /* declare what kind of content is in buffer */
    void *data;                  /* value being passed in or out */
    size_t data_size;            /* data size */
    size_t return_size;          /* returned content size */
  } OSSL_PARAM;

  void OSSL_PROVIDER_set_default_search_path(OSSL_LIB_CTX *libctx,
                                             const char *path);


  OSSL_PROVIDER *OSSL_PROVIDER_load(OSSL_LIB_CTX *libctx, const char *name);
  OSSL_PROVIDER *OSSL_PROVIDER_try_load(OSSL_LIB_CTX *libctx, const char *name);
  int OSSL_PROVIDER_unload(OSSL_PROVIDER *prov);
  int OSSL_PROVIDER_available(OSSL_LIB_CTX *libctx, const char *name);

  const OSSL_PARAM *OSSL_PROVIDER_gettable_params(OSSL_PROVIDER *prov);
  int OSSL_PROVIDER_get_params(OSSL_PROVIDER *prov, OSSL_PARAM params[]);

  // int OSSL_PROVIDER_add_builtin(OSSL_LIB_CTX *libctx, const char *name,
  //                              ossl_provider_init_fn *init_fn);

  const char *OSSL_PROVIDER_name(const OSSL_PROVIDER *prov);
  int OSSL_PROVIDER_self_test(const OSSL_PROVIDER *prov);

  OSSL_PARAM OSSL_PARAM_construct_int(const char *key, int *buf);
  OSSL_PARAM OSSL_PARAM_construct_BN(const char *key, unsigned char *buf,
                                    size_t bsize);
  OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *key, char *buf,
                                              size_t bsize);
  OSSL_PARAM OSSL_PARAM_construct_octet_string(const char *key, void *buf,
                                                size_t bsize);
  OSSL_PARAM OSSL_PARAM_construct_utf8_ptr(const char *key, char **buf,
                                            size_t bsize);
  OSSL_PARAM OSSL_PARAM_construct_octet_ptr(const char *key, void **buf,
                                            size_t bsize);
  OSSL_PARAM OSSL_PARAM_construct_end(void);
]]

return {
  OSSL_PARAM_INTEGER = 1,
  OSSL_PARAM_UNSIGNED_INTEGER = 2,
  OSSL_PARAM_REAL = 3,
  OSSL_PARAM_UTF8_STRING = 4,
  OSSL_PARAM_OCTET_STRING = 5,
  OSSL_PARAM_UTF8_PTR = 6,
  OSSL_PARAM_OCTET_PTR = 7,
}
