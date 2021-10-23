local ffi = require "ffi"

require "resty.openssl.include.ossl_typ"
require "resty.openssl.include.provider"

ffi.cdef [[
  typedef struct evp_mac_st EVP_MAC;
  typedef struct evp_mac_ctx_st EVP_MAC_CTX;

  EVP_MAC_CTX *EVP_MAC_CTX_new(EVP_MAC *mac);
  void EVP_MAC_CTX_free(EVP_MAC_CTX *ctx);

  const OSSL_PROVIDER *EVP_MAC_get0_provider(const EVP_MAC *mac);
  EVP_MAC *EVP_MAC_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
                          const char *properties);

  int EVP_MAC_init(EVP_MAC_CTX *ctx, const unsigned char *key, size_t keylen,
                    const OSSL_PARAM params[]);
  int EVP_MAC_update(EVP_MAC_CTX *ctx, const unsigned char *data, size_t datalen);
  int EVP_MAC_final(EVP_MAC_CTX *ctx,
                    unsigned char *out, size_t *outl, size_t outsize);

  size_t EVP_MAC_CTX_get_mac_size(EVP_MAC_CTX *ctx);
]]