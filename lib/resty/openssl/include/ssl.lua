local ffi = require "ffi"
local C = ffi.C

require "resty.openssl.include.ossl_typ"
require "resty.openssl.include.stack"

ffi.cdef [[
  // SSL_METHOD
  typedef struct ssl_method_st SSL_METHOD;

  // SSL_CIPHER
  typedef struct ssl_cipher_st SSL_CIPHER;
  const char *SSL_CIPHER_get_name(const SSL_CIPHER *cipher);
  SSL_CIPHER *SSL_get_current_cipher(const SSL *ssl);

  SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);
  void SSL_CTX_free(SSL_CTX *a);


  typedef int (*SSL_CTX_alpn_select_cb_func)(SSL *ssl,
                const unsigned char **out,
                unsigned char *outlen,
                const unsigned char *in,
                unsigned int inlen,
                void *arg);
  void SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx,
                                  SSL_CTX_alpn_select_cb_func cb,
                                  void *arg);

  int SSL_select_next_proto(unsigned char **out, unsigned char *outlen,
                            const unsigned char *server,
                            unsigned int server_len,
                            const unsigned char *client,
                            unsigned int client_len);

  SSL *SSL_new(SSL_CTX *ctx);
  void SSL_free(SSL *ssl);

  /*STACK_OF(SSL_CIPHER)*/ OPENSSL_STACK *SSL_get_ciphers(const SSL *ssl);
  /*STACK_OF(SSL_CIPHER)*/ OPENSSL_STACK *SSL_CTX_get_ciphers(const SSL_CTX *ctx);

  OPENSSL_STACK *SSL_get_peer_cert_chain(const SSL *ssl);
  X509 *SSL_get_peer_certificate(const SSL *ssl);
]]
