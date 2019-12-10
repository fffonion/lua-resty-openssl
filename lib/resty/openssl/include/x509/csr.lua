local ffi = require "ffi"

require "resty.openssl.include.ossl_typ"
require "resty.openssl.include.evp"
require "resty.openssl.include.objects"
require "resty.openssl.include.x509"
require "resty.openssl.include.stack"

ffi.cdef [[
  X509_REQ *X509_REQ_new(void);
  void X509_REQ_free(X509_REQ *req);

  int X509_REQ_set_subject_name(X509_REQ *req, X509_NAME *name);
  int X509_REQ_set_pubkey(X509_REQ *x, EVP_PKEY *pkey);
  int X509_add1_ext_i2d(X509 *x, int nid, void *value, int crit,
                      unsigned long flags);
  int X509_REQ_get_attr_count(const X509_REQ *req);

  int X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md);

  int i2d_X509_REQ_bio(BIO *bp, X509_REQ *req);

  // STACK_OF(X509_EXTENSION)
  OPENSSL_STACK *X509_REQ_get_extensions(X509_REQ *req);
  // STACK_OF(X509_EXTENSION)
  int X509_REQ_add_extensions(X509_REQ *req, OPENSSL_STACK *exts);

]]