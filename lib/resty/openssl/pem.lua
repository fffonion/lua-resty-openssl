
local ffi = require "ffi"

require "resty.openssl.ossl_typ"

ffi.cdef [[
  typedef int pem_password_cb (char *buf, int size, int rwflag, void *userdata);
  EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x,
    pem_password_cb *cb, void *u);
  EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x,
    pem_password_cb *cb, void *u);
  int PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
    unsigned char *kstr, int klen,
    pem_password_cb *cb, void *u);
  int PEM_write_bio_PUBKEY(BIO *bp, EVP_PKEY *x);

  int PEM_write_bio_X509_REQ(BIO *bp, X509_REQ *x);
  
  X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u);

  // macro in pem.h
  int PEM_write_bio_X509(BIO *bp, X509 *x);
]]
