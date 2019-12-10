local ffi = require "ffi"

require "resty.openssl.include.ossl_typ"
require "resty.openssl.include.bio"
require "resty.openssl.include.pem"

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

  int X509_set_pubkey(X509 *x, EVP_PKEY *pkey);
  int X509_set_version(X509 *x, long version);
  int X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial);
  int X509_set_subject_name(X509 *x, X509_NAME *name);
  int X509_set_issuer_name(X509 *x, X509_NAME *name);

]]

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
end