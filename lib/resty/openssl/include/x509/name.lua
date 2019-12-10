local ffi = require "ffi"

require "resty.openssl.include.ossl_typ"
require "resty.openssl.include.asn1"
require "resty.openssl.include.objects"

ffi.cdef [[
  X509_NAME * X509_NAME_new(void);
  void X509_NAME_free(X509_NAME *name);
  X509_NAME *X509_NAME_dup(X509_NAME *xn);
  int X509_NAME_add_entry_by_OBJ(X509_NAME *name, const ASN1_OBJECT *obj, int type,
                               const unsigned char *bytes, int len, int loc,
                               int set);
]]