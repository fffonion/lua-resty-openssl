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

  int X509_NAME_entry_count(const X509_NAME *name);
  X509_NAME_ENTRY *X509_NAME_get_entry(X509_NAME *name, int loc);
  ASN1_OBJECT *X509_NAME_ENTRY_get_object(const X509_NAME_ENTRY *ne);
  ASN1_STRING * X509_NAME_ENTRY_get_data(const X509_NAME_ENTRY *ne);
  int X509_NAME_get_index_by_OBJ(X509_NAME *name, const ASN1_OBJECT *obj,
                               int lastpos);
]]