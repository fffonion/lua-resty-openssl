local ffi = require "ffi"

require "resty.openssl.ossl_typ"

ffi.cdef [[
  ASN1_OBJECT *OBJ_txt2obj(const char *s, int no_name);
  const char *OBJ_nid2sn(int n);
  int OBJ_ln2nid(const char *s);
]]
