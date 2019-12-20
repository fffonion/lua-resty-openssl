local ffi = require "ffi"

require "resty.openssl.include.ossl_typ"

ffi.cdef [[
  int OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name);
  ASN1_OBJECT *OBJ_txt2obj(const char *s, int no_name);
  const char *OBJ_nid2sn(int n);
  int OBJ_ln2nid(const char *s);
  const char *OBJ_nid2ln(int n);
  const char *OBJ_nid2sn(int n);
  int OBJ_obj2nid(const ASN1_OBJECT *o);
]]
