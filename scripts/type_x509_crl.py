defines = {
    "output": "../lib/resty/openssl/x509/crl.lua",
    "output_test": "../t/openssl/x509/crl.t",
    "type": "X509_CRL",
    "has_extension_accessor_by_nid": True,
    "extensions_in_struct":"crl.extensions",
    "has_sign_verify": True,
    "fields":
[
{
    "field": "issuer_name",
    "type": "x509.name",
    "dup": True,
},

{
    "field": "last_update",
    "type": "number",
    "set_converter": '''
  toset = C.ASN1_TIME_set(nil, toset)
  ffi_gc(toset, C.ASN1_STRING_free)
''',
    "get_converter": '''
  got = asn1_lib.asn1_to_unix(got)
''',
},

{
    "field": "next_update",
    "type": "number",
    "set_converter": '''
  toset = C.ASN1_TIME_set(nil, toset)
  ffi_gc(toset, C.ASN1_STRING_free)
''',
    "get_converter": '''
  got = asn1_lib.asn1_to_unix(got)
''',
},

{
    "field": "version",
    "type": "number",
    "set_converter":
'''
  -- Note: this is defined by standards (X.509 et al) to be one less than the certificate version.
  -- So a version 3 certificate will return 2 and a version 1 certificate will return 0.
  toset = toset - 1
''',
    "get_converter":
'''
  got = tonumber(got) + 1
''',
},
]
}