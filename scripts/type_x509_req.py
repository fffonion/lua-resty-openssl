defines = {
    "output": "../lib/resty/openssl/x509/csr.lua",
    "output_test": "../t/openssl/x509/csr.t",
    "type": "X509_REQ",
    "has_sign_verify": True,
    "fields":
[
{
    "field": "subject_name",
    "type": "x509.name",
    "dup": True,
},

{
    "field": "pubkey",
    "type": "pkey",
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