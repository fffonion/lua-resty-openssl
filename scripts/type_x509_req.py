defines = {
    "output": "../lib/resty/openssl/x509/csr.lua",
    "output_test": "../t/openssl/x509/csr.t",
    "type": "X509_REQ",
    "has_sign_verify": True,
    "sample": "test.csr",
    "fields":
[
{
    "field": "subject_name",
    "type": "x509.name",
    "dup": True,
    "sample_printable": "C=US/CN=test.mars/L=San Francisco/O=Mars Co./OU=Terraforming Department/ST=California",
},

{
    "field": "pubkey",
    "type": "pkey",
    "sample_printable": '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy00jcwmJKMr9+/RwQd0G
CAvw685rqAJD1uKuBotlHTeN95xHI+xZCsRpFblAdhtaDb5Xlc33Fn+cjJ8nF2WS
1HslaZVM51m3sePsDlufBuVCKh+7KqQk64pNejYBasSR+jG7WWEjivR8yclQouJZ
T7WaF6SEET2dxiqXWAWmSbT4J3heP4b3xAAEqsa9kZJX9vQNOB5mqOyvrtqlULNm
WJkKjf8gOtuZePfopEHuyUK2YGVBHCciIfHKeBsIPc2EMajEZYSl0N5/1i4zFxdU
XlLP/qQqafrc2noEz6lv5LXbK2v4T05/5L+klJzcVnCnWnVsaYAUkaEJ5kNyIHpU
AQIDAQAB
-----END PUBLIC KEY-----
''',
},

{
    "field": "version",
    "type": "number",
    "sample_printable": 1,
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