import extension_struct as es

defines = {
    "output": "../lib/resty/openssl/x509/init.lua",
    "output_test": "../t/openssl/x509.t",
    "type": "X509",
    "has_extension_accessor_by_nid": True,
    "extensions_in_struct":"cert_info.extensions",
    "has_sign_verify": True,
    "sample": "Github.pem",
    "fields":
[
{
    # name used in openssl
    "field": "serial_number",
    # attribute type
    "type": "bn",
    # this struct should be copied during return
    "dup": True,
    # the value of sample used in tests
    "sample_printable": "0A0630427F5BBCED6957396593B6451F",
    # the optional type converter
    "set_converter":
'''
  toset = C.BN_to_ASN1_INTEGER(toset, nil)
  if toset == nil then
    return false, format_error("x509:set: BN_to_ASN1_INTEGER")
  end
  -- "A copy of the serial number is used internally
  -- so serial should be freed up after use.""
  ffi_gc(toset, C.ASN1_INTEGER_free)
''',
    "get_converter":
'''
  -- returns a new BIGNUM instance
  got = C.ASN1_INTEGER_to_BN(got, nil)
  if got == nil then
    return false, format_error("x509:set: BN_to_ASN1_INTEGER")
  end
  -- bn will be duplicated thus this ctx should be freed up
  ffi_gc(got, C.BN_free)
''',
},

{
    "field": "not_before",
    "type": "number",
    "sample_printable": 1525737600,
    "set_converter": '''
  toset = C.ASN1_TIME_set(nil, toset)
  ffi_gc(toset, C.ASN1_STRING_free)
''',
    "get_converter": '''
  got = asn1_lib.asn1_to_unix(got)
''',
},

{
    "field": "not_after",
    "type": "number",
    "sample_printable": 1591185600,
    "set_converter": '''
  toset = C.ASN1_TIME_set(nil, toset)
  ffi_gc(toset, C.ASN1_STRING_free)
''',
    "get_converter": '''
  got = asn1_lib.asn1_to_unix(got)
''',
},

{
    "field": "pubkey",
    "type": "pkey",
    "sample_printable": '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxjyq8jyXDDrBTyitcnB9
0865tWBzpHSbindG/XqYQkzFMBlXmqkzC+FdTRBYyneZw5Pz+XWQvL+74JW6LsWN
c2EF0xCEqLOJuC9zjPAqbr7uroNLghGxYf13YdqbG5oj/4x+ogEG3dF/U5YIwVr6
58DKyESMV6eoYV9mDVfTuJastkqcwero+5ZAKfYVMLUEsMwFtoTDJFmVf6JlkOWw
sxp1WcQ/MRQK1cyqOoUFUgYylgdh3yeCDPeF22Ax8AlQxbcaI+GwfQL1FB7Jy+h+
KjME9lE/UpgV6Qt2R1xNSmvFCBWu+NFX6epwFP/JRbkMfLz0beYFUvmMgLtwVpEP
SwIDAQAB
-----END PUBLIC KEY-----
''',
},

{
    "field": "subject_name",
    "type": "x509.name",
    "dup": True,
    "sample_printable": "C=US/CN=github.com/L=San Francisco/O=GitHub, Inc./ST=California/businessCategory=Private Organization/jurisdictionC=US/jurisdictionST=Delaware/serialNumber=5157550",
},

{
    "field": "issuer_name",
    "type": "x509.name",
    "dup": True,
    "sample_printable": "C=US/CN=DigiCert SHA2 Extended Validation Server CA/O=DigiCert Inc/OU=www.digicert.com",
},

{
    "field": "version",
    "type": "number",
    "sample_printable": 3,
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

################## extensions ######################

{
    "field": "subject_alt_name",
    "type": "x509.altname",
    "dup": True,
    "extension": "subjectAltName",
    "sample_printable": 'DNS=www.github.com',
    "get_converter": '''
  -- Note: here we only free the stack itself not elements
  -- since there seems no way to increase ref count for a GENERAL_NAME
  -- we left the elements referenced by the new-dup'ed stack
  local got_ref = got
  ffi_gc(got_ref, stack_lib.gc_of("GENERAL_NAME"))
  got = ffi_cast("GENERAL_NAMES*", got_ref)''',
},

{
    "field": "issuer_alt_name",
    "type": "x509.altname",
    "dup": True,
    "extension": "issuerAltName",
    "skip_tests": True, # need to find a good sample
    "get_converter": '''
  -- Note: here we only free the stack itself not elements
  -- since there seems no way to increase ref count for a GENERAL_NAME
  -- we left the elements referenced by the new-dup'ed stack
  local got_ref = got
  ffi_gc(got_ref, stack_lib.gc_of("GENERAL_NAME"))
  got = ffi_cast("GENERAL_NAMES*", got_ref)''',
},

{
    "field": "basic_constraints",
    "type": "table",
    "extension": "basicConstraints",
    "set_converter": es.table_to_c_struct("BASIC_CONSTRAINTS"),
    "get_converter": es.c_struct_to_table("BASIC_CONSTRAINTS"),
},

{
    "field": "info_access",
    "type": "x509.extension.info_access",
    "dup": True,
    "extension": "authorityInfoAccess",
    "get_converter": '''
  -- Note: here we only free the stack itself not elements
  -- since there seems no way to increase ref count for a ACCESS_DESCRIPTION
  -- we left the elements referenced by the new-dup'ed stack
  local got_ref = got
  ffi_gc(got_ref, stack_lib.gc_of("ACCESS_DESCRIPTION"))
  got = ffi_cast("AUTHORITY_INFO_ACCESS*", got_ref)''',
},

{
    "field": "crl_distribution_points",
    "type": "x509.extension.dist_points",
    "dup": True,
    "extension": "crlDistributionPoints",
    "get_converter": '''
  -- Note: here we only free the stack itself not elements
  -- since there seems no way to increase ref count for a DIST_POINT
  -- we left the elements referenced by the new-dup'ed stack
  local got_ref = got
  ffi_gc(got_ref, stack_lib.gc_of("DIST_POINT"))
  got = ffi_cast("OPENSSL_STACK*", got_ref)''',
},
]
}