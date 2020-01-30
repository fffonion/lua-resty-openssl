import extension_struct as es

defines = {
    "output": "../lib/resty/openssl/x509/init.lua",
    "output_test": "../t/openssl/x509.t",
    "type": "X509",
    "has_extension_accessor_by_nid": True,
    "extensions_in_struct":"cert_info.extensions",
    "has_sign_verify": True,
    "fields":
[
{
    # name used in openssl
    "field": "serial_number",
    # attribute type
    "type": "bn",
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
    "dup": True,
},

{
    "field": "not_before",
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
    "field": "not_after",
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
    "field": "pubkey",
    "type": "pkey",
},

{
    "field": "subject_name",
    "type": "x509.name",
    "dup": True,
},

{
    "field": "issuer_name",
    "type": "x509.name",
    "dup": True,
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

################## extensions ######################

{
    "field": "subject_alt_name",
    "type": "x509.altname",
    "dup": True,
    "extension": "subjectAltName",
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