#!/usr/bin/env python3

import re
import x509_autogen_extension_struct as xaes

output = "../lib/resty/openssl/x509/init.lua"
ANCHOR_START = '-- START AUTO GENERATED CODE'
ANCHOR_END = '-- END AUTO GENERATED CODE'

LUA_TYPES = ('number', 'string', 'table')

# Auto generate X509 getter and setters

number_to_asn1 = '''
  got = C.ASN1_TIME_set(nil, got)
  ffi_gc(got, C.ASN1_STRING_free)'''

attributes = [{
    # name used in openssl
    "field": "serial_number",
    # attribute type
    "type": "resty.openssl.bn",
    # the optional type converter
    "set":
'''
  toset = C.BN_to_ASN1_INTEGER(toset, nil)
  if toset == nil then
    return false, format_error("x509:set: BN_to_ASN1_INTEGER")
  end
  -- "A copy of the serial number is used internally
  -- so serial should be freed up after use.""
  ffi_gc(toset, C.ASN1_INTEGER_free)
''',
    "get":
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
    "set":
'''
  toset = C.ASN1_TIME_set(nil, toset)
  ffi_gc(toset, C.ASN1_STRING_free)
''',
    "get":
'''
  got = asn1_lib.asn1_to_unix(got)
''',
},

{
    "field": "not_after",
    "type": "number",
    "set":
'''
  toset = C.ASN1_TIME_set(nil, toset)
  ffi_gc(toset, C.ASN1_STRING_free)
''',
    "get":
'''
  got = asn1_lib.asn1_to_unix(got)
''',
},

{
    "field": "pubkey",
    "type": "resty.openssl.pkey",
},

{
    "field": "subject_name",
    "type": "resty.openssl.x509.name",
    "dup": True,
},

{
    "field": "issuer_name",
    "type": "resty.openssl.x509.name",
    "dup": True,
},

{
    "field": "version",
    "type": "number",
    "set":
'''
  -- Note: this is defined by standards (X.509 et al) to be one less than the certificate version.
  -- So a version 3 certificate will return 2 and a version 1 certificate will return 0.
  toset = toset - 1
''',
    "get":
'''
  got = tonumber(got) + 1
''',
},

################## extensions ######################

{
    "field": "subject_alt_name",
    "type": "resty.openssl.x509.altname",
    "dup": True,
    "extension": "subjectAltName",
    "get": '''
  -- Note: here we only free the stack itself not elements
  -- since there seems no way to increase ref count for a GENERAL_NAME
  -- we left the elements referenced by the new-dup'ed stack
  ffi_gc(got, stack_lib.gc_of("GENERAL_NAME"))
  got = ffi_cast("GENERAL_NAMES*", got)''',
},

{
    "field": "issuer_alt_name",
    "type": "resty.openssl.x509.altname",
    "dup": True,
    "extension": "issuerAltName",
    "get": '''
  -- Note: here we only free the stack itself not elements
  -- since there seems no way to increase ref count for a GENERAL_NAME
  -- we left the elements referenced by the new-dup'ed stack
  ffi_gc(got, stack_lib.gc_of("GENERAL_NAME"))
  got = ffi_cast("GENERAL_NAMES*", got)''',
},

{
    "field": "basic_constraints",
    "type": "table",
    "extension": "basicConstraints",
    "set": xaes.table_to_c_struct("BASIC_CONSTRAINTS"),
    "get": xaes.c_struct_to_table("BASIC_CONSTRAINTS"),
},

{
    "field": "info_access",
    "type": "resty.openssl.x509.extension.info_access",
    "dup": True,
    "extension": "authorityInfoAccess",
    "get": '''
  -- Note: here we only free the stack itself not elements
  -- since there seems no way to increase ref count for a ACCESS_DESCRIPTION
  -- we left the elements referenced by the new-dup'ed stack
  ffi_gc(got, stack_lib.gc_of("ACCESS_DESCRIPTION"))
  got = ffi_cast("AUTHORITY_INFO_ACCESS*", got)''',
},

{
    "field": "crl_distribution_points",
    "type": "resty.openssl.x509.extension.dist_points",
    "dup": True,
    "extension": "crlDistributionPoints",
    "get": '''
  -- Note: here we only free the stack itself not elements
  -- since there seems no way to increase ref count for a DIST_POINT
  -- we left the elements referenced by the new-dup'ed stack
  ffi_gc(got, stack_lib.gc_of("DIST_POINT"))
  got = ffi_cast("OPENSSL_STACK*", got)''',
},
]

attr_setter_tc_common = '''
  if type(toset) ~= "{type}" then
    return false, "expect a {type} at #1"
  end'''

attr_setter_tc_lib = '''
  local lib = require("{type}")
  if lib.istype and not lib.istype(toset) then
    return false, "expect a {type} instance at #1"
  end
  toset = toset.ctx'''

attr_setter_cv = '''
  toset, err = attribute.from(toset)
  if err then
    return false, err
  end'''

attr_setter = '''
-- AUTO GENERATED
function _M:set_{field}(toset)
{typecheck}{converter}
  if accessors.set_{field}(self.ctx, toset) == 0 then
    return false, format_error("x509:set_{field}")
  end

  return true
end
'''

attr_getter_return_raw = '''
  return got'''

attr_getter_return_dup = '''
  local lib = require("{type}")
  -- the internal ptr is returned, ie we need to copy it
  return lib.dup(got)'''

attr_getter_return_new = '''
  local lib = require("{type}")
  -- returned a copied instance directly
  return lib.new(got)'''


attr_getter = '''
-- AUTO GENERATED
function _M:get_{field}()
  local got = accessors.get_{field}(self.ctx)
  if got == nil then
    return nil, format_error("x509:get_{field}")
  end
{converter}{returner}
end
'''

extension_setter = '''
local NID_{field} = C.OBJ_sn2nid("{extension}")
assert(NID_{field} ~= 0)

-- AUTO GENERATED: EXTENSIONS
function _M:set_{field}(toset)
{typecheck}{converter}
  -- x509v3.h: # define X509V3_ADD_REPLACE              2L
  if C.X509_add1_ext_i2d(self.ctx, NID_{field}, toset, 0, 0x2) ~= 1 then
    return false, format_error("x509:set_{field}")
  end

  return true
end

-- AUTO GENERATED: EXTENSIONS
function _M:set_{field}_critical(crit)
  return _M.set_critical(self, NID_{field}, crit)
end
'''

extension_getter = '''
-- AUTO GENERATED: EXTENSIONS
function _M:get_{field}({extra_args})
  -- X509_get_ext_d2i returns internal pointer, always dup
  local got = C.X509_get_ext_d2i(self.ctx, NID_{field}, nil, nil)
  if got == nil then
    return nil, format_error("x509:get_{field}")
  end
{converter}{returner}
end

-- AUTO GENERATED: EXTENSIONS
function _M:get_{field}_critical()
  return _M.get_critical(self, NID_{field})
end
'''

ct = None
with open(output, "r") as f:
    ct = f.read()

blocks = [
]
for attr in attributes:
    if attr['type'] in LUA_TYPES:
        typecheck = attr_setter_tc_common
    else:
        typecheck = attr_setter_tc_lib
    
    typecheck = typecheck.format(
        type = attr['type'],
    )

    if 'extension' in attr:
        setter = extension_setter
    else:
        setter = attr_setter
    
    blocks.append(setter.format(
        field = attr['field'],
        type = attr['type'],
        typecheck = typecheck,
        converter = 'set' in attr and attr['set'] or '',
        extension = 'extension' in attr and attr['extension'] or '',
    ))

    converter = ''
    if 'get' in attr:
        converter = attr['get']

    returner = ''
    if attr['type'] not in LUA_TYPES:
        if 'dup' in attr and attr['dup']:
            returner = attr_getter_return_dup.format(
                type = attr['type'],
            )
        else:
            returner = attr_getter_return_new.format(
                type = attr['type'],
            )
    else:
        returner = attr_getter_return_raw

    if 'extension' in attr:
        getter = extension_getter
    else:
        getter = attr_getter
    blocks.append(getter.format(
        field = attr['field'],
        type = attr['type'],
        converter = converter,
        returner = returner,
        extension = 'extension' in attr and attr['extension'] or '',
        extra_args = 'extension' in attr and attr['extension'] and attr['type'] == 'table'
                    and "name" or "",
    ))


# Auto generate X509 extension getter and setters

ct = re.sub(
    ANCHOR_START + '.+' + ANCHOR_END,
    ANCHOR_START + '\n' + ''.join(blocks) + '\n' + ANCHOR_END,
    ct,
    flags = re.DOTALL,
)

open(output, 'w').write(ct)

print("codegen wrote %d blocks (%dl)" % (len(blocks), len(ct.split('\n'))))