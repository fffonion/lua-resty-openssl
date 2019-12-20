# lua-resty-openssl

FFI-based OpenSSL binding for LuaJIT, supporting OpenSSL 1.1 and 1.0.2 series

![Build Status](https://travis-ci.com/fffonion/lua-resty-openssl.svg?branch=master)


Table of Contents
=================

- [Description](#description)
- [Status](#status)
- [Synopsis](#synopsis)
  * [resty.openssl](#restyopenssl)
    + [openssl.luaossl_compact](#opensslluaossl-compact)
  * [resty.openssl.version](#restyopensslversion)
    + [version_num](#version_num)
    + [version_text](#version_text)
    + [version.version](#versionversion)
    + [OPENSSL_11](#openssl_11)
    + [OPENSSL_10](#openssl_10)
  * [resty.openssl.pkey](#restyopensslpkey)
    + [pkey.new](#pkeynew)
    + [pkey.istype](#pkeyistype)
    + [pkey:get_parameters](#pkeyget_parameters)
    + [pkey:sign](#pkeysign)
    + [pkey:verify](#pkeyverify)
    + [pkey:to_PEM](#pkeyto_pem)
  * [resty.openssl.bn](#restyopensslbn)
    + [bn.new](#bnnew)
    + [bn.dup](#bndup)
    + [bn.istype](#bnistype)
    + [bn.from_binary](#bnfrom_binary)
    + [bn:to_binary](#bnto_binary)
    + [bn:to_hex](#bnto_hex)
  * [resty.openssl.cipher](#restyopensslcipher)
    + [cipher.new](#ciphernew)
    + [cipher.istype](#cipheristype)
    + [cipher:encrypt](#cipherencrypt)
    + [cipher:decrypt](#cipherdecrypt)
    + [cipher:init](#cipherinit)
    + [cipher:update](#cipherupdate)
    + [cipher:final](#cipherfinal)
  * [resty.openssl.digest](#restyopenssldigest)
    + [digest.new](#digestnew)
    + [digest.istype](#digestistype)
    + [digest:update](#digestupdate)
    + [digest:final](#digestfinal)
  * [resty.openssl.hmac](#restyopensslhmac)
    + [hmac.new](#hmacnew)
    + [hmac.istype](#hmacistype)
    + [hmac:update](#hmacupdate)
    + [hmac:final](#hmac-final)
  * [resty.openssl.rand](#restyopensslrand)
    + [rand.bytes](#randbytes)
  * [resty.openssl.x509](#restyopensslx509)
    + [x509.new](#x509new)
    + [x509.dup](#x509dup)
    + [x509.istype](#x509istype)
    + [x509:add_extension](#x509add_extension)
    + [x509:digest](#x509digest)
    + [x509:pubkey_digest](#x509pubkey_digest)
    + [x509:get_*, x509:set_*](#x509get_-x509set_)
    + [x509:get_lifetime](#x509get_lifetime)
    + [x509:set_lifetime](#x509set_lifetime)
    + [x509:set_basic_constraints](#x509set_basic_constraints)
    + [x509:set_basic_constraints_critical](#x509set_basic_constraints_critical)
    + [x509:sign](#x509sign)
    + [x509:to_PEM](#x509to_pem)
  * [resty.openssl.x509.name](#restyopensslx509name)
    + [name.new](#namenew)
    + [name.dup](#namedup)
    + [name.istype](#nameistype)
    + [name:add](#nameadd)
  * [resty.openssl.x509.altname](#restyopensslx509altname)
    + [altname.new](#altnamenew)
    + [altname.istype](#altnameistype)
    + [altname:add](#altnameadd)
  * [resty.openssl.x509.csr](#restyopensslx509csr)
    + [csr.new](#csrnew)
    + [csr.istype](#csristype)
    + [csr:set_subject_name](#csrset_subject_name)
    + [csr:set_subject_alt](#csrset_subject_alt)
    + [csr:set_pubkey](#csrset_pubkey)
    + [csr:tostring](#csrtostring)
    + [csr:to_PEM](#csrto_pem)
  * [resty.openssl.x509.extension](#restyopensslx509extension)
    + [extension.new](#extensionnew)
    + [extension.istype](#extensionistype)
  * [resty.openssl.x509.chain](#restyopensslx509chain)
    + [chain.new](#chainnew)
    + [chain:add](#chainadd)
    + [chain:__metamethods](#chain__metamethods)
- [Compatibility](#compatibility)
- [TODO](#todo)
- [Copyright and License](#copyright-and-license)
- [See Also](#see-also)



Description
===========

`lua-resty-openssl` is a FFI-based OpenSSL binding library, currently
supports OpenSSL `1.1.1`, `1.1.0` and `1.0.2` series.

The API is kept as same [luaossl](https://github.com/wahern/luaossl) while only a small sets
of OpenSSL APIs are currently implemented.


[Back to TOC](#table-of-contents)

Status
========

Production.

Synopsis
========

This library is greatly inspired by [luaossl](https://github.com/wahern/luaossl), while uses the
naming conversion closer to original OpenSSL API.
For example, a function called `X509_set_pubkey` in OpenSSL C API will expect to exist
as `resty.openssl.x509:set_pubkey`.
*CamelCase*s are replaced to *underscore_case*s, for exmaple `X509_set_serialNumber` becomes
`resty.openssl.x509:set_serial_number`. Another difference than `luaossl` is that errors are never thrown
using `error()` but instead return as last parameter.

Each Lua table returned by `new()` contains a cdata object `ctx`. User are not supposed to manully setting
`ffi.gc` or calling corresponding destructor of the `ctx` struct (like `*_free` functions).


## resty.openssl

This meta module provides a version sanity check and returns all exported modules to a local table.

```lua
local _M = {
  _VERSION = '0.1.0',
  version = require("resty.openssl.version"),
  pkey = require("resty.openssl.pkey"),
  digest = require("resty.openssl.digest"),
  hmac = require("resty.openssl.hmac"),
  bn = require("resty.openssl.bn"),
  x509 = require("resty.openssl.x509"),
  name = require("resty.openssl.x509.name"),
  altname = require("resty.openssl.x509.altname"),
  csr = require("resty.openssl.x509.csr"),
  extension = require("resty.openssl.x509.extension"),
}
```

### openssl.luaossl_compact

**syntax**: *openssl.luaossl_compact()*

Provides `luaossl` flavored API which uses *camelCase* naming; user can expect drop in replacement.

For example, `pkey:get_parameters` is mapped to `pkey:getParameters`.

## resty.openssl.version

A module to provide version info.

### version_num

The OpenSSL version number.

### version_text

The OpenSSL version text.

### version.version

**syntax**: *text = version.version(types)*

Returns various OpenSSL information. Available values for `types` are:

    VERSION
    CFLAGS
    BUILT_ON
    PLATFORM
    DIR
    ENGINES_DIR
    VERSION_STRING
    FULL_VERSION_STRING
    MODULES_DIR
    CPU_INFO

For OpenSSL prior to 1.1.x, only `VERSION`, `CFLAGS`, `BUILT_ON`, `PLATFORM`
and `DIR` are supported.

```lua
local version = require("resty.openssl.version")
ngx.say(string.format("%x", version.version_num))
-- outputs "101000bf"
ngx.say(version.version_text)
-- outputs "OpenSSL 1.1.0k  28 May 2019"
ngx.say(version.version(version.PLATFORM))
-- outputs "darwin64-x86_64-cc"
```

### OPENSSL_11

A boolean indicates whether the linked OpenSSL is 1.1 series.

### OPENSSL_10

A boolean indicates whether the linked OpenSSL is 1.0 series.

## resty.openssl.pkey

Module to interact with private keys and public keys (EVP_PKEY).

### pkey.new

**syntax**: *pk, err = pkey.new(config)*

**syntax**: *pk, err = pkey.new(string, format?)*

**syntax**: *pk, err = pkey.new()*

Creates a new pkey instance. The first argument can be:

1. A table which defaults to:

```lua
{
    type = 'RSA',
    bits = 2048,
    exp = 65537
}
```

to create EC private key:

```lua
{
    type = 'EC',
    curve = 'primve196v1',
}
```

2. A string of private or public key in PEM or DER format; optionally tells the library
to explictly decode the key using `format`, which can be a choice of `PER`, `DER` or `*`
for auto detect.
3. `nil` to create a 2048 bits RSA key.
4. A `EVP_PKEY*` cdata pointer, to return a wrapped `pkey` instance. Normally user won't use this
approach. User shouldn't free the pointer on their own, since the pointer is not copied.

### pkey.istype

**syntax**: *ok = pkey.istype(table)*

Returns `true` if table is an instance of `pkey`. Returns `false` otherwise.

### pkey:get_parameters

**syntax**: *parameters, err = pk:get_parameters()*

Returns a table containing the `parameters` of pkey instance. Currently only `n`, `e` and `d`
parameter of RSA key is supported. Each value of the returned table is a
[resty.openssl.bn](#restyopensslbn) instance.

```lua
local pk, err = require("resty.openssl").pkey.new()
local parameters, err = pk:get_parameters()
local e = parameters.e
ngx.say(ngx.encode_base64(e:to_binary()))
-- outputs 'AQAB' (65537) by default
```

### pkey:sign

**syntax**: *signature, err = pk:sign(digest)*

Sign a [digest](#restyopenssldigest) using the private key defined in `pkey`
instance. The `digest` parameter must be a [resty.openssl.digest](#restyopenssldigest) 
instance. Returns the signed raw binary and error if any.

```lua
local pk, err = require("resty.openssl").pkey.new()
local digest, err = require("resty.openssl").digest.new("SHA256")
digest:update("dog")
local signature, err = pk:sign(digest)
ngx.say(ngx.encode_base64(signature))
```

### pkey:verify

**syntax**: *ok, err = pk:verify(signature, digest)*

Verify a signture (which can be generated by [pkey:sign](#pkey-sign)). The second
argument must be a [resty.openssl.digest](#restyopenssldigest) instance that uses
the same digest algorithm as used in `sign`. `ok` returns `true` if verficiation is
successful and `false` otherwise. Note when verfication failed `err` will not be set.

### pkey:to_PEM

**syntax**: *pem, err = pk:to_PEM(private_or_public?)*

Outputs private key or public key of `pkey` instance in PEM-formatted text.
The first argument must be a choice of `public`, `PublicKey`, `private`, `PrivateKey` or nil.
By default, it returns the public key.


## resty.openssl.bn

Module to expose BIGNUM structure.

### bn.new

**syntax**: *b, err = bn.new(number?)*

Creates a `bn` instance. The first argument can be a Lua number or `nil` to
creates an empty instance.

### bn.dup

**syntax**: *b, err = bn.new(bn_ptr_cdata)*

Creates a `bn` instance from `BIGNUM*` cdata pointer.

### bn.istype

**syntax**: *ok = bn.istype(table)*

Returns `true` if table is an instance of `bn`. Returns `false` otherwise.

### bn.from_binary

Creates a `bn` instance from binary string.

```lua
local b, err = require("resty.openssl.bn").from_binary(ngx.decode_base64("WyU="))
local bin, err = b:to_binary()
ngx.say(ngx.encode_base64(bin))
-- outputs "WyU="
```

### bn:to_binary

**syntax**: *bin, err = bn:to_binary()*

Export the BIGNUM value in binary string.


### bn:to_hex

**syntax**: *hex, err = bn:to_hex()*

Export the BIGNUM value in hex encoded string.

```lua
local b, err = require("resty.openssl.bn").new(23333)
local bin, err = b:to_binary()
ngx.say(ngx.encode_base64(bin))
-- outputs "WyU="
local hex, err = b:to_hex()
ngx.say(hex)
-- outputs "5B25"
```

## resty.openssl.cipher

Module to interact with symmetric cryptography (EVP_CIPHER).

### cipher.new

**syntax**: *d, err = cipher.new(cipher_name)*

Creates a cipher instance. `cipher_name` is a case-insensitive string of cipher algorithm name.
To view a list of cipher algorithms implemented, use `openssl list -cipher-algorithms`.

### cipher.istype

**syntax**: *ok = cipher.istype(table)*

Returns `true` if table is an instance of `cipher`. Returns `false` otherwise.

### cipher:encrypt

**syntax**: *s, err = cipher:encrypt(key, iv?, s, no_padding?)*

Encrypt the text `s` with key `key` and IV `iv`. Returns the encrypted text in raw binary string
and error if any.
Optionally accepts a boolean `no_padding` which tells the cipher to enable or disable padding and default
to `false` (enable padding). If `no_padding` is `true`, the length of `s` must then be a multiple of the
block size or an error will occur.

This function is a shorthand of `cipher:init` plus `cipher:final`.

### cipher:decrypt

**syntax**: *s, err = cipher:decrypt(key, iv?, s, no_padding?)*

Decrypt the text `s` with key `key` and IV `iv`. Returns the decrypted text in raw binary string
and error if any.
Optionally accepts a boolean `no_padding` which tells the cipher to enable or disable padding and default
to `false` (enable padding). If `no_padding` is `true`, the length of `s` must then be a multiple of the
block size or an error will occur; also, padding in the decrypted text will not be removed.

This function is a shorthand of `cipher:init` plus `cipher:final`.

### cipher:init

**syntax**: *ok, err = cipher:init(key, iv?, opts?)*

Initialize the cipher with key `key` and IV `iv`. The optional third argument is a table consists of:

```lua
{
    is_encrypt = false,
    no_padding = false,
}
```

Calling function is needed before `cipher:update` and `cipher:final` but not
`cipher:encrypt` or `cipher:decrypt`.

### cipher:update

**syntax**: *s, err = cipher:update(partial, ...)*

Updates the cipher with one or more strings. If the cipher has larger than block size of data to flush,
the function will return a non-empty string as first argument. This function can be used in a streaming
fashion to encrypt or decrypt continous data stream.

### cipher:final

**syntax**: *s, err = cipher:final(partial?)*

Returns the encrypted or decrypted text in raw binary string, optionally accept one string to encrypt or decrypt.

```lua
-- encryption
local c, err = require("resty.openssl.cipher").new("aes256")
c:init(string.rep("0", 32), string.rep("0", 16), {
    is_encrypt = true,
})
c:update("🦢")
local cipher, err = c:final()
ngx.say(ngx.encode_base64(cipher))
-- outputs "vGJRHufPYrbbnYYC0+BnwQ=="
-- OR:
local c, err = require("resty.openssl.cipher").new("aes256")
local cipher, err = c:encrypt(string.rep("0", 32), string.rep("0", 16), "🦢")
ngx.say(ngx.encode_base64(cipher))
-- outputs "vGJRHufPYrbbnYYC0+BnwQ=="

-- decryption
local encrypted = ngx.decode_base64("vGJRHufPYrbbnYYC0+BnwQ==")
local c, err = require("resty.openssl.cipher").new("aes256")
c:init(string.rep("0", 32), string.rep("0", 16), {
    is_encrypt = false,
})
c:update(encrypted)
local cipher, err = c:final()
ngx.say(cipher)
-- outputs "🦢"
-- OR:
local c, err = require("resty.openssl.cipher").new("aes256")
local cipher, err = c:decrypt(string.rep("0", 32), string.rep("0", 16), encrypted)
ngx.say(cipher)
-- outputs "🦢"
```

## resty.openssl.digest

Module to interact with message digest (EVP_MD_CTX).

### digest.new

**syntax**: *d, err = digest.new(digest_name?)*

Creates a digest instance. `digest_name` is a case-insensitive string of digest algorithm name.
To view a list of digest algorithms implemented, use `openssl list -digest-algorithms`.

If `digest_name` is omitted, it's default to `sha1`.

### digest.istype

**syntax**: *ok = digest.istype(table)*

Returns `true` if table is an instance of `digest`. Returns `false` otherwise.

### digest:update

**syntax**: *ok, err = digest:update(partial, ...)*

Updates the digest with one or more strings.

### digest:final

**syntax**: *str, err = digest:final(partial?)*

Returns the digest in raw binary string, optionally accept one string to digest.

```lua
local d, err = require("resty.openssl.digest").new("sha256")
d:update("🦢")
local digest, err = d:final()
ngx.say(ngx.encode_base64(digest))
-- outputs "tWW/2P/uOa/yIV1gRJySJLsHq1xwg0E1RWCvEUDlla0="
-- OR:
local d, err = require("resty.openssl.digest").new("sha256")
local digest, err = d:final("🦢")
ngx.say(ngx.encode_base64(digest))
-- outputs "tWW/2P/uOa/yIV1gRJySJLsHq1xwg0E1RWCvEUDlla0="
```

## resty.openssl.hmac

Module to interact with hash-based message authentication code (HMAC_CTX).

### hmac.new

**syntax**: *h, err = hmac.new(key, digest_name?)*

Creates a hmac instance. `digest_name` is a case-insensitive string of digest algorithm name.
To view a list of digest algorithms implemented, use `openssl list -digest-algorithms`.

If `digest_name` is omitted, it's default to `sha1`.

### hmac.istype

**syntax**: *ok = hmac.istype(table)*

Returns `true` if table is an instance of `hmac`. Returns `false` otherwise.

### hmac:update

**syntax**: *ok, err = hmac:update(partial, ...)*

Updates the HMAC with one or more strings.

### hmac:final

**syntax**: *str, err = hmac:final(partial?)*

Returns the HMAC in raw binary string, optionally accept one string to digest.

```lua
local d, err = require("resty.openssl.hmac").new("goose", "sha256")
d:update("🦢")
local hmac, err = d:final()
ngx.say(ngx.encode_base64(hmac))
-- outputs "k2UcrRp25tj1Spff89mJF3fAVQ0lodq/tJT53EYXp0c="
-- OR:
local d, err = require("resty.openssl.hmac").new("goose", "sha256")
local hmac, err = d:final("🦢")
ngx.say(ngx.encode_base64(hmac))
-- outputs "k2UcrRp25tj1Spff89mJF3fAVQ0lodq/tJT53EYXp0c="
```

## resty.openssl.rand

Module to interact with random number generator.

### rand.bytes

**syntax**: *str, err = rand.bytes(length)*

Generate random bytes with length of `length`. 

## resty.openssl.x509

Module to interact with X.509 certificates.

### x509.new

**syntax**: *crt, err = x509.new(pem)*

**syntax**: *crt, err = x509.new()*

Creates a `x509` instance. The first argument can be:

1. PEM-formatted X.509 certificate `string`.
2. `nil` to create an empty certificate.

### x509.dup

**syntax**: *x509, err = x509.dup(x509_ptr_cdata)*

Creates a `x509` instance from `X509*` cdata pointer.

### x509.istype

**syntax**: *ok = x509.istype(table)*

Returns `true` if table is an instance of `x509`. Returns `false` otherwise.

### x509:add_extension

**syntax**: *ok, err = x509:add_extension(extension)*

Adds an X.509 `extension` to certificate, the first argument must be a
[resty.openssl.x509.extension](#restyopensslx509extension) instance.

```lua
local extension, err = require("resty.openssl.extension").new({
    "keyUsage", "critical,keyCertSign,cRLSign",
})
local x509, err = require("resty.openssl.x509").new()
local ok, err = x509:add_extension(extension)
```

### x509:digest

**syntax**: *d, err = x509:digest(digest_name?)*

Returns a digest of the DER representation of the X509 certificate object in raw binary text.

`digest_name` is a case-insensitive string of digest algorithm name.
To view a list of digest algorithms implemented, use `openssl list -digest-algorithms`.

If `digest_name` is omitted, it's default to `sha1`.

### x509:pubkey_digest

**syntax**: *d, err = x509:pubkey_digest(digest_name?)*

Returns a digest of the DER representation of the pubkey in the X509 object in raw binary text.

`digest_name` is a case-insensitive string of digest algorithm name.
To view a list of digest algorithms implemented, use `openssl list -digest-algorithms`.

If `digest_name` is omitted, it's default to `sha1`.

### x509:get_*, x509:set_*

**syntax**: *ok, err = x509:set_attribute(instance)*

**syntax**: *instance, err = x509:get_attribute()*

Setters and getters for x509 attributes share the same syntax.

| Attribute name | Type | Description |
| ------------   | ---- | ----------- |
| issuer_name   | x509.name | Issuer of the certificate |
| not_before    | number | Unix timestamp when certificate is not valid before |
| not_after     | number | Unix timestamp when certificate is not valid after |
| pubkey        | pkey   | Public key of the certificate |
| serial_number | bn     | Serial number of the certficate |
| subject_name  | x509.name | Subject of the certificate |
| version       | number | Version of the certificate, value is one less than version. For example, `2` represents `version 3` |

Example:
```lua
local x509, err = require("resty.openssl.x509").new()
err = x509:set_not_before(ngx.time())
local not_before, err = x509:get_not_before()
ngx.say(not_before)
-- outputs 1571875065
```

### x509:get_lifetime

**syntax**: *not_before, not_after, err = x509:get_lifetime()*

A shortcut of `x509:get_not_before` plus `x509:get_not_after`

### x509:set_lifetime

**syntax**: *ok, err = x509:set_lifetime(not_before, not_after)*

A shortcut of `x509:set_not_before`
plus `x509:set_not_after`.

### x509:set_basic_constraints

**syntax**: *ok, err = x509:set_basic_constraints({CA = boolean})*

Sets the basic constraints flag. Accepts a table which contains a key `CA` and a boolean value,
indicating if the certificate is a CA or not.

### x509:set_basic_constraints_critical

**syntax**: *ok, err = x509:set_basic_constraints_critical(boolean)*

Sets the basic constraints critical flag.

### x509:sign

**syntax**: *ok, err = x509:sign(pkey)*

Sign the certificate using the private key specified by `pkey`. The first argument must be a 
[resty.openssl.pkey](#restyopensslpkey) that stores private key.

### x509:to_PEM

**syntax**: *pem, err = x509:to_PEM()*

Outputs the certificate in PEM-formatted text.

## resty.openssl.x509.name

Module to interact with X.509 names.

### name.new

**syntax**: *name, err = name.new()*

Creates an empty `name` instance.

### name.dup

**syntax**: *name, err = name.dup(name_ptr_cdata)*

Creates a `name` instance from `X509_NAME*` cdata pointer.

### name.istype

**syntax**: *ok = name.istype(table)*

Returns `true` if table is an instance of `name`. Returns `false` otherwise.

### name:add

**syntax**: *name, err = name:add(nid, txt)*

Adds an ASN.1 object to `name`. First arguments in the *text representation* of
[NID](https://boringssl.googlesource.com/boringssl/+/HEAD/include/openssl/nid.h).
Second argument is the plain text value for the ASN.1 object.

Returns the name instance itself on success, or `nil` and an error on failure.

This function can be called multiple times in a chained fashion.

```lua
local name, err = require("resty.openssl.x509.name").new()
local _, err = name:add("CN", "example.com")

_, err = name
    :add("C", "US")
    :add("ST", "California")
    :add("L", "San Francisco")

```

## resty.openssl.x509.altname

Module to interact with GENERAL_NAMES, an extension to X.509 names.

### altname.new

**syntax**: *altname, err = altname.new()*

Creates an empty `altname` instance.

### altname.istype

**syntax**: *altname = digest.istype(table)*

Returns `true` if table is an instance of `altname`. Returns `false` otherwise.

### altname:add

**syntax**: *altname, err = altname:add(key, value)*

Adds a name to altname stack, first argument is case-insensitive and can be one of

    RFC822Name
    RFC822
    RFC822
    UniformResourceIdentifier
    URI
    DNSName
    DNS
    IPAddress
    IP
    DirName

This function can be called multiple times in a chained fashion.

```lua
local altname, err = require("resty.openssl.x509").new()
local _, err = altname:add("DNS", "example.com")

_, err = altname
    :add("DNS", "2.example.com")
    :add("DnS", "3.example.com")
```

## resty.openssl.x509.csr

Module to interact with certificate signing request.

### csr.new

**syntax**: *csr, err = csr.new()*

Create an empty `csr` instance.

### csr.istype

**syntax**: *ok = csr.istype(table)*

Returns `true` if table is an instance of `csr`. Returns `false` otherwise.

### csr:set_subject_name

**syntax**: *ok = csr:set_subject_name(name)*

Set subject of the certificate request,
the first argument must be a [resty.openssl.x509.name](#restyopensslx509name) instance.

### csr:set_subject_alt

**syntax**: *ok = csr:set_subject_alt(name)*

Set additional subject identifiers of the certificate request,
the first argument must be a [resty.openssl.x509.altname](#restyopensslx509altname) instance.

For now this function can be only called `once` for a `csr` instance.

### csr:set_pubkey

**syntax**: *ok = csr:set_pubkey(pkey)*

Set public key of the certificate request,
the first argument must be a [resty.openssl.pkey](#restyopensslpkey) instance.

### csr:tostring

**syntax**: *str, err = csr:tostring(pem_or_der?)*

Outputs certificate request in PEM-formatted text or DER-formatted binary.
The first argument can be a choice of `PEM` or `DER`; when omitted, this function outputs PEM by default.

### csr:to_PEM

**syntax**: *pem, err = csr:to_PEM(?)*

Outputs CSR in PEM-formatted text.

## resty.openssl.x509.extension

Module to interact with X.509 extensions.

### extension.new

**syntax**: *ext, err = extension.new(name, value, data)*

Creates a new `extension` instance. `name` and `value` are strings in OpenSSL
[arbitrary extension format](https://www.openssl.org/docs/man1.0.2/man5/x509v3_config.html).

`data` can be a table or nil. Where data is a table, the following key will be looked up:

```lua
data = {
    issuer = resty.openssl.x509 instance,
    subject = resty.openssl.x509 instance,
    request = resty.opensl.csr instance,
}
```

Example:
```lua
local x509, err = require("resty.openssl.x509").new()
local extension = require("resty.openssl.x509.extension")
local ext, err = extension.new("extendedKeyUsage", "serverAuth,clientAuth")
ext, err =  extension.new("subjectKeyIdentifier", "hash", {
    subject = crt
})
```

### extension.istype

**syntax**: *ok = extension.istype(table)*

Returns `true` if table is an instance of `pkey`. Returns `false` otherwise.

## resty.openssl.x509.chain

Module to interact with X.509 stack.

### chain.new

**syntax**: *ch, err = chain.new()*

Creates a new `chain` instance.

### chain:add

**syntax**: *ok, err = chain:add(x509)*

Add a `X509` object to the chain. The first argument must be a
[resty.openssl.x509](#restyopensslx509) instance.

### chain:__metamethods

**syntax**: *x509 = chain[index]*

**syntax**: *for i, x509 in pairs(chain)*

**syntax**: *for i, x509 in ipairs(chain)*

Access the underlying stack element as it's a Lua table. Make sure your LuaJIT compiled
with `-DLUAJIT_ENABLE_LUA52COMPAT` flag.


Compatibility
====

Although only a small combinations of CPU arch and OpenSSL version are tested, the library
should function well as long as the linked OpenSSL library is API compatible. This means
the same name of functions are exported with same argument types.

For OpenSSL 1.0.2 series however, binary/ABI compatibility must be ensured as some struct members
are accessed directly. They are accessed by memory offset in assembly.

OpenSSL [keeps ABI/binary compatibility](https://wiki.openssl.org/index.php/Versioning)
with minor releases or letter releases. So all structs offsets and macro constants are kept
same.

If you plan to use this library on an untested version of OpenSSL (like custom builds or pre releases),
[this](https://abi-laboratory.pro/index.php?view=timeline&l=openssl) can be a good source to consult.

TODO
====

- test memory leak
- add tests for x509 getters/setters

[Back to TOC](#table-of-contents)


Copyright and License
=====================

This module is licensed under the BSD license.

Copyright (C) 2019, by fffonion <fffonion@gmail.com>.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[Back to TOC](#table-of-contents)

See Also
========
* [luaossl](https://github.com/wahern/luaossl)
* [API/ABI changes review for OpenSSL](https://abi-laboratory.pro/index.php?view=timeline&l=openssl)

[Back to TOC](#table-of-contents)
