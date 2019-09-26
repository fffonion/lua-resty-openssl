package = "lua-resty-openssl"
version = "0.1.0-1"
source = {
   url = "git+https://github.com/fffonion/lua-resty-openssl.git"
}
description = {
   detailed = "FFI-based OpenSSL binding for LuaJIT.",
   homepage = "https://github.com/fffonion/lua-resty-openssl",
   license = "BSD"
}
build = {
   type = "builtin",
   modules = {
      ["resty.openssl"] = "lib/resty/openssl.lua",
      ["resty.openssl.asn1"] = "lib/resty/openssl/asn1.lua",
      ["resty.openssl.bio"] = "lib/resty/openssl/bio.lua",
      ["resty.openssl.bn"] = "lib/resty/openssl/bn.lua",
      ["resty.openssl.digest"] = "lib/resty/openssl/digest.lua",
      ["resty.openssl.ec"] = "lib/resty/openssl/ec.lua",
      ["resty.openssl.evp"] = "lib/resty/openssl/evp.lua",
      ["resty.openssl.objects"] = "lib/resty/openssl/objects.lua",
      ["resty.openssl.ossl_typ"] = "lib/resty/openssl/ossl_typ.lua",
      ["resty.openssl.pem"] = "lib/resty/openssl/pem.lua",
      ["resty.openssl.pkey"] = "lib/resty/openssl/pkey.lua",
      ["resty.openssl.rsa"] = "lib/resty/openssl/rsa.lua",
      ["resty.openssl.stack"] = "lib/resty/openssl/stack.lua",
      ["resty.openssl.util"] = "lib/resty/openssl/util.lua",
      ["resty.openssl.version"] = "lib/resty/openssl/version.lua",
      ["resty.openssl.x509.altname"] = "lib/resty/openssl/x509/altname.lua",
      ["resty.openssl.x509.csr"] = "lib/resty/openssl/x509/csr.lua",
      ["resty.openssl.x509.init"] = "lib/resty/openssl/x509/init.lua",
      ["resty.openssl.x509.name"] = "lib/resty/openssl/x509/name.lua",
      ["resty.openssl.x509v3"] = "lib/resty/openssl/x509v3.lua"
   }
}
