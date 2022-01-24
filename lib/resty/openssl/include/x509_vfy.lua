local ffi = require "ffi"
local C = ffi.C

require "resty.openssl.include.ossl_typ"
require "resty.openssl.include.stack"
local OPENSSL_10 = require("resty.openssl.version").OPENSSL_10
local OPENSSL_11_OR_LATER = require("resty.openssl.version").OPENSSL_11_OR_LATER
local OPENSSL_30 = require("resty.openssl.version").OPENSSL_30
local BORINGSSL_110 = require("resty.openssl.version").BORINGSSL_110

ffi.cdef [[
  X509_STORE *X509_STORE_new(void);
  void X509_STORE_free(X509_STORE *v);
 /* int X509_STORE_lock(X509_STORE *ctx);
  int X509_STORE_unlock(X509_STORE *ctx);
  int X509_STORE_up_ref(X509_STORE *v);
  // STACK_OF(X509_OBJECT)
  OPENSSL_STACK *X509_STORE_get0_objects(X509_STORE *v);*/

  int X509_STORE_add_cert(X509_STORE *ctx, X509 *x);
  int X509_STORE_add_crl(X509_STORE *ctx, X509_CRL *x);
  int X509_STORE_load_locations(X509_STORE *ctx,
                              const char *file, const char *dir);
  int X509_STORE_set_default_paths(X509_STORE *ctx);

  X509_STORE_CTX *X509_STORE_CTX_new(void);
  void X509_STORE_CTX_free(X509_STORE_CTX *ctx);
  // STACK_OF(X509)
  int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store,
                        X509 *x509, OPENSSL_STACK *chain);

  int X509_STORE_CTX_get_error(X509_STORE_CTX *ctx);

  int X509_STORE_set_flags(X509_STORE *ctx, unsigned long flags);
]]

local _M = {}

if OPENSSL_10 or BORINGSSL_110 then
  ffi.cdef [[
    // STACK_OF(X509)
    OPENSSL_STACK *X509_STORE_CTX_get_chain(X509_STORE_CTX *ctx);
  ]];
  _M.X509_STORE_CTX_get0_chain = C.X509_STORE_CTX_get_chain
elseif OPENSSL_11_OR_LATER then
  ffi.cdef [[
    // STACK_OF(X509)
    OPENSSL_STACK *X509_STORE_CTX_get0_chain(X509_STORE_CTX *ctx);
  ]];
  _M.X509_STORE_CTX_get0_chain = C.X509_STORE_CTX_get0_chain
end

if OPENSSL_30 then
  ffi.cdef [[
    X509_STORE_CTX *X509_STORE_CTX_new_ex(OSSL_LIB_CTX *libctx, const char *propq);

    int X509_STORE_set_default_paths_ex(X509_STORE *ctx, OSSL_LIB_CTX *libctx,
                                        const char *propq);
    /* int X509_STORE_load_file_ex(X509_STORE *ctx, const char *file,
                                OSSL_LIB_CTX *libctx, const char *propq);
    int X509_STORE_load_store_ex(X509_STORE *ctx, const char *uri,
                                OSSL_LIB_CTX *libctx, const char *propq); */
    int X509_STORE_load_locations_ex(X509_STORE *ctx, const char *file,
                                    const char *dir, OSSL_LIB_CTX *libctx,
                                    const char *propq);
  ]]
  _M.X509_STORE_set_default_paths = function(...) return C.X509_STORE_set_default_paths_ex(...) end
  _M.X509_STORE_load_locations = function(...) return C.X509_STORE_load_locations_ex(...) end
else
  _M.X509_STORE_set_default_paths = function(s) return C.X509_STORE_set_default_paths(s) end
  _M.X509_STORE_load_locations = function(s, file, dir) return C.X509_STORE_load_locations(s, file, dir) end
end

return _M

