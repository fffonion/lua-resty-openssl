local ffi = require "ffi"
local C = ffi.C
local ffi_str = ffi.string

require "resty.openssl.include.ssl"

local nginx_aux = require("resty.openssl.aux.nginx")
local x509_lib = require("resty.openssl.x509")
local chain_lib = require("resty.openssl.x509.chain")
local stack_lib = require("resty.openssl.stack")
local OPENSSL_30 = require("resty.openssl.version").OPENSSL_30
local format_error = require("resty.openssl.err").format_error

local _M = {}
local mt = {__index = _M}

local ssl_ptr_ct = ffi.typeof('SSL*')

local stack_of_ssl_cipher_iter = function(ctx)
  return stack_lib.mt_of("SSL_CIPHER", function(x) return x end, {}, true).__ipairs({ctx = ctx})
end

function _M.from_request()
  -- don't GC this
  local ctx, err = nginx_aux.get_req_ssl()
  if err ~= nil then
    return nil, err
  end

  return setmetatable({
    ctx = ctx,
    -- the cdata is not manage by Lua, don't GC on Lua side
    _managed = false,
    -- this is the client SSL session
    _server = true,
  }, mt)
end

function _M.from_socket(socket)
  if not socket then
    return nil, "expect a ngx.socket.tcp instance at #1"
  end
  -- don't GC this
  local ctx, err = nginx_aux.get_socket_ssl(socket)
  if err ~= nil then
    return nil, err
  end

  return setmetatable({
    ctx = ctx,
    -- the cdata is not manage by Lua, don't GC on Lua side
    _managed = false,
    -- this is the client SSL session
    _server = false,
  }, mt)
end

function _M.istype(l)
  return l and l.ctx and ffi.istype(ssl_ptr_ct, l.ctx)
end

function _M:get_peer_certificate()
  local x509
  if OPENSSL_30 then
    x509 = C.SSL_get1_peer_certificate(self.ctx)
  else
    x509 = C.SSL_get_peer_certificate(self.ctx)
  end

  if x509 == nil then
    return nil
  end
  ffi.gc(x509, C.X509_free)

  local err
  -- always copy, although the ref counter of returned x509 is
  -- already increased by one.
  x509, err = x509_lib.dup(x509)
  if err then
    return nil, err
  end

  return x509
end

function _M:get_peer_cert_chain()
  local stack = C.SSL_get_peer_cert_chain(self.ctx)

  if stack == nil then
    return nil
  end

  return chain_lib.dup(stack)
end

-- TLSv1.3
function _M:set_ciphersuites(ciphers)
  if C.SSL_set_ciphersuites(self.ctx, ciphers) ~= 1 then
    return false, format_error("ssl:set_ciphers: SSL_set_ciphersuites")
  end

  return true
end

-- TLSv1.2 and lower
function _M:set_cipher_list(ciphers)
  if C.SSL_set_cipher_list(self.ctx, ciphers) ~= 1 then
    return false, format_error("ssl:set_ciphers: SSL_set_cipher_list")
  end

  return true
end

function _M:get_ciphers()
  local ciphers = C.SSL_get_ciphers(self.ctx)

  if ciphers == nil then
    return nil
  end

  local ret = {}

  for i, cipher in stack_of_ssl_cipher_iter(ciphers) do
    cipher = C.SSL_CIPHER_get_name(cipher)
    if cipher == nil then
      return nil, format_error("ssl:get_ciphers: SSL_CIPHER_get_name")
    end
    ret[i] = ffi_str(cipher)
  end

  return table.concat(ret, ":")
end

function _M:get_cipher_name()
  local cipher = C.SSL_get_current_cipher(self.ctx)

  if cipher == nil then
    return nil
  end

  cipher = C.SSL_CIPHER_get_name(cipher)
  if cipher == nil then
    return nil, format_error("ssl:get_current_cipher: SSL_CIPHER_get_name")
  end
  return ffi_str(cipher)
end

function _M:set_timeout(epoch)
  local session = C.SSL_get_session(self.ctx)

  if session == nil then
    return false, format_error("ssl:set_timeout: SSL_get_session")
  end

  if C.SSL_SESSION_set_timeout(session, epoch) ~= 1 then
    return false, format_error("ssl:set_timeout: SSL_SESSION_set_timeout")
  end
  return true
end

function _M:get_timeout()
  local session = C.SSL_get_session(self.ctx)

  if session == nil then
    return false, format_error("ssl:get_timeout: SSL_get_session")
  end

  return tonumber(C.SSL_SESSION_get_timeout(session))
end


return _M