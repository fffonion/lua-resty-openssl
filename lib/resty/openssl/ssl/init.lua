local ffi = require "ffi"
local C = ffi.C
local ffi_str = ffi.string

require "resty.openssl.include.ssl"

local nginx_ssl = require("resty.openssl.aux.nginx")
local x509_lib = require("resty.openssl.x509")
local chain_lib = require("resty.openssl.x509.chain")
local stack_lib = require("resty.openssl.stack")

local format_error = require("resty.openssl.err").format_error

local _M = {}
local mt = {__index = _M}

local ssl_ptr_ct = ffi.typeof('SSL*')

local stack_of_ssl_cipher_iter = function(ctx)
  return stack_lib.mt_of("SSL_CIPHER", function(x) return x end, {}, true).__ipairs({ctx = ctx})
end

function _M.from_request()
  -- don't GC this
  local ctx, err = nginx_ssl.get_req_ssl()
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
  local ctx, err = nginx_ssl.get_socket_ssl(socket)
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
  local x509 = C.SSL_get_peer_certificate(self.ctx)

  if x509 == nil then
    return nil
  end

  return x509_lib.new(x509)
end

function _M:get_peer_cert_chain()
  local stack = C.SSL_get_peer_cert_chain(self.ctx)

  if stack == nil then
    return nil
  end

  return chain_lib.dup(stack)
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

  return ret
end

function _M:get_current_cipher()
  local cipher = C.SSL_get_current_cipher(self.ctx)

  if cipher == nil then
    return nil
  end

  cipher = C.SSL_CIPHER_get_name(cipher)
  if cipher == nil then
    return nil, format_error("ssl:get_ciphers: SSL_CIPHER_get_name")
  end
  return ffi_str(cipher)
end


return _M