local ffi = require "ffi"
local C = ffi.C
local ffi_new = ffi.new
local ffi_str = ffi.string

local provider_macro = require "resty.openssl.include.provider"
local OPENSSL_30 = require("resty.openssl.version").OPENSSL_30
local format_error = require("resty.openssl.err").format_error

if not OPENSSL_30 then
  error("provider is only supported since OpenSSL 3.0")
end

local _M = {}
local mt = {__index = _M}

local ossl_lib_ctx_st = ffi.typeof('OSSL_LIB_CTX*')

function _M.load(name, try)
  local ctx
  if try then
    ctx = C.OSSL_PROVIDER_try_load(nil, name)
    if ctx == nil then
      return nil, format_error("provider.try_load")
    end
  else
    ctx = C.OSSL_PROVIDER_load(nil, name)
    if ctx == nil then
      return nil, format_error("provider.load")
    end
  end

  return setmetatable({
    ctx = ctx,
    param_types = nil,
  }, mt), nil
end

function _M.set_default_search_path(path)
  if C.OSSL_PROVIDER_set_default_search_path(nil, path) ~= 1 then
    return false, format_error("provider.set_default_search_path")
  end
  return true
end

function _M.is_available(name)
  return C.OSSL_PROVIDER_available(nil, name) == 1
end

function _M.istype(l)
  return l and l.ctx and ffi.istype(ossl_lib_ctx_st, l.ctx)
end

function _M:unload()
  if C.OSSL_PROVIDER_unload(self.ctx) == nil then
    return false, format_error("provider:unload")
  end
  return true
end

function _M:self_test()
  if C.OSSL_PROVIDER_self_test(self.ctx) == nil then
    return false, format_error("provider:self_test")
  end
  return true
end

local params_well_known = {
  -- Well known parameter names that core passes to providers
  ["openssl-version"] = provider_macro.OSSL_PARAM_UTF8_PTR,
  ["provider-name"]   = provider_macro.OSSL_PARAM_UTF8_PTR,
  ["module-filename"] = provider_macro.OSSL_PARAM_UTF8_PTR,

  -- Well known parameter names that Providers can define
  ["name"]                = provider_macro.OSSL_PARAM_UTF8_PTR,
  ["version"]             = provider_macro.OSSL_PARAM_UTF8_PTR,
  ["buildinfo"]           = provider_macro.OSSL_PARAM_UTF8_PTR,
  ["status"]              = provider_macro.OSSL_PARAM_INTEGER,
  ["security-checks"]     = provider_macro.OSSL_PARAM_INTEGER,
}

local function load_gettable_names(ctx)
  local schema = {}
  for k, v in pairs(params_well_known) do
    schema[k] = v
  end

  local params = C.OSSL_PROVIDER_gettable_params(ctx)
  if params == nil then
    return nil, format_error("OSSL_PROVIDER_gettable_params")
  end

  while true do
    if params.key == nil then
      break
    end
    schema[ffi_str(params.key)] = tonumber(params.data_type)
    -- pointer arithmetic
    params = params + 1
  end
  return schema
end

function _M:get_params(...)
  local keys = {...}
  local key_length = #keys
  if key_length == 0 then
    return nil, "provider:get_params: at least one key is required"
  end

  if not self.param_types then
    local param_types, err = load_gettable_names(self.ctx)
    if err then
      return nil, "provider:get_params: " .. err
    end
    self.param_types = param_types
  end

  local req = ffi_new("OSSL_PARAM[?]", key_length + 1)

  local buffers = {}
  for i, key in ipairs(keys) do
    local typ = self.param_types[key]
    if not typ then
      return nil, "provider:get_params: unknown key \"" .. key .. "\""
    end
    local param
    if typ == provider_macro.OSSL_PARAM_UTF8_PTR then
      local buf = ffi_new("char*[1]")
      buffers[i] = buf
      param = C.OSSL_PARAM_construct_utf8_ptr(key, buf, 0)
    elseif typ == provider_macro.OSSL_PARAM_INTEGER then
      local buf = ffi_new("int[1]")
      buffers[i] = buf
      param = C.OSSL_PARAM_construct_int(key, buf)
    else
      return nil, "provider:get_params: not yet supported type \"" .. typ .. "\" for \"" .. key .. "\""
    end
    req[i-1] = param
  end

  req[key_length] = C.OSSL_PARAM_construct_end()

  if C.OSSL_PROVIDER_get_params(self.ctx, req) ~= 1 then
    return nil, format_error("provider:get_params")
  end

  for i=0, key_length do
    local buf = buffers[i]
    local key = keys[i]
    local typ = self.param_types[key]
    if typ == provider_macro.OSSL_PARAM_UTF8_PTR then
      buffers[key] = ffi_str(buf[0])
    elseif typ == provider_macro.OSSL_PARAM_INTEGER then
      buffers[key] = tonumber(buf[0])
    end
    buffers[i] = nil
    -- crypto_macro.OPENSSL_free(req[i-1].data)
  end

  if key_length == 1 then
    return buffers[keys[1]]
  end
  return buffers
end

return _M
