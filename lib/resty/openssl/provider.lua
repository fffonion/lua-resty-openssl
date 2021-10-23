local ffi = require "ffi"
local C = ffi.C
local ffi_str = ffi.string

require "resty.openssl.include.provider"
local param_macro = require "resty.openssl.include.param"
local OPENSSL_30 = require("resty.openssl.version").OPENSSL_30
local format_error = require("resty.openssl.err").format_error

if not OPENSSL_30 then
  error("provider is only supported since OpenSSL 3.0")
end

local _M = {}
local mt = {__index = _M}

local ossl_provider_ctx_ct = ffi.typeof('OSSL_PROVIDER*')

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
  C.OSSL_PROVIDER_set_default_search_path(nil, path)
end

function _M.is_available(name)
  return C.OSSL_PROVIDER_available(nil, name) == 1
end

function _M.istype(l)
  return l and l.ctx and ffi.istype(ossl_provider_ctx_ct, l.ctx)
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
  ["openssl-version"] = param_macro.OSSL_PARAM_UTF8_PTR,
  ["provider-name"]   = param_macro.OSSL_PARAM_UTF8_PTR,
  ["module-filename"] = param_macro.OSSL_PARAM_UTF8_PTR,

  -- Well known parameter names that Providers can define
  ["name"]                = param_macro.OSSL_PARAM_UTF8_PTR,
  ["version"]             = param_macro.OSSL_PARAM_UTF8_PTR,
  ["buildinfo"]           = param_macro.OSSL_PARAM_UTF8_PTR,
  ["status"]              = param_macro.OSSL_PARAM_INTEGER,
  ["security-checks"]     = param_macro.OSSL_PARAM_INTEGER,
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

  local buffers = {}
  for _, key in ipairs(keys) do
    buffers[key] = ngx.null
  end
  local req, err = param_macro.construct(buffers, key_length, self.param_types)
  if not req then
    return nil, "provider:get_params: failed to construct params: " .. err
  end

  if C.OSSL_PROVIDER_get_params(self.ctx, req) ~= 1 then
    return nil, format_error("provider:get_params")
  end

  buffers, err = param_macro.parse(buffers, key_length, self.param_types)
  if err then
    return nil, "provider:get_params: failed to parse params: " .. err
  end

  if key_length == 1 then
    return buffers[keys[1]]
  end
  return buffers
end

return _M
