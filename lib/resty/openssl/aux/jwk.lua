
local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc

local cjson = require("cjson.safe")
local evp_macro = require "resty.openssl.include.evp"
require "resty.openssl.include.rsa"
local rsa_lib = require "resty.openssl.rsa"
local bn_lib = require "resty.openssl.bn"

local b64 = require("ngx.base64")


local _M = {}

local rsa_jwk_params = {"n", "e", "d", "p", "q", "dp", "dq", "qi"}
local rsa_openssl_params = rsa_lib.params

local function load_jwk_rsa(tbl)
  if not tbl["n"] and not tbl["e"] then
    return nil, "at least \"n\" and \"e\" parameter is required"
  end
  local key = C.RSA_new()
  if key == nil then
    return nil, "RSA_new() failed"
  end

  local params = {}
  local err
  for i, k in ipairs(rsa_jwk_params) do
    local v = tbl[k]
    if v then
      v = b64.decode_base64url(v)
      if not v then
        return nil, "cannot decode parameter \"" .. k .. "\" from base64 " .. tbl[k]
      end

      params[rsa_openssl_params[i]], err = bn_lib.from_binary(v)
      if err then
        C.RSA_free(key)
        return nil, "cannot use parameter \"" .. k .. "\": " .. err
      end
    end
  end

  local _, err = rsa_lib.set_parameters(key, params)
  if err ~= nil then
    C.RSA_free(key)
    return nil, err
  end

  return key
end

local curve_map = {
  ["P-256"] = C.OBJ_ln2nid("prime256v1"),
  ["P-384"] = C.OBJ_ln2nid("secp384r1"),
  ["P-512"] = C.OBJ_ln2nid("secp512r1"),
}

local ec_jwk_params = {"x", "y", "d"}

local function load_jwk_ec(tbl)
  local curve = tbl['crv']
  if not curve then
    return nil, "\"crv\" not defined for EC key"
  end
  if not tbl["x"] and not tbl["y"] then
    return nil, "at least \"x\" and \"y\" parameter is required"
  end
  local nid = curve_map[curve]
  if not nid then
    return nil, "curve \"" .. curve .. "\" is not supported by this library"
  elseif nid == 0 then
    return nil, "curve \"" .. curve .. "\" is not supported by linked OpenSSL"
  end
  local group = C.EC_GROUP_new_by_curve_name(nid)
  if group == nil then
    return nil, "EC_GROUP_new_by_curve_name() failed"
  end
  ffi_gc(group, C.EC_GROUP_free)
  -- # define OPENSSL_EC_NAMED_CURVE     0x001
  C.EC_GROUP_set_asn1_flag(group, 1)
  C.EC_GROUP_set_point_conversion_form(group, C.POINT_CONVERSION_UNCOMPRESSED)

  local key = C.EC_KEY_new()
  if key == nil then
    return nil, "EC_KEY_new() failed"
  end
  C.EC_KEY_set_group(key, group)


  return key
end

local function load_jwk_ed25519(tbl)
  return nil, "NYI"
end

function _M.load_jwk(txt)
  local tbl, err = cjson.decode(txt)
  if err then
    return nil, "error decoding jwk json: " .. err
  end

  local key, key_free, key_type, err

  if tbl["kty"] == "RSA" then
    key_type = evp_macro.EVP_PKEY_RSA
    if key_type == 0 then
      return nil, "the linked OpenSSL library doesn't support RSA key"
    end
    key, err = load_jwk_rsa(tbl)
    key_free = C.RSA_free
  elseif tbl["kty"] == "EC" then
    key_type = evp_macro.EVP_PKEY_EC
    if key_type == 0 then
      return nil, "the linked OpenSSL library doesn't support Ed25519 key"
    end
    key, err = load_jwk_ec(tbl)
    key_free = C.EC_KEY_free
  elseif tbl["kty"] == "OKP" and tbl["crv"] == "Ed25519" then
    key_type = evp_macro.EVP_PKEY_ED25519
    if key_type == 0 then
      return nil, "the linked OpenSSL library doesn't support Ed25519 key"
    end
    key, err = load_jwk_ed25519(tbl)
    key_free = C.EC_KEY_free
  else
    return nil, "not yet supported jwk type \"" .. (tbl["kty"] or "nil") .. "\""
  end

  if err then
    return nil, "failed to construct key from JWK: " .. err
  end

  local ctx = C.EVP_PKEY_new()
  if ctx == nil then
    key_free(key)
    return nil, "EVP_PKEY_new() failed"
  end

  local code = C.EVP_PKEY_assign(ctx, key_type, key)
  if code ~= 1 then
    key_free(key)
    C.EVP_PKEY_free(ctx)
    return nil, "EVP_PKEY_assign() failed"
  end

  return ctx
end

return _M