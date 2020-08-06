local ffi = require "ffi"
local cjson = require("cjson.safe")
local evp_macro = require "resty.openssl.include.evp"
local rsa_lib = require "resty.openssl.rsa"
local ec_lib = require "resty.openssl.ec"
local ecx_lib = require "resty.openssl.ecx"
local bn_lib = require "resty.openssl.bn"
local digest_lib = require "resty.openssl.digest"
local ctypes = require "resty.openssl.aux.ctypes"
local base64 = ngx and require('ngx.base64') or {}

local C = ffi.C
local ffi_str = ffi.string
local uchar_array = ctypes.uchar_array

local cjson_encode = cjson.encode
local ipairs, pairs = ipairs, pairs

local function base64_encoded_length(len)
    return ((len + 2) / 3) * 4
end

local function base64_decoded_length(len)
    return ((len + 3) / 4) * 3
end

local function encode_b64(s)
    local size = base64_encoded_length(#s)
    local buf = uchar_array(size)
    local c = C.EVP_EncodeBlock(buf, s, #s)
    if c < 0 then
        return nil, "can not encode"
    end
    return ffi_str(buf, size):gsub("+", "-")
                             :gsub("/", "_")
end

local function decode_b64(s)
    s = s:gsub("-", "+")
         :gsub("_", "/")
    local size = #s
    local rem = size % 4
    if rem > 0 then
        s = s .. (("="):rep(4 - rem))
    end
    size = base64_decoded_length(#s)
    local buf = uchar_array(size)
    size = C.EVP_DecodeBlock(buf, s, #s)
    if size < 0 then
        return nil, "can not decode base 64"
    end
    return ffi_str(buf, size)
end
local encode_base64url = ngx and base64.encode_base64url or  encode_b64
local decode_base64url = ngx and base64.decode_base64url or decode_b64
local _M = {}

local rsa_jwk_params = { "n", "e", "d", "p", "q", "dp", "dq", "qi" }
local rsa_openssl_params = rsa_lib.params

local function load_jwk_rsa(tbl)

    if not tbl["n"] or not tbl["e"] then
        return nil, "at least \"n\" and \"e\" parameter is required"
    end

    local params = {}
    local err
    for i, k in ipairs(rsa_jwk_params) do
        local v = tbl[k]
        if v then
            v = decode_base64url(v)
            require('pl.pretty').dump {
                V = v or "EMPTY",
                VV = tbl[k]
            }
            if not v then
                return nil, "cannot decode parameter \"" .. k .. "\" from base64 " .. tbl[k]
            end

            params[rsa_openssl_params[i]], err = bn_lib.from_binary(v)
            if err then
                return nil, "cannot use parameter \"" .. k .. "\": " .. err
            end
        end
    end

    local key = C.RSA_new()
    if key == nil then
        return nil, "RSA_new() failed"
    end

    local _, err = rsa_lib.set_parameters(key, params)
    if err ~= nil then
        C.RSA_free(key)
        return nil, err
    end

    return key
end

local ec_curves = {
    ["P-256"] = C.OBJ_ln2nid("prime256v1"),
    ["P-384"] = C.OBJ_ln2nid("secp384r1"),
    ["P-512"] = C.OBJ_ln2nid("secp512r1"),
}

local ec_curves_reverse = {}
for k, v in pairs(ec_curves) do
    ec_curves_reverse[v] = k
end

local ec_jwk_params = { "x", "y", "d" }

local function load_jwk_ec(tbl)
    local curve = tbl['crv']
    if not curve then
        return nil, "\"crv\" not defined for EC key"
    end
    if not tbl["x"] or not tbl["y"] then
        return nil, "at least \"x\" and \"y\" parameter is required"
    end
    local curve_nid = ec_curves[curve]
    if not curve_nid then
        return nil, "curve \"" .. curve .. "\" is not supported by this library"
    elseif curve_nid == 0 then
        return nil, "curve \"" .. curve .. "\" is not supported by linked OpenSSL"
    end

    local params = {}
    local err
    for _, k in ipairs(ec_jwk_params) do
        local v = tbl[k]
        if v then
            v = decode_base64url(v)
            if not v then
                return nil, "cannot decode parameter \"" .. k .. "\" from base64 " .. tbl[k]
            end

            params[k], err = bn_lib.from_binary(v)
            if err then
                return nil, "cannot use parameter \"" .. k .. "\": " .. err
            end
        end
    end

    -- map to the name we expect
    if params["d"] then
        params["private"] = params["d"]
        params["d"] = nil
    end
    params["group"] = curve_nid

    local key = C.EC_KEY_new()
    if key == nil then
        return nil, "EC_KEY_new() failed"
    end

    local _, err = ec_lib.set_parameters(key, params)
    if err ~= nil then
        C.EC_KEY_free(key)
        return nil, err
    end

    return key
end

local function load_jwk_okp(key_type, tbl)
    local params = {}
    if tbl["d"] then
        params.private = decode_base64url(tbl["d"])
    elseif tbl["x"] then
        params.public = decode_base64url(tbl["x"])
    else
        return nil, "at least \"x\" or \"d\" parameter is required"
    end
    local key, err = ecx_lib.set_parameters(key_type, nil, params)
    if err ~= nil then
        return nil, err
    end
    return key
end

local ecx_curves_reverse = {}
for k, v in pairs(evp_macro.ecx_curves) do
    ecx_curves_reverse[v] = k
end

function _M.load_jwk(txt)
    local tbl, err = cjson.decode(txt)

    if err then
        return nil, "error decoding JSON from JWK: " .. err
    elseif type(tbl) ~= "table" then
        return nil, "except input to be decoded as a table, got " .. type(tbl)
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
            return nil, "the linked OpenSSL library doesn't support EC key"
        end
        key, err = load_jwk_ec(tbl)
        key_free = C.EC_KEY_free
    elseif tbl["kty"] == "OKP" then
        local curve = tbl["crv"]
        key_type = evp_macro.ecx_curves[curve]
        if not key_type then
            return nil, "unknown curve \"" .. tostring(curve)
        elseif key_type == 0 then
            return nil, "the linked OpenSSL library doesn't support \"" .. curve .. "\" key"
        end
        key, err = load_jwk_okp(key_type, tbl)
        if key ~= nil then
            return key
        end
    else
        return nil, "not yet supported jwk type \"" .. (tbl["kty"] or "nil") .. "\""
    end

    if err then
        return nil, "failed to construct " .. tbl["kty"] .. " key from JWK: " .. err
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

function _M.dump_jwk(pkey, is_priv)
    local jwk
    if pkey.key_type == evp_macro.EVP_PKEY_RSA then
        local param_keys = { "n", "e" }
        if is_priv then
            param_keys = rsa_jwk_params
        end
        local params, err = pkey:get_parameters()
        if err then
            return nil, "jwk.dump_jwk: " .. err
        end
        jwk = {
            kty = "RSA",
        }
        for i, p in ipairs(param_keys) do
            local v = params[rsa_openssl_params[i]]:to_binary()
            jwk[p] = encode_base64url(v)
        end
    elseif pkey.key_type == evp_macro.EVP_PKEY_EC then
        local params, err = pkey:get_parameters()
        if err then
            return nil, "jwk.dump_jwk: " .. err
        end
        jwk = {
            kty = "EC",
            crv = ec_curves_reverse[params.group],
            x = encode_base64url(params.x:to_binary()),
            y = encode_base64url(params.x:to_binary()),
        }
        if is_priv then
            jwk.d = encode_base64url(params.private:to_binary())
        end
    elseif ecx_curves_reverse[pkey.key_type] then
        local params, err = pkey:get_parameters()
        if err then
            return nil, "jwk.dump_jwk: " .. err
        end
        jwk = {
            kty = "OKP",
            crv = ecx_curves_reverse[pkey.key_type],
            d = encode_base64url(params.private),
            x = encode_base64url(params.public),
        }
    else
        return nil, "jwk.dump_jwk: not implemented for this key type"
    end

    local der = pkey:tostring(is_priv and "private" or "public", "DER")
    local dgst = digest_lib.new("sha256")
    local d, err = dgst:final(der)
    if err then
        return nil, "jwk.dump_jwk: failed to calculate digest for key"
    end
    jwk.kid = encode_base64url(d)

    return cjson_encode(jwk)
end

return _M