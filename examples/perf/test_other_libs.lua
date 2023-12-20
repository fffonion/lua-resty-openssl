local path = debug.getinfo(1, "S").source:sub(2):match("(.*/)")
package.path = path .. "/?.lua;" .. package.path

local test = require "framework".test
local set_iteration = require "framework".set_iteration
local write_seperator = require "framework".write_seperator
local cipher = require "resty.openssl.cipher"
local digest = require "resty.openssl.digest"
local pkey = require "resty.openssl.pkey"
local version = require "resty.openssl.version"
local rand = require "resty.openssl.rand"
local aes = require "resty.aes"
local resty_rsa = require "resty.rsa"

-- ensure best performance
require "framework".set_no_count_iter(true)

local luaossl
do
    local pok, perr, err = pcall(require, "_openssl")
    if pok then
        luaossl = perr
    end
end

local lua_openssl
do
    -- move openssl.so to lua-openssl.so to avoid conflict with luaossl
    local pok, perr, err = pcall(require, "lua-openssl")
    if pok then
        lua_openssl = perr
    end
end

local lua_pack
do
    local pok, perr, err = pcall(require, "lua_pack")
    if pok then
        lua_pack = perr
    end
end

------------- bn

set_iteration(1000000)

local binary_input = rand.bytes(24)
local bn = require "resty.openssl.bn"
local hex_input = assert(bn.from_binary(binary_input)):to_hex()

test("lua-resty-openssl bn unpack parse binary", function()
    return bn.new(hex_input, 16)
end)

local bni = bn.new()
test("lua-resty-openssl bn unpack parse binary reused struct", function()
    return bni:set(hex_input, 16)
end)

if luaossl then
    local luaossl_bn = require "_openssl.bignum"
    local hex_input = "0X" .. hex_input

    test("luaossl bn unpack parse binary", function()
        return luaossl_bn.new(hex_input)
    end)
end

if lua_openssl then
    local hex_input = "X" .. hex_input
    test("lua-openssl bn unpack parse binary", function()
        return lua_openssl.bn.number(hex_input)
    end)
end

if lua_pack then
    test("lua_pack unpack 6 int", function()
        return lua_pack.unpack(binary_input, ">6I")
    end)
end


------------- cipher
write_seperator()

local key = rand.bytes(32)
local iv = rand.bytes(16)
local data = string.rep("1", 4096)

set_iteration(100000)

for _, t in ipairs({"aes-256-cbc", "aes-256-gcm"}) do
    for _, op in ipairs({"encrypt", "decrypt"}) do 

        local c = assert(cipher.new(t))
        local _iv = iv
        if t == "aes-256-gcm" then
            _iv = string.rep("0", 12)
        end

        local aes_default
        if t == "aes-256-cbc" then
            aes_default = aes:new(key, nil, aes.cipher(256, "cbc"), {iv = _iv})
        else
            aes_default = aes:new(key, nil, aes.cipher(256, "gcm"), {iv = _iv})
        end

        local luaossl_aes
        if luaossl then
            local luaossl_cipher = require "_openssl.cipher"
            luaossl_aes = luaossl_cipher.new(t)
        end

        local ciphertext = assert(c:encrypt(key, _iv, data, false))

        if op == "encrypt" then
            -- assert(c:init(key, _iv, {is_encrypt = true }))
            -- assert(c:encrypt(key, _iv, data, false))
            test("lua-resty-openssl encrypt with " .. t .. " on " .. #data .. " bytes", function()
                return c:encrypt(key, _iv, data, false)
                -- return c:final(data)
            end, nil, ciphertext)

            test("lua-resty-strings encrypt with " .. t .. " on " .. #data .. " bytes", function()
                local r = aes_default:encrypt(data)
                if t == "aes-256-gcm" then
                    return r[1]
                end
                return r
            end, nil, ciphertext)

            if luaossl then
                test("luaossl encrypt with " .. t .. " on " .. #data .. " bytes", function()
                    return luaossl_aes:encrypt(key, _iv):final(data) 
                end, nil, ciphertext)
            end

            if lua_openssl then
                local evp_cipher = lua_openssl.cipher.get(t)
                test("lua_openssl encrypt with " .. t .. " on " .. #data .. " bytes", function()
                    return evp_cipher:encrypt(data, key, _iv)
                end, nil, ciphertext)
            end


        else

            local tag
            if t == "aes-256-gcm" then
                tag = assert(c:get_aead_tag())
            end
            -- assert(c:init(key, _iv))
            test("lua-resty-openssl decrypt with " .. t .. " on " .. #ciphertext .. " bytes", function()
                -- if tag then
                --    c:set_aead_tag(tag)
                --end
                --return c:final(ciphertext)
                return c:decrypt(key, _iv, ciphertext, false, nil, tag)
            end, nil, data)


            test("lua-resty-strings decrypt with " .. t .. " on " .. #ciphertext .. " bytes", function()
                return aes_default:decrypt(ciphertext, tag) 
            end, nil, data)

            if luaossl then
                --local luaossl_cipher = require "openssl.cipher"
                --local luaossl_aes2 = luaossl_cipher.new(t)

                test("luaossl decrypt with " .. t .. " on " .. #ciphertext .. " bytes", function()
                    luaossl_aes:decrypt(key, _iv)
                    if t == "aes-256-gcm" then
                        luaossl_aes:setTag(tag)
                    end
                    return luaossl_aes:final(ciphertext)
                end, nil, data)
            end


            if lua_openssl then
                local evp = lua_openssl.cipher.get(t)

                local d = evp:decrypt_new(key, _iv)
                test("lua_openssl decrypt with " .. t .. " on " .. #ciphertext .. " bytes", function()
                    d:ctrl(lua_openssl.cipher.EVP_CTRL_GCM_SET_IVLEN, #_iv)
                    d:init(key, _iv)
                    d:padding(false)

                    local r = d:update(ciphertext)
                    if t == "aes-256-gcm" then
                        assert(d:ctrl(lua_openssl.cipher.EVP_CTRL_GCM_SET_TAG, tag))
                    end
                    return r .. d:final()
                end) -- has extra padding: , nil, data)
            end
        end
::continue::
    end

    write_seperator()
end

------------- digest
write_seperator()

for _, t in ipairs({"sha256", "md5"}) do

    local d = digest.new(t)

    local expected = d:final(data)

    test("lua-resty-openssl " .. t .. " on " .. #data .. " bytes", function()
        d:reset()
        return d:final(data)
    end, nil, expected)

    local h = require ("resty." .. t)
    local hh = h:new()

    test("lua-resty-strings " .. t .. " on " .. #data .. " bytes", function()
        hh:reset()
        hh:update(data)
        return hh:final()
    end, nil, expected)

    if luaossl then
        local _digest = require "_openssl.digest"
        test("luaossl " .. t .. " on " .. #data .. " bytes", function()
            local hh = _digest.new(t)
            return hh:final(data)
        end, nil, expected)
    end

    if lua_openssl then
        local hh = lua_openssl.digest.get(t)
        test("lua_openssl " .. t .. " on " .. #data .. " bytes", function()
            return hh:digest(data)
        end, nil, expected)
    end

    if t == "md5" then
        test("ngx.md5_bin on " .. #data .. " bytes", function()
            return ngx.md5_bin(data)
        end, nil, expected)
    end
end

------------- pkey
write_seperator()

local key = pkey.new({ type = "RSA", bits = 4096 }) 
local data = string.rep("1", 200)
local rsa_encrypted = assert(key:encrypt(data, pkey.PADDINGS.RSA_PKCS1_PADDING))

set_iteration(1000)

for _, op in ipairs({"encrypt", "decrypt"}) do 
    local _data = data
    if op == "decrypt" then
        _data = rsa_encrypted
    end

    local f = key[op]
    test("lua-resty-openssl RSA " .. op .. " on " .. #data .. " bytes", function()
        return f(key, _data)
    end)

    if not version.OPENSSL_3X then
        local pub = resty_rsa:new({ public_key = key:to_PEM("public"), padding = resty_rsa.PADDING.RSA_PKCS1_PADDING })
        local priv = resty_rsa:new({ private_key = key:to_PEM("private"), padding = resty_rsa.PADDING.RSA_PKCS1_PADDING }) 

        local _key = pub
        if op == "decrypt" then
            _key = priv
        end

        local f = _key[op]
        test("lua-resty-rsa RSA " .. op .." on " .. #data .. " bytes", function()
            return f(_key, _data)
        end)
    end

    if luaossl then
        local _key = require "_openssl.pkey".new(key:to_PEM("private"))
        local f = _key[op] 
        test("luaossl RSA " .. op .." on " .. #data .. " bytes", function()
            return f(_key, _data) 
        end)
    end


    if lua_openssl then
        local _key = lua_openssl.pkey.read(key:to_PEM("private"), true)
        local f = _key[op] 
        test("lua_openssl RSA " .. op .." on " .. #data .. " bytes", function()
            return f(_key, _data) 
        end)
    end

end

