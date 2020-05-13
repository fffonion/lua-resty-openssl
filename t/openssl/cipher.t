# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

my $use_luacov = $ENV{'TEST_NGINX_USE_LUACOV'} // '';

our $HttpConfig = qq{
    lua_package_path "$pwd/t/openssl/?.lua;$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
    init_by_lua_block {
        if "1" == "$use_luacov" then
            require 'luacov.tick'
            jit.off()
        end
        _G.myassert = require("helper").myassert
    }
};

run_tests();

__DATA__
=== TEST 1: Creates cipher correctly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local cipher = myassert(require("resty.openssl.cipher").new("aes256"))

            myassert(cipher:init(string.rep("0", 32), string.rep("0", 16), {
                is_encrypt = true,
            }))

            ngx.print(ngx.encode_base64(myassert(cipher:final('1'))))
        }
    }
--- request
    GET /t
--- response_body eval
"VhGyRCcMvlAgUjTYrqiWpg=="
--- no_error_log
[error]


=== TEST 2: Rejects unknown cipher
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local cipher, err = require("resty.openssl.cipher").new("aes257")
            ngx.print(err)
        }
    }
--- request
    GET /t
--- response_body eval
"cipher.new: invalid cipher type \"aes257\""
--- no_error_log
[error]

=== TEST 3: Unintialized ctx throw errors
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local cipher = myassert(require("resty.openssl.cipher").new("aes256"))

            local s, err = cipher:update("1")
            ngx.say(err)
            local _, err = cipher:final("1")
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body eval
"cipher:update: cipher not initalized, call cipher:init first
cipher:update: cipher not initalized, call cipher:init first
"
--- no_error_log
[error]

=== TEST 4: Encrypt
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local cipher = myassert(require("resty.openssl.cipher").new("aes256"))

            local s = myassert(cipher:encrypt(string.rep("0", 32), string.rep("0", 16), '1'))

            ngx.print(ngx.encode_base64(s))
        }
    }
--- request
    GET /t
--- response_body eval
"VhGyRCcMvlAgUjTYrqiWpg=="
--- no_error_log
[error]

=== TEST 5: Encrypt no padding
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local cipher = myassert(require("resty.openssl.cipher").new("aes256"))

            local s, err = cipher:encrypt(string.rep("0", 32), string.rep("0", 16), '1', {
                    no_padding = true,
                })
            ngx.say(s)
            ngx.say(err)
            local s = myassert(cipher:encrypt(string.rep("0", 32), string.rep("0", 16),
                '1' .. string.rep(string.char(15), 15), {
                    no_padding = true,
                }))
            ngx.print(ngx.encode_base64(s))
        }
    }
--- request
    GET /t
--- response_body_like eval
"nil
.+data not multiple of block length
VhGyRCcMvlAgUjTYrqiWpg=="
--- no_error_log
[error]

=== TEST 6: Decrypt
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local cipher = myassert(require("resty.openssl.cipher").new("aes256"))

            local s = myassert(cipher:decrypt(string.rep("0", 32), string.rep("0", 16),
                ngx.decode_base64("VhGyRCcMvlAgUjTYrqiWpg==")))

            ngx.print(s)
        }
    }
--- request
    GET /t
--- response_body eval
"1"
--- no_error_log
[error]

=== TEST 7: Decrypt no padding
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local cipher = myassert(require("resty.openssl.cipher").new("aes256"))

            local s = myassert(cipher:decrypt(string.rep("0", 32), string.rep("0", 16),
                ngx.decode_base64("VhGyRCcMvlAgUjTYrqiWpg=="), {
                    no_padding = true,
                }))

            ngx.print(s)
        }
    }
--- request
    GET /t
--- response_body eval
"1\x{0f}\x{0f}\x{0f}\x{0f}\x{0f}\x{0f}\x{0f}\x{0f}\x{0f}\x{0f}\x{0f}\x{0f}\x{0f}\x{0f}\x{0f}"
--- no_error_log
[error]

=== TEST 8: Encrypt streaming
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local cipher = myassert(require("resty.openssl.cipher").new("aes256"))

            local ok = myassert(cipher:init(string.rep("0", 32), string.rep("0", 16), {
                is_encrypt = true,
            }))

            local sample = 'abcdefghi'
            local count = 5
            for i=1,count,1 do
                local s = myassert(cipher:update(sample))

                if s ~= "" then
                    ngx.say(ngx.encode_base64(s))
                else
                    ngx.say("nothing")
                end
            end
            local s = myassert(cipher:final())

            ngx.say(ngx.encode_base64(s))
        }
    }
--- request
    GET /t
--- response_body eval
"nothing
SEk81GpcHC9KoZfN14RrNg==
nothing
L2dVbLMhEigy917CJBXz7g==
nothing
yP4vKOecDyao4AzxaTAzkA==
"
--- no_error_log
[error]

=== TEST 9: Decrypt streaming
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local cipher = myassert(require("resty.openssl.cipher").new("aes256"))

            local ok = myassert(cipher:init(string.rep("0", 32), string.rep("0", 16), {
                is_encrypt = false,
            }))

            local input = ngx.decode_base64('SEk81GpcHC9KoZfN14RrNg==') ..
                            ngx.decode_base64('L2dVbLMhEigy917CJBXz7g==') ..
                            ngx.decode_base64('yP4vKOecDyao4AzxaTAzkA==')
            local count = 5
            local len = (#input - #input % count) / count
            for i=0,#input-len,len do
                local s = myassert(cipher:update(string.sub(input, i+1, i+len)))

                if s ~= "" then
                    ngx.say(s)
                else
                    ngx.say("nothing")
                end
            end
            -- this should throw error since we end in the middle
            local s, err = cipher:final()
            ngx.say(err)
            ngx.say(s)
            -- feed the last chunk of input
            local s = myassert(cipher:final(string.sub(input, #input -#input % count + 1, #input)))

            ngx.say(s)
        }
    }
--- request
    GET /t
--- response_body_like eval
"nothing
abcdefghiabcdefg
nothing
hiabcdefghiabcde
nothing
.+wrong final block length
nil
fghiabcdefghi
"
--- no_error_log
[error]


=== TEST 10: Derive key and iv
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            function string.tohex(str)
                return (str:gsub('.', function (c)
                    return string.format('%02X', string.byte(c))
                end))
            end

            local cipher = myassert(require("resty.openssl.cipher").new("aes256"))

            -- openssl enc -aes256 -pass pass:xxx -S 797979 -P -md md5
            local key, iv = cipher:derive("xxx", "yyy", 1, "md5")

            ngx.say(key:tohex())
            ngx.say(iv:tohex())

            local cipher = myassert(require("resty.openssl.cipher").new("aes-256-ecb"))

            -- openssl enc -aes-256-ecb -pass pass:xxx -S 797979 -P -md md5
            local key, iv = cipher:derive("xxx", "yyy", 1, "md5")
            ngx.say(key:tohex())
            ngx.say(iv:tohex() == "" and "no iv")
        }
    }
--- request
    GET /t
--- response_body eval
"1F94CD004791ECFD50955451ACDA89D2CF1B4BCC6A378E4FC5C5861BDED17F61
FE91AF7782EDB48F32775BB2B72DD5ED
1F94CD004791ECFD50955451ACDA89D2CF1B4BCC6A378E4FC5C5861BDED17F61
no iv
"
--- no_error_log
[error]

=== TEST 11: Derive key and iv: salt, count and md is optional
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            function string.tohex(str)
                return (str:gsub('.', function (c)
                    return string.format('%02X', string.byte(c))
                end))
            end

            local cipher = myassert(require("resty.openssl.cipher").new("aes256"))

            -- openssl enc -aes256 -pass pass:xxx -nosalt -P -md sha1
            local key, iv = cipher:derive("xxx")

            ngx.say(key:tohex())
            ngx.say(iv:tohex())
        }
    }
--- request
    GET /t
--- response_body eval
"B60D121B438A380C343D5EC3C2037564B82FFEF3542808AB5694FA93C3179140
20578C4FEF1AEE907B1DC95C776F8160
"
--- no_error_log
[error]

=== TEST 12: AEAD modes
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local myassert = require("helper").myassert
            local key = string.rep("0", 32)
            local iv = string.rep("0", 12)
            local aad = "an aad"
            local cipher = require("resty.openssl.cipher")

            local enc = myassert(cipher.new("aes-256-gcm"))
            local d = myassert(enc:encrypt(key, iv, "secret", false, aad))
            local tag = myassert(enc:get_aead_tag())

            local dec = myassert(cipher.new("aes-256-gcm"))
            local s = myassert(dec:decrypt(key, iv, d, false, aad, tag))
            ngx.say(s)

            local dec = myassert(cipher.new("aes-256-gcm"))
            local r, err = dec:decrypt(key, iv, d, false, nil, tag)
            ngx.say(r)

            local dec = myassert(cipher.new("aes-256-gcm"))
            local r, err = dec:decrypt(key, iv, d, false, aad, nil)
            ngx.say(r)

        }
    }
--- request
    GET /t
--- response_body eval
"secret
nil
nil
"
--- no_error_log
[error]