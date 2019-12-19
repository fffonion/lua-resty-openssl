# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
};

run_tests();

__DATA__
=== TEST 1: Creates cipher correctly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local cipher, err = require("resty.openssl.cipher").new("aes256")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local ok, err = cipher:init(string.rep("0", 32), string.rep("0", 16), {
                is_encrypt = true,
            })
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.print(ngx.encode_base64(cipher:final('1')))
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
"invalid cipher type \"aes257\""
--- no_error_log
[error]

=== TEST 3: Unintialized ctx throw errors
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local cipher, err = require("resty.openssl.cipher").new("aes256")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local s, err = cipher:update("1")
            ngx.say(err)
            local _, err = cipher:final("1")
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body eval
"cipher not initalized, call cipher:init first
cipher not initalized, call cipher:init first
"
--- no_error_log
[error]

=== TEST 4: Encrypt
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local cipher, err = require("resty.openssl.cipher").new("aes256")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local s, err = cipher:encrypt(string.rep("0", 32), string.rep("0", 16), '1')
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
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
            local cipher, err = require("resty.openssl.cipher").new("aes256")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local s, err = cipher:encrypt(string.rep("0", 32), string.rep("0", 16), '1', {
                    no_padding = true,
                })
            ngx.say(s)
            ngx.say(err)
            local s, err = cipher:encrypt(string.rep("0", 32), string.rep("0", 16),
                '1' .. string.rep(string.char(15), 15), {
                    no_padding = true,
                })
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
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
            local cipher, err = require("resty.openssl.cipher").new("aes256")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local s, err = cipher:decrypt(string.rep("0", 32), string.rep("0", 16),
                ngx.decode_base64("VhGyRCcMvlAgUjTYrqiWpg=="))
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
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
            local cipher, err = require("resty.openssl.cipher").new("aes256")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local s, err = cipher:decrypt(string.rep("0", 32), string.rep("0", 16),
                ngx.decode_base64("VhGyRCcMvlAgUjTYrqiWpg=="), {
                    no_padding = true,
                })
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
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
            local cipher, err = require("resty.openssl.cipher").new("aes256")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local ok, err = cipher:init(string.rep("0", 32), string.rep("0", 16), {
                is_encrypt = true,
            })
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local sample = 'abcdefghi'
            local count = 5
            for i=1,count,1 do
                local s, err = cipher:update(sample)
                if err then
                    ngx.log(ngx.ERR, err)
                    return
                end
                if s ~= "" then
                    ngx.say(ngx.encode_base64(s))
                else
                    ngx.say("nothing")
                end
            end
            local s, err = cipher:final()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
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
            local cipher, err = require("resty.openssl.cipher").new("aes256")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local ok, err = cipher:init(string.rep("0", 32), string.rep("0", 16), {
                is_encrypt = false,
            })
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local input = ngx.decode_base64('SEk81GpcHC9KoZfN14RrNg==') ..
                            ngx.decode_base64('L2dVbLMhEigy917CJBXz7g==') ..
                            ngx.decode_base64('yP4vKOecDyao4AzxaTAzkA==')
            local count = 5
            local len = (#input - #input % count) / count
            for i=0,#input-len,len do
                local s, err = cipher:update(string.sub(input, i+1, i+len))
                if err then
                    ngx.log(ngx.ERR, err)
                    return
                end
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
            local s, err = cipher:final(string.sub(input, #input -#input % count + 1, #input))
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
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