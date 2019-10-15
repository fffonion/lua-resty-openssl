# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
};

run_tests();

__DATA__
=== TEST 1: Generates RSA key by default
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = require("resty.openssl.pkey").new()
            ngx.say(p:to_PEM('private'))
        }
    }
--- request
    GET /t
--- response_body_like eval
"-----BEGIN PRIVATE KEY-----"
--- no_error_log
[error]

=== TEST 2: Generates RSA key explictly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = require("resty.openssl.pkey").new({
                type = 'RSA',
                bits = 2048,
            })
            ngx.say(p:to_PEM('private'))
        }
    }
--- request
    GET /t
--- response_body_like eval
"-----BEGIN PRIVATE KEY-----"
--- no_error_log
[error]

=== TEST 3: Generates EC key
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = require("resty.openssl.pkey").new({
                type = 'EC',
                curve = 'prime256v1',
            })
            ngx.say(p:to_PEM('private'))
        }
    }
--- request
    GET /t
--- response_body_like eval
"-----BEGIN PRIVATE KEY-----"
--- no_error_log
[error]

=== TEST 4: Rejects invalid arg
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local pkey = require("resty.openssl.pkey")
            local p, err = pkey.new(123)
            ngx.say(err)
            local p, err = pkey.new('PRIVATE KEY')
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body_like eval
"unexpected type.+
pkey.new:load_pkey: .+
"
--- no_error_log
[error]

=== TEST 5: Loads PEM format
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local pkey = require("resty.openssl.pkey")
            local p1, err = pkey.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local p2, err = pkey.new(p1:to_PEM('private'))
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.print(p1:to_PEM('private') == p2:to_PEM('private'))
        }
    }
--- request
    GET /t
--- response_body eval
"true"
--- no_error_log
[error]

=== TEST 6: Loads DER format
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local pkey = require("resty.openssl.pkey")
            local p1, err = pkey.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local pem = p1:to_PEM('private')
            local der, err = require("ngx.ssl").priv_key_pem_to_der(pem)
            local p2, err = pkey.new(der)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.print(p2 and pem == p2:to_PEM('private'))
        }
    }
--- request
    GET /t
--- response_body eval
"true"
--- no_error_log
[error]

=== TEST 7: Extracts parameters
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p, err = require("resty.openssl.pkey").new({
                exp = 65537,
            })
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local params, err = p:get_parameters()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(params.d ~= nil)
            ngx.say(params.e ~= nil)
            ngx.say(params.n ~= nil)
            ngx.say(ngx.encode_base64(params.e:to_binary()))
        }
    }
--- request
    GET /t
--- response_body eval
"true
true
true
AQAB
"
--- no_error_log
[error]

=== TEST 8: Sign and verify
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p, err = require("resty.openssl.pkey").new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            
            local digest, err = require("resty.openssl.digest").new("SHA256")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            err = digest:update("🕶️", "+1s")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local s, err = p:sign(digest)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(#s)
            local v, err = p:verify(s, digest)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(v)
        }
    }
--- request
    GET /t
--- response_body eval
"256
true
"
--- no_error_log
[error]

=== TEST 9: Bail on bad digest or verify parameters
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p, err = require("resty.openssl.pkey").new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end

            local s, err = p:sign("not a cdata")
            ngx.say(err)
            local v, err = p:verify(s, "not a cdata")
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body eval
"expect a digest instance at #1
expect a digest instance at #2
"
--- no_error_log
[error]

=== TEST 10: Outputs public key
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p, err = require("resty.openssl.pkey").new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(p:to_PEM())
        }
    }
--- request
    GET /t
--- response_body_like eval
"-----BEGIN PUBLIC KEY-----"
--- no_error_log
[error]