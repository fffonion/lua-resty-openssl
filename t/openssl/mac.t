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
=== TEST 1: Calculate hmac correctly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            if not require("resty.openssl.version").OPENSSL_30 then
                ngx.say("kwUMjYrP0BSJb8cIJvWYoiM1Kc4mQxZOTwSiTTLRhDM=")
                ngx.exit(0)
            end

            local hmac = myassert(require("resty.openssl.mac").new("goose", "HMAC", nil, "sha256"))

            myassert(hmac:update("🦢🦢🦢🦢🦢🦢"))
            ngx.print(ngx.encode_base64(myassert(hmac:final())))
        }
    }
--- request
    GET /t
--- response_body_like eval
"kwUMjYrP0BSJb8cIJvWYoiM1Kc4mQxZOTwSiTTLRhDM="
--- no_error_log
[error]

=== TEST 2: Update accepts vardiac args
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            if not require("resty.openssl.version").OPENSSL_30 then
                ngx.say("kwUMjYrP0BSJb8cIJvWYoiM1Kc4mQxZOTwSiTTLRhDM=")
                ngx.exit(0)
            end

            local hmac = myassert(require("resty.openssl.mac").new("goose", "HMAC", nil, "sha256"))

            hmac:update("🦢", "🦢🦢", "🦢🦢", "🦢")
            ngx.print(ngx.encode_base64(hmac:final()))
        }
    }
--- request
    GET /t
--- response_body_like eval
"kwUMjYrP0BSJb8cIJvWYoiM1Kc4mQxZOTwSiTTLRhDM="
--- no_error_log
[error]

=== TEST 3: Final accepts optional arg
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            if not require("resty.openssl.version").OPENSSL_30 then
                ngx.say("kwUMjYrP0BSJb8cIJvWYoiM1Kc4mQxZOTwSiTTLRhDM=")
                ngx.exit(0)
            end

            local hmac = myassert(require("resty.openssl.mac").new("goose", "HMAC", nil, "sha256"))

            myassert(hmac:update("🦢", "🦢🦢", "🦢🦢"))
            ngx.print(ngx.encode_base64(myassert(hmac:final("🦢"))))
        }
    }
--- request
    GET /t
--- response_body_like eval
"kwUMjYrP0BSJb8cIJvWYoiM1Kc4mQxZOTwSiTTLRhDM="
--- no_error_log
[error]

=== TEST 4: Rejects unknown hash
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            if not require("resty.openssl.version").OPENSSL_30 then
                ngx.say("mac.new: invalid cipher or digest type")
                ngx.exit(0)
            end
            local hmac, err = require("resty.openssl.mac").new("goose", "HMAC", nil, "sha257")
            ngx.print(err)
        }
    }
--- request
    GET /t
--- response_body_like eval
"mac.new: invalid cipher or digest type.*"
--- no_error_log
[error]

=== TEST 5: Returns provider
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            if not require("resty.openssl.version").OPENSSL_30 then
                ngx.say("default")
                ngx.exit(0)
            end

            local mac = require("resty.openssl.mac")
            local m = myassert(mac.new("goose", "HMAC", nil, "sha256"))
            ngx.say(myassert(m:get_provider_name()))
        }
    }
--- request
    GET /t
--- response_body
default
--- no_error_log
[error]
