# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

my $use_luacov = $ENV{'TEST_NGINX_USE_LUACOV'} // '';

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
    init_by_lua_block {
        if "1" == "$use_luacov" then
            require 'luacov.tick'
            jit.off()
        end
    }
};

run_tests();

__DATA__
=== TEST 1: Calculate hmac correctly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local hmac, err = require("resty.openssl.hmac").new("goose", "sha256")
            assert(err == nil)
            hmac:update("🦢🦢🦢🦢🦢🦢")
            ngx.print(ngx.encode_base64(hmac:final()))
        }
    }
--- request
    GET /t
--- response_body eval
"kwUMjYrP0BSJb8cIJvWYoiM1Kc4mQxZOTwSiTTLRhDM="
--- no_error_log
[error]

=== TEST 2: Update accepts vardiac args
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local hmac, err = require("resty.openssl.hmac").new("goose", "sha256")
            assert(err == nil)
            hmac:update("🦢", "🦢🦢", "🦢🦢", "🦢")
            ngx.print(ngx.encode_base64(hmac:final()))
        }
    }
--- request
    GET /t
--- response_body eval
"kwUMjYrP0BSJb8cIJvWYoiM1Kc4mQxZOTwSiTTLRhDM="
--- no_error_log
[error]

=== TEST 3: Final accepts optional arg
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local hmac, err = require("resty.openssl.hmac").new("goose", "sha256")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            hmac:update("🦢", "🦢🦢", "🦢🦢")
            ngx.print(ngx.encode_base64(hmac:final("🦢")))
        }
    }
--- request
    GET /t
--- response_body eval
"kwUMjYrP0BSJb8cIJvWYoiM1Kc4mQxZOTwSiTTLRhDM="
--- no_error_log
[error]

=== TEST 4: Rejects unknown hash
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local hmac, err = require("resty.openssl.hmac").new("goose", "sha257")
            ngx.print(err)
        }
    }
--- request
    GET /t
--- response_body eval
"invalid digest type \"sha257\""
--- no_error_log
[error]