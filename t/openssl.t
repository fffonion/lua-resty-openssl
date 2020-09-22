# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

my $use_luacov = $ENV{'TEST_NGINX_USE_LUACOV'} // '';

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;$pwd/lib/?/init.lua;$pwd/../lua-resty-hmac/lib/?.lua;$pwd/../lua-resty-string/lib/?.lua;;";
    init_by_lua_block {
        if "1" == "$use_luacov" then
            require 'luacov.tick'
            jit.off()
        end
    }
};

run_tests();

__DATA__
=== TEST 1: Load ffi openssl library
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local openssl = require("resty.openssl")
            ngx.say(string.format("%x", openssl.version.version_num))
        }
    }
--- request
    GET /t
--- response_body_like
\d{6}[0-9a-f][0f]
--- no_error_log
[error]


=== TEST 2: Luaossl compat pattern
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local openssl = require("resty.openssl")
            openssl.luaossl_compat()
            local pkey = require("resty.openssl.pkey")
            local pok, perr = pcall(pkey.new, "not a key")
            ngx.say(pok)
            ngx.say(perr)
        }
    }
--- request
    GET /t
--- response_body_like
false
.+pkey.new.+
--- no_error_log
[error]

=== TEST 3: lua-resty-hmac compat
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local openssl = require("resty.openssl")
            require("resty.openssl.hmac")
            local pok, perr = pcall(require, "resty.hmac")
            ngx.say(pok)
            ngx.say(perr)
            openssl.resty_hmac_compat()
            local pok, perr = pcall(require, "resty.hmac")
            ngx.say(pok)
            ngx.say(perr)
        }
    }
--- request
    GET /t
--- skip_openssl
2: < 1.1.0
--- response_body_like
false
.+size of C type is unknown or too large.+
true
null
--- no_error_log
[error]