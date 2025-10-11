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

=== TEST 1: memcmp: strings are equal
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local crypto = require("resty.openssl.crypto")
            ngx.print(crypto.memcmp("123", "123", 3))
        }
    }
--- request
    GET /t
--- response_body eval
0
--- no_error_log
[error]

=== TEST 2: memcmp: strings are same length but not equal
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local crypto = require("resty.openssl.crypto")
            ngx.print(crypto.memcmp("aaa", "123", 2))
        }
    }
--- request
    GET /t
--- response_body eval
1
--- no_error_log
[error]

=== TEST 3: memcmp: strings are different lengths
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local crypto = require("resty.openssl.crypto")
            ngx.print(crypto.memcmp("123123123123", "123", 12))
        }
    }
--- request
    GET /t
--- response_body eval
1
--- no_error_log
[error]

=== TEST 4: memcmp: invalid args
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local crypto = require("resty.openssl.crypto")
            local res, err = crypto.memcmp("123123123123", "123", -1)
            ngx.print(err)
        }
    }
--- request
    GET /t
--- response_body eval
"crypto:memcmp invalid args"
--- no_error_log
[error]
