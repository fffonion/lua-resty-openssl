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

=== TEST 1: memcmp: memory regions are equal
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local crypto = require("resty.openssl.crypto")
            local buffer = require("string.buffer")
            local res, err

            res, err = crypto.memcmp("abc", "abc", 3)
            ngx.say(res)
            ngx.say(err)

            res, err = crypto.memcmp(100, 100, #buffer.encode(100))
            ngx.say(res)
            ngx.say(err)

            local table_a = { "a", b=1, 101 }
            local table_b = { "a", b=1, 101 }
            res, err = crypto.memcmp(table_a, table_b, #buffer.encode(table_a))
            ngx.say(res)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
0
nil
0
nil
0
nil
--- no_error_log
[error]

=== TEST 2: memcmp: memory regions are not equal
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local crypto = require("resty.openssl.crypto")
            local buffer = require("string.buffer")
            local res, err

            res, err = crypto.memcmp("abc", "acc", 3)
            ngx.say(res)
            ngx.say(err)

            res, err = crypto.memcmp(100, 102, #buffer.encode(100))
            ngx.say(res)
            ngx.say(err)

            local table_a = { "a", b=1, 101 }
            local table_b = { "a", b=1, 102 }
            res, err = crypto.memcmp(table_a, table_b, #buffer.encode(table_a))
            ngx.say(res)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
1
nil
1
nil
1
nil
--- no_error_log
[error]

=== TEST 3: memcmp: invalid len arg
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local crypto = require("resty.openssl.crypto")
            local res, err = crypto.memcmp("123123123123", "123", -1)
            ngx.say(res)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
nil
crypto:memcmp arg 'len' must be a number > 0
--- no_error_log
[error]
