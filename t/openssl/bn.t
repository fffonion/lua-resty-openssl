# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
};

run_tests();

__DATA__
=== TEST 1: New BIGNUM instance correctly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local bn, err = require("resty.openssl.bn").new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local b, err = bn:to_binary()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.print(ngx.encode_base64(b))
        }
    }
--- request
    GET /t
--- response_body eval
""
--- error_log
bn:to_binary failed

=== TEST 2: New BIGNUM instance from number
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local bn, err = require("resty.openssl.bn").new(0x5b25)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local b, err = bn:to_binary()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.print(ngx.encode_base64(b))
        }
    }
--- request
    GET /t
--- response_body eval
"WyU="
--- no_error_log
[error]

=== TEST 3: Created using from_binary
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local d = ngx.decode_base64('WyU=')
            local bn, err = require("resty.openssl.bn").from_binary(d)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local b, err = bn:to_binary()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.print(ngx.encode_base64(b))
        }
    }
--- request
    GET /t
--- response_body eval
"WyU="
--- no_error_log
[error]

=== TEST 4: Duplicate the ctx
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            require('ffi').cdef('typedef struct bignum_st BIGNUM; void BN_free(BIGNUM *a);')
            local bn, err = require("resty.openssl.bn").new(0x5b25)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local bn2, err = require("resty.openssl.bn").dup(bn.ctx)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            require('ffi').C.BN_free(bn.ctx)
            local b, err = bn2:to_binary()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.print(ngx.encode_base64(b))
        }
    }
--- request
    GET /t
--- response_body eval
"WyU="
--- no_error_log
[error]

=== TEST 5: Export as hex string
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local bn, err = require("resty.openssl.bn").new(0x5b25)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local b, err = bn:to_hex()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.print(b)
        }
    }
--- request
    GET /t
--- response_body eval
"5B25"
--- no_error_log
[error]