# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/t/openssl/x509/?.lua;$pwd/lib/?.lua;$pwd/lib/?/init.lua;$pwd/../lib/?.lua;$pwd/../lib/?/init.lua;;";
};


run_tests();

__DATA__
=== TEST 1: Duplicate the ctx
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            require('ffi').cdef('typedef struct X509_name_st X509_NAME; void X509_NAME_free(X509_NAME *name);')
            local name, err = require("resty.openssl.x509.name").new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local name2, err = require("resty.openssl.x509.name").dup(name.ctx)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            require('ffi').C.X509_NAME_free(name.ctx)
            -- if name2.ctx is also freed this following will segfault
            local _, err = name2:add("CN", "example.com")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
        }
    }
--- request
    GET /t
--- response_body eval
""
--- no_error_log
[error]

=== TEST 2: Rejects invalid NID
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local name, err = require("resty.openssl.x509.name").new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            name, err = name:add("whatever", "value")
            ngx.say(name == nil)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body eval
"true
invalid NID text whatever
"
--- no_error_log
[error]