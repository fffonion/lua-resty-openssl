# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/t/openssl/x509/?.lua;$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
};


run_tests();

__DATA__
=== TEST 1: Creates stack properly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local altname = require("resty.openssl.x509.altname")
            local c, err = altname.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(#c)
        }
    }
--- request
    GET /t
--- response_body eval
"0
"
--- no_error_log
[error]

=== TEST 2: Adds elements to stack properly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local altname = require("resty.openssl.x509.altname")
            local c, err = altname.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            for i=0,2,1 do
                local ok, err = c:add("DNS", string.format("%d.com", i))
                if err then
                    ngx.log(ngx.ERR, err)
                    return
                end
            end
            ngx.say(#c)
            ngx.say(#c:all())
        }
    }
--- request
    GET /t
--- response_body eval
"3
3
"
--- no_error_log
[error]

=== TEST 3: Element can be indexed properly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local altname = require("resty.openssl.x509.altname")
            local c, err = altname.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            for i=0,2,1 do
                local ok, err = c:add("DNS", string.format("%d.com", i))
                if err then
                    ngx.log(ngx.ERR, err)
                    return
                end
            end
            for k, v in pairs(c) do
                ngx.say(k, " ", v)
            end
        }
    }
--- request
    GET /t
--- response_body eval
"DNS 0.com
DNS 1.com
DNS 2.com
"
--- no_error_log
[error]

=== TEST 4: Element is duplicated when added to stack
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local altname = require("resty.openssl.x509.altname")
            local c, err = altname.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local ok, err = c:add("DNS", "example.com")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            cert = nil
            collectgarbage("collect")
            local k, v = unpack(c[1])
            ngx.say(k, " ", v)
        }
    }
--- request
    GET /t
--- response_body eval
"DNS example.com
"
--- no_error_log
[error]

=== TEST 5: Element is duplicated when returned
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local altname = require("resty.openssl.x509.altname")
            local c, err = altname.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local ok, err = c:add("DNS", "example.com")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local cc = c[1]
            c = nil
            collectgarbage("collect")
            local k, v = unpack(cc)
            ngx.say(k, " ", v)
        }
    }
--- request
    GET /t
--- response_body eval
"DNS example.com
"
--- no_error_log
[error]