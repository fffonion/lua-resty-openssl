# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
};


run_tests();

__DATA__
=== TEST 1: Creates stack properly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local chain = require("resty.openssl.x509.chain")
            local c, err = chain.new()
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
            os.execute("openssl req -newkey rsa:2048 -nodes -keyout key2.pem -x509 -days 365 -out cert2.pem -subj '/'")
            local pem = io.open("cert2.pem"):read("*a")
            local x509 = require("resty.openssl.x509")
            local p, err = x509.new(pem)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local chain = require("resty.openssl.x509.chain")
            local c, err = chain.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            for i=0,2,1 do
                local ok, err = c:add(p)
                if err then
                    ngx.log(ngx.ERR, err)
                    return
                end
            end
            ngx.say(#c)
        }
    }
--- request
    GET /t
--- response_body eval
"3
"
--- no_error_log
[error]

=== TEST 3: Element can be indexed properly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            os.execute("openssl req -newkey rsa:2048 -nodes -keyout key3.pem -x509 -days 365 -out cert3.pem -subj '/'")
            local pem = io.open("cert3.pem"):read("*a")
            local x509 = require("resty.openssl.x509")
            local p, err = x509.new(pem)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local chain = require("resty.openssl.x509.chain")
            local c, err = chain.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            for i=0,2,1 do
                local ok, err = c:add(p)
                if err then
                    ngx.log(ngx.ERR, err)
                    return
                end
            end
            for _, cc in ipairs(c) do
                ngx.say(#cc:digest())
            end
        }
    }
--- request
    GET /t
--- response_body eval
"20
20
20
"
--- no_error_log
[error]

=== TEST 4: Element is duplicated when added to stack
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            os.execute("openssl req -newkey rsa:2048 -nodes -keyout key4.pem -x509 -days 365 -out cert4.pem -subj '/'")
            local pem = io.open("cert4.pem"):read("*a")
            local x509 = require("resty.openssl.x509")
            local p, err = x509.new(pem)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local chain = require("resty.openssl.x509.chain")
            local c, err = chain.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local ok, err = c:add(p)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            p = nil
            collectgarbage("collect")
            ngx.say(#c[1]:digest())
        }
    }
--- request
    GET /t
--- response_body eval
"20
"
--- no_error_log
[error]

=== TEST 5: Element is duplicated when returned
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            os.execute("openssl req -newkey rsa:2048 -nodes -keyout key5.pem -x509 -days 365 -out cert5.pem -subj '/'")
            local pem = io.open("cert5.pem"):read("*a")
            local x509 = require("resty.openssl.x509")
            local p, err = x509.new(pem)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local chain = require("resty.openssl.x509.chain")
            local c, err = chain.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local ok, err = c:add(p)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local cc = c[1]
            c = nil
            collectgarbage("collect") 
            ngx.say(#cc:digest())
        }
    }
--- request
    GET /t
--- response_body eval
"20
"
--- no_error_log
[error]