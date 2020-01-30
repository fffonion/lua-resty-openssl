# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/t/openssl/x509/?.lua;$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
};


run_tests();

__DATA__
=== TEST 1: Creates store properly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local store = require("resty.openssl.x509.store")
            local c, err = store.new()
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


=== TEST 2: Loads a x509 object
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local cert, key = require("helper").create_self_signed()
            local store = require("resty.openssl.x509.store")
            local s, err = store.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local ok, err = s:add(cert)
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

=== TEST 3: Loads default location
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local store = require("resty.openssl.x509.store")
            local s, err = store.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local ok, err = s:use_default()
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

=== TEST 4: Loads file
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local store = require("resty.openssl.x509.store")
            local s, err = store.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local ok, err = s:load_file("certnonexistent.pem")
            ngx.say(ok)
            ngx.say(err)
            os.execute("echo > cert4-empty.pem")
            local ok, err = s:load_file("cert4-empty.pem")
            ngx.say(ok)
            -- we only get detailed error for "no certificate found" on >= 1.1.1
            ngx.say(err)
            os.remove("cert4-empty.pem")
            os.execute("openssl req -newkey rsa:2048 -nodes -keyout key4.pem -x509 -days 365 -out cert4.pem -subj '/'")
            local ok, err = s:load_file("cert4.pem")
            os.remove("cert4.pem")
            os.remove("key4.pem")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
        }
    }
--- request
    GET /t
--- response_body_like eval
"false
store:load_file.+system library.+
false
store:load_file.+
"
--- no_error_log
[error]


=== TEST 5: Verifies a x509 object
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local cert1, key1 = require("helper").create_self_signed()
            local cert2, key2 = require("helper").create_self_signed()
            local cert3, key3 = require("helper").create_self_signed()
            local store = require("resty.openssl.x509.store")
            local s, err = store.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local ok, err = s:add(cert1)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local ok, err = s:add(cert2)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local chain, err = s:verify(cert1, nil, true)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(#chain)
            local chain, err = s:verify(cert3, nil, true)
            ngx.say(err)
            ngx.say(chain == nil)
        }
    }
--- request
    GET /t
--- response_body_like eval
"1
self signed certificate
true
"
--- no_error_log
[error]


=== TEST 6: Using default CAs (skip due to hard to setup on custom-built openssl env)
--- SKIP
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local store = require("resty.openssl.x509.store")
            local s, err = store.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local ok, err = s:use_default()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local f = io.open("t/fixtures/GlobalSign.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)

            local chain, err = s:verify(c, nil, true)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(#chain)
        }
    }
--- request
    GET /t
--- response_body_like eval
"1
"
--- no_error_log
[error]

=== TEST 7: Loads directory
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local store = require("resty.openssl.x509.store")
            local s, err = store.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local ok, err = s:load_directory("/etc/ssl/certs")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local f = io.open("t/fixtures/GlobalSign.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)

            local chain, err = s:verify(c, nil, true)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(#chain)
        }
    }
--- request
    GET /t
--- response_body_like eval
"1
"
--- no_error_log
[error]

=== TEST 8: Verifies sub cert
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local helper = require("helper")
            local x509 = require("resty.openssl.x509")
            local store = require("resty.openssl.x509.store")
            local s, err = store.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local f = io.open("t/fixtures/GlobalSign.pem"):read("*a")
            local c, err = x509.new(f)
            ngx.say(helper.to_hex(c:digest()))

            local chain, err = s:add(c)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end

            local f = io.open("t/fixtures/GlobalSign_sub.pem"):read("*a")
            local c, err = x509.new(f)
            ngx.say(helper.to_hex(c:digest()))

            local chain, err = s:verify(c, nil, true)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            for _, c in ipairs(chain) do
                ngx.say(helper.to_hex(c:digest()))
            end
        }
    }
--- request
    GET /t
--- response_body eval
"B1BC968BD4F49D622AA89A81F2150152A41D829C
C187B85714202A2941E8EAFB846C39EB1F9C609A
C187B85714202A2941E8EAFB846C39EB1F9C609A
B1BC968BD4F49D622AA89A81F2150152A41D829C
"
--- no_error_log
[error]