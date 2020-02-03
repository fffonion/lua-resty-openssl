# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/t/openssl/x509/?.lua;$pwd/lib/?.lua;$pwd/lib/?/init.lua;$pwd/../lib/?.lua;$pwd/../lib/?/init.lua;;";
};

no_long_string();

run_tests();

__DATA__
=== TEST 1: Loads a crl
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local c, err = require("resty.openssl.x509.crl").new(f)
            if err then
                ngx.say(err)
                return
            end
            ngx.say("ok")
        }
    }
--- request
    GET /t
--- response_body eval
"ok
"
--- no_error_log
[error]

=== TEST 2: Converts and loads PEM format
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local c, err = require("resty.openssl.x509.crl").new(f)
            if err then
                ngx.say(err)
                return
            end
            local pem, err = c:tostring("PEM")
            if err then
                ngx.say(err)
                return
            end
            for _, typ in ipairs({"PEM", "*", false}) do
              local c2, err = require("resty.openssl.x509.crl").new(pem, typ)
              if err then
                  ngx.say(err)
                  return
              end
            end
            local c2, err = require("resty.openssl.x509.crl").new(pem, "DER")
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body_like eval
"x509.crl.new.+nested asn1 error.+"
--- no_error_log
[error]

=== TEST 3: Converts and loads DER format
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local c, err = require("resty.openssl.x509.crl").new(f)
            if err then
                ngx.say(err)
                return
            end
            local pem, err = c:tostring("DER")
            if err then
                ngx.say(err)
                return
            end
            for _, typ in ipairs({"DER", "*", false}) do
              local c2, err = require("resty.openssl.x509.crl").new(pem, typ)
              if err then
                  ngx.say(err)
                  return
              end
            end
            local c2, err = require("resty.openssl.x509.crl").new(pem, "PEM")
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body_like eval
"x509.crl.new.+no start line.+"
--- no_error_log
[error]

# START AUTO GENERATED CODE


=== TEST 4: x509.crl:get_issuer_name (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local c, err = require("resty.openssl.x509.crl").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_issuer_name()
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            get = get:_tostring()
            ngx.print(get)
        }
    }
--- request
    GET /t
--- response_body eval
"C=CN/CN=TrustAsia EV TLS Pro CA G2/O=TrustAsia Technologies, Inc."
--- no_error_log
[error]

=== TEST 5: x509.crl:set_issuer_name (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local c, err = require("resty.openssl.x509.crl").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            local toset = require("resty.openssl.x509.name").new():add('CN', 'earth.galaxy')
            local ok, err = c:set_issuer_name(toset)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_issuer_name()
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            get = get:_tostring()
            toset = toset:_tostring()
            if get ~= toset then
              ngx.say(get)
              ngx.say(toset)
            else
              ngx.print("ok")
            end
        }
    }
--- request
    GET /t
--- response_body eval
"ok"
--- no_error_log
[error]

=== TEST 4: x509.crl:get_last_update (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local c, err = require("resty.openssl.x509.crl").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_last_update()
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            ngx.print(get)
        }
    }
--- request
    GET /t
--- response_body eval
"1580684546"
--- no_error_log
[error]

=== TEST 5: x509.crl:set_last_update (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local c, err = require("resty.openssl.x509.crl").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            local toset = ngx.time()
            local ok, err = c:set_last_update(toset)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_last_update()
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            if get ~= toset then
              ngx.say(get)
              ngx.say(toset)
            else
              ngx.print("ok")
            end
        }
    }
--- request
    GET /t
--- response_body eval
"ok"
--- no_error_log
[error]

=== TEST 4: x509.crl:get_next_update (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local c, err = require("resty.openssl.x509.crl").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_next_update()
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            ngx.print(get)
        }
    }
--- request
    GET /t
--- response_body eval
"1581289346"
--- no_error_log
[error]

=== TEST 5: x509.crl:set_next_update (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local c, err = require("resty.openssl.x509.crl").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            local toset = ngx.time()
            local ok, err = c:set_next_update(toset)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_next_update()
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            if get ~= toset then
              ngx.say(get)
              ngx.say(toset)
            else
              ngx.print("ok")
            end
        }
    }
--- request
    GET /t
--- response_body eval
"ok"
--- no_error_log
[error]

=== TEST 4: x509.crl:get_version (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local c, err = require("resty.openssl.x509.crl").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_version()
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            ngx.print(get)
        }
    }
--- request
    GET /t
--- response_body eval
"2"
--- no_error_log
[error]

=== TEST 5: x509.crl:set_version (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local c, err = require("resty.openssl.x509.crl").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            local toset = ngx.time()
            local ok, err = c:set_version(toset)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_version()
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            if get ~= toset then
              ngx.say(get)
              ngx.say(toset)
            else
              ngx.print("ok")
            end
        }
    }
--- request
    GET /t
--- response_body eval
"ok"
--- no_error_log
[error]
# END AUTO GENERATED CODE