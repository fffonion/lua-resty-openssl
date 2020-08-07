# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

my $use_luacov = $ENV{'TEST_NGINX_USE_LUACOV'} // '';

our $HttpConfig = qq{
    lua_package_path "$pwd/t/openssl/?.lua;$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
    init_by_lua_block {
        if "1" == "$use_luacov" then
            require 'luacov.tick'
            jit.off()
        end
        _G.myassert = require("helper").myassert
    }
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
            local c = myassert(require("resty.openssl.x509.crl").new(f))

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
            local c = myassert(require("resty.openssl.x509.crl").new(f))

            local pem = myassert(c:tostring("PEM"))

            for _, typ in ipairs({"PEM", "*", false}) do
              local c2 = myassert(require("resty.openssl.x509.crl").new(pem, typ))
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
            local c = myassert(require("resty.openssl.x509.crl").new(f))

            local pem = myassert(c:tostring("DER"))

            for _, typ in ipairs({"DER", "*", false}) do
              local c2 = myassert(require("resty.openssl.x509.crl").new(pem, typ))
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

=== TEST 4: x509.crl:add_revoked should add revoked to crl
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local revoked =  myassert(require("resty.openssl.x509.revoked"))
            local c = myassert(require("resty.openssl.x509.crl").new(f))
            local toset = ngx.time()
            local r, err = revoked.new(1234, toset, 1)
            if err then
              ngx.say(err)
              return
            end
            if not revoked.istype(r) then
             ngx.say("it should be instance of revoked")
             return
            end

            local ok = myassert(c:add_revoked(r))
            if ok ~= true then
              ngx.say("Could not add revoked")
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

=== TEST 5: x509.crl:add_revoked should fail if revoked is not instance of revoked
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local revoked =  myassert(require("resty.openssl.x509.revoked"))
            local c = myassert(require("resty.openssl.x509.crl").new(f))

            local ok, err = c:add_revoked({ctx ={}})
            if ok ~= false then
                ngx.say("false")
            elseif err ~= "x509.crl:add_revoked: expect a revoked instance at #1" then
                ngx.say("false")
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


=== TEST 6: x509.crl:sign should succeed
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local revoked =  myassert(require("resty.openssl.x509.revoked"))
            local c = myassert(require("resty.openssl.x509.crl").new(f))
            local toset = ngx.time()
            local r, err = revoked.new(1234, toset, 1)
            c:add_revoked(r)

            local d = myassert(require("resty.openssl.digest").new("SHA256"))
            local p = myassert(require("resty.openssl.pkey").new())
            local ok = myassert(c:sign(p, d))
            if ok == false then
                ngx.say("false")
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
# START AUTO GENERATED CODE


=== TEST 7: x509.crl:get_issuer_name (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local c = myassert(require("resty.openssl.x509.crl").new(f))

            local get = myassert(c:get_issuer_name())
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

=== TEST 8: x509.crl:set_issuer_name (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local c = myassert(require("resty.openssl.x509.crl").new(f))
            local toset = require("resty.openssl.x509.name").new():add('CN', 'earth.galaxy')
            local ok = myassert(c:set_issuer_name(toset))

            local get = myassert(c:get_issuer_name())
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

=== TEST 9: x509.crl:get_last_update (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local c = myassert(require("resty.openssl.x509.crl").new(f))

            local get = myassert(c:get_last_update())
            ngx.print(get)
        }
    }
--- request
    GET /t
--- response_body eval
"1580684546"
--- no_error_log
[error]

=== TEST 10: x509.crl:set_last_update (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local c = myassert(require("resty.openssl.x509.crl").new(f))
            local toset = ngx.time()
            local ok = myassert(c:set_last_update(toset))

            local get = myassert(c:get_last_update())
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

=== TEST 11: x509.crl:get_next_update (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local c = myassert(require("resty.openssl.x509.crl").new(f))

            local get = myassert(c:get_next_update())
            ngx.print(get)
        }
    }
--- request
    GET /t
--- response_body eval
"1581289346"
--- no_error_log
[error]

=== TEST 12: x509.crl:set_next_update (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local c = myassert(require("resty.openssl.x509.crl").new(f))
            local toset = ngx.time()
            local ok = myassert(c:set_next_update(toset))

            local get = myassert(c:get_next_update())
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

=== TEST 13: x509.crl:get_version (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local c = myassert(require("resty.openssl.x509.crl").new(f))

            local get = myassert(c:get_version())
            ngx.print(get)
        }
    }
--- request
    GET /t
--- response_body eval
"2"
--- no_error_log
[error]

=== TEST 14: x509.crl:set_version (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local c = myassert(require("resty.openssl.x509.crl").new(f))
            local toset = ngx.time()
            local ok = myassert(c:set_version(toset))

            local get = myassert(c:get_version())
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
