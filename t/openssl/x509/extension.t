# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/t/openssl/x509/?.lua;$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
};


run_tests();

__DATA__
=== TEST 1: Creates extension by nconf
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local extension = require("resty.openssl.x509.extension")
            local c, err = extension.new("extendedKeyUsage",
                                        "serverAuth,clientAuth")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
        }
    }
--- request
    GET /t
--- no_error_log
[error]

=== TEST 2: Gets extension object
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local extension = require("resty.openssl.x509.extension")
            local c, err = extension.new("extendedKeyUsage",
                                        "serverAuth,clientAuth")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(require("cjson").encode(c:get_object()))
        }
    }
--- request
    GET /t
--- response_body_like eval
'{"ln":"X509v3 Extended Key Usage","nid":126,"sn":"extendedKeyUsage","id":"2.5.29.37"}
'
--- no_error_log
[error]

=== TEST 3: Gets extension critical
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local extension, _, err = c:get_extension("X509v3 Key Usage")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(extension:get_critical())
            local extension, _, err = c:get_extension("X509v3 Extended Key Usage")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(extension:get_critical())
        }
    }
--- request
    GET /t
--- response_body_like eval
"true
false
"
--- no_error_log
[error]

=== TEST 4: Set extension critical
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local extension = require("resty.openssl.x509.extension")
            local c, err = extension.new("extendedKeyUsage",
                                        "serverAuth,clientAuth")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ok, err = c:set_critical()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(c:get_critical())
            ok, err = c:set_critical(true)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(c:get_critical())
        }
    }
--- request
    GET /t
--- response_body_like eval
"false
true
"
--- no_error_log
[error]

=== TEST 5: Prints human readable txt of extension
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local extension, _, err = c:get_extension("subjectKeyIdentifier")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(extension:text())
            local extension, _, err = c:get_extension("Authority Information Access")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(tostring(extension))
        }
    }
--- request
    GET /t
--- response_body_like eval
"C9:C2:53:61:66:9D:5F:AB:25:F4:26:CD:0F:38:9A:A8:49:EA:48:A9
OCSP - URI:http://ocsp.digicert.com
CA Issuers - URI:http://cacerts.digicert.com/DigiCertSHA2ExtendedValidationServerCA.crt
"
--- no_error_log
[error]

=== TEST 6: Creates extension by X509V3_CTX
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local x509, err = require("resty.openssl.x509").new(f)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local extension = require("resty.openssl.x509.extension")
            local c, err = extension.new("subjectKeyIdentifier", "hash",
                                        {
                                            subject = x509,
                                        })
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(tostring(c))
        }
    }
--- request
    GET /t
--- response_body_like eval
"C9:C2:53:61:66:9D:5F:AB:25:F4:26:CD:0F:38:9A:A8:49:EA:48:A9
"
--- no_error_log
[error]

=== TEST 7: Creates extension by data
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local altname = require("resty.openssl.x509.altname").new()
            altname:add("DNS", "test.com")
            altname:add("DNS", "test2.com")
            local extension = require("resty.openssl.x509.extension")
            local c, err = extension.from_data(altname, 85, false)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(require("cjson").encode(c:get_object()))
            ngx.say(tostring(c))
        }
    }
--- request
    GET /t
--- response_body_like eval
'{"ln":"X509v3 Subject Alternative Name","nid":85,"sn":"subjectAltName","id":"2.5.29.17"}
DNS:test.com, DNS:test2.com
'
--- no_error_log
[error]
