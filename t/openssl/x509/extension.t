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
        _G.encode_sorted_json = require("helper").encode_sorted_json
    }
};


run_tests();

__DATA__
=== TEST 1: Creates extension by nconf
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local extension = require("resty.openssl.x509.extension")
            local c = myassert(extension.new("extendedKeyUsage",
                                        "serverAuth,clientAuth"))
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
            local c = myassert(extension.new("extendedKeyUsage",
                                        "serverAuth,clientAuth"))

            ngx.say(encode_sorted_json(myassert(c:get_object())))
        }
    }
--- request
    GET /t
--- response_body_like eval
'{"id":"2.5.29.37","ln":"X509v3 Extended Key Usage","nid":126,"sn":"extendedKeyUsage"}
'
--- no_error_log
[error]

=== TEST 3: Gets extension critical
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c = myassert(require("resty.openssl.x509").new(f))

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
            local c = myassert(extension.new("extendedKeyUsage",
                                        "serverAuth,clientAuth"))
            myassert(c:set_critical())
            ngx.say(c:get_critical())

            myassert(c:set_critical(true))
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
            local c = myassert(require("resty.openssl.x509").new(f))

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
            local x509 = myassert(require("resty.openssl.x509").new(f))

            local extension = require("resty.openssl.x509.extension")
            local c = myassert(extension.new("subjectKeyIdentifier", "hash",
                                        {
                                            subject = x509,
                                        }))

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
            local c = myassert(extension.from_data(altname, 85, false))

            ngx.say(encode_sorted_json(c:get_object()))
            ngx.say(tostring(c))
        }
    }
--- request
    GET /t
--- response_body_like eval
'{"id":"2.5.29.17","ln":"X509v3 Subject Alternative Name","nid":85,"sn":"subjectAltName"}
DNS:test.com, DNS:test2.com
'
--- no_error_log
[error]

=== TEST 8: Convert extension to data
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local altname = require("resty.openssl.x509.altname").new()
            altname:add("DNS", "test.com")
            altname:add("DNS", "test2.com")
            local extension = require("resty.openssl.x509.extension")
            local c = myassert(extension.from_data(altname, 85, false))

            local alt2 = myassert(extension.to_data(c, 85))
            ngx.say(alt2:tostring())
        }
    }
--- request
    GET /t
--- response_body_like eval
'DNS=test.com/DNS=test2.com
'
--- no_error_log
[error]

=== TEST 9: Creates extension by der
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local extension = require("resty.openssl.x509.extension")
            local c = myassert(extension.from_der("\x00\x01\x02\x03", "basicConstraints"))

            ngx.say(encode_sorted_json(c:get_object()))
        }
    }
--- request
    GET /t
--- response_body_like eval
'{"id":"2.5.29.19","ln":"X509v3 Basic Constraints","nid":87,"sn":"basicConstraints"}
'
--- no_error_log
[error]

=== TEST 10: Creates extension by nconf
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local extension = require("resty.openssl.x509.extension")
            local c = myassert(extension.new("certificatePolicies", "ia5org,1.2.3.4,1.5.6.7.8,@polsect",
                [[
                [polsect]
                policyIdentifier = 1.3.5.8
                CPS.1="http://my.host.name/"
                CPS.2="http://my.your.name/"
                userNotice.1=@notice

                [notice]
                explicitText="Explicit Text Here"
                organization="Organisation Name"
                noticeNumbers=1,2,3,4
                ]]
            ))

            ngx.say(encode_sorted_json(c:get_object()))
            ngx.say(tostring(c))
        }
    }
--- request
    GET /t
--- response_body_like eval
'{"id":"2.5.29.32","ln":"X509v3 Certificate Policies","nid":89,"sn":"certificatePolicies"}
Policy: 1.2.3.4
Policy: 1.5.6.7.8
Policy: 1.3.5.8
  CPS: http://my.host.name/
  CPS: http://my.your.name/
  User Notice:
    Organization: Organisation Name
    Numbers: 1, 2, 3, 4
    Explicit Text: Explicit Text Here
'
--- no_error_log
[error]