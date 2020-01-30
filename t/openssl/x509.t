# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/t/openssl/x509/?.lua;$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
};


run_tests();

__DATA__
=== TEST 1: Loads a pem cert
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            if err then
                ngx.say("1 " .. err)
                ngx.exit(0)
            end
            local not_before, not_after, err = c:get_lifetime()
            if err then
                ngx.say("2 " .. err)
                ngx.exit(0)
            end
            ngx.say(not_before)
            ngx.say(not_after)
        }
    }
--- request
    GET /t
--- response_body eval
"1525737600
1591185600
"
--- no_error_log
[error]

=== TEST 2: Rejectes invalid cert
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local x509 = require("resty.openssl.x509")
            local p, err = x509.new(true)
            ngx.say(err)
            p, err = x509.new("222")
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body_like eval
"expect nil or a string at #1
x509.new: .*ASN1_get_object:header too long
"
--- no_error_log
[error]


=== TEST 3: Exports public key
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local c, key = require("helper").create_self_signed()
            local p, err = c:get_pubkey()
            if err then
                ngx.say("2 " .. err)
                ngx.exit(0)
            end
            ngx.say(p:to_PEM():sub(1, 26))
            ngx.print(c:get_pubkey():to_PEM() == key:to_PEM("public"))
        }
    }
--- request
    GET /t
--- response_body eval
"-----BEGIN PUBLIC KEY-----
true"
--- no_error_log
[error]


=== TEST 4: Calculates cert digest
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/GlobalSign.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            local dd, err = c:digest()
            if err then
                ngx.say("2 " .. err)
                ngx.exit(0)
            end
            local h, err = require("helper").to_hex(dd)
            ngx.say(h)
        }
    }
--- request
    GET /t
--- response_body eval
"B1BC968BD4F49D622AA89A81F2150152A41D829C
"
--- no_error_log
[error]

=== TEST 5: Calculates pubkey digest
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/GlobalSign.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            local dd, err = c:pubkey_digest()
            if err then
                ngx.say("2 " .. err)
                ngx.exit(0)
            end
            local h, err = require("helper").to_hex(dd)
            ngx.say(h)
        }
    }
--- request
    GET /t
--- response_body eval
"607B661A450D97CA89502F7D04CD34A8FFFCFD4B
"
--- no_error_log
[error]

=== TEST 6: Gets extension
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            local ext, pos, err = c:get_extension("X509v3 Extended Key Usage")
            if err then
                ngx.say(err)
                ngx.exit(0)
            end
            ngx.say(pos)
            ngx.say(tostring(ext))
        }
    }
--- request
    GET /t
--- response_body eval
"5
TLS Web Server Authentication, TLS Web Client Authentication
"
--- no_error_log
[error]

=== TEST 7: Adds extension
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local c, err = require("resty.openssl.x509").new()
            local ext, err = require("resty.openssl.x509.extension").new(
                "extendedKeyUsage", "TLS Web Server Authentication"
            )
            if err then
                ngx.say(err)
                ngx.exit(0)
            end
            local ok, err = c:add_extension(ext)
            if err then
                ngx.say(err)
                ngx.exit(0)
            end
            local ext, _, err = c:get_extension("X509v3 Extended Key Usage")
            if err then
                ngx.say(err)
                ngx.exit(0)
            end
            ngx.say(tostring(ext))
        }
    }
--- request
    GET /t
--- response_body eval
"TLS Web Server Authentication
"
--- no_error_log
[error]

=== TEST 8: Set extension
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/GlobalSign.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            local ext, err = require("resty.openssl.x509.extension").new(
                "keyUsage", "Digital Signature, Key Encipherment"
            )
            local ok, err = c:set_extension(ext)
            if err then
                ngx.say(err)
                ngx.exit(0)
            end
            local ext, _, err = c:get_extension("X509v3 Key Usage")
            if err then
                ngx.say(err)
                ngx.exit(0)
            end
            ngx.say(tostring(ext))
        }
    }
--- request
    GET /t
--- response_body eval
"Digital Signature, Key Encipherment
"
--- no_error_log
[error]


=== TEST 9: Reads basic constraints
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/GlobalSign.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            ngx.say(c:get_basic_constraints("ca"))
            ngx.say(c:get_basic_constraints("pathlen"))
            collectgarbage("collect")
        }
    }
--- request
    GET /t
--- response_body eval
"true
0
"
--- no_error_log
[error]

=== TEST 10: Set basic constraints
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/GlobalSign.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            local ok, err = c:set_basic_constraints({
                CA = false,
                pathLen = 233,
            })
            if err then ngx.log(ngx.ERR, err) end
            ngx.say(c:get_basic_constraints("ca"))
            ngx.say(c:get_basic_constraints("pathlen"))
            collectgarbage("collect")
        }
    }
--- request
    GET /t
--- response_body eval
"false
233
"
--- no_error_log
[error]

=== TEST 11: Reads basic constraints critical
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/GlobalSign.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            ngx.say(c:get_basic_constraints_critical())
            collectgarbage("collect")
        }
    }
--- request
    GET /t
--- response_body eval
"true
"
--- no_error_log
[error]

=== TEST 12: Set basic constraints critical
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/GlobalSign.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            local ok, err = c:set_basic_constraints_critical(false)
            if err then ngx.log(ngx.ERR, err) end
            ngx.say(c:get_basic_constraints_critical())
            collectgarbage("collect")
        }
    }
--- request
    GET /t
--- response_body eval
"false
"
--- no_error_log
[error]


=== TEST 13: Get subject alt name
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            local altnames, err = c:get_subject_alt_name()
            if err then ngx.log(ngx.ERR, err) end
            for k, v in pairs(altnames) do
                ngx.say(k, " ", v)
            end
            collectgarbage("collect")
        }
    }
--- request
    GET /t
--- response_body eval
"DNS github.com
DNS www.github.com
"
--- no_error_log
[error]

=== TEST 14: Set subject alt name
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            local altnames, err = c:get_subject_alt_name()
            if err then ngx.log(ngx.ERR, err) end
            local _, err = altnames:add("DNS", "subdomain.github.com")
            if err then ngx.log(ngx.ERR, err) end
            ok, err = c:set_subject_alt_name(altnames)
            if err then ngx.log(ngx.ERR, err) end
            altnames, err = c:get_subject_alt_name()
            for k, v in pairs(altnames) do
                ngx.say(k, " ", v)
            end
            collectgarbage("collect")
        }
    }
--- request
    GET /t
--- response_body eval
"DNS github.com
DNS www.github.com
DNS subdomain.github.com
"
--- no_error_log
[error]

=== TEST 15: Get authority info access
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            local aia, err = c:get_info_access()
            if err then ngx.log(ngx.ERR, err) end
            local ffi = require "ffi"
            for _, v in ipairs(aia) do
                ngx.say(ffi.string(ffi.C.OBJ_nid2ln(v[1])), " - ", v[2], ":", v[3])
            end
            collectgarbage("collect")
        }
    }
--- request
    GET /t
--- response_body eval
"OCSP - URI:http://ocsp.digicert.com
CA Issuers - URI:http://cacerts.digicert.com/DigiCertSHA2ExtendedValidationServerCA.crt
"
--- no_error_log
[error]

=== TEST 16: Set authority info access
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            local aia, err = c:get_info_access()
            local _, err = aia:add("OCSP", "URI", "http://somedomain.com")
            if err then ngx.log(ngx.ERR, err) end
            ok, err = c:set_info_access(aia)
            if err then ngx.log(ngx.ERR, err) end
            local aia, err = c:get_info_access()
            local ffi = require "ffi"
            for _, v in ipairs(aia) do
                ngx.say(ffi.string(ffi.C.OBJ_nid2ln(v[1])), " - ", v[2], ":", v[3])
            end
            collectgarbage("collect")
        }
    }
--- request
    GET /t
--- response_body eval
"OCSP - URI:http://ocsp.digicert.com
CA Issuers - URI:http://cacerts.digicert.com/DigiCertSHA2ExtendedValidationServerCA.crt
OCSP - URI:http://somedomain.com
"
--- no_error_log
[error]

=== TEST 17: Get CRL distribution points
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            local cdp, err = c:get_crl_distribution_points()
            if err then ngx.log(ngx.ERR, err) end
            local ffi = require "ffi"
            for _, altname in pairs(cdp) do
                for k, v in pairs(altname) do
                    ngx.say(k, " ", v)
                end
            end
            collectgarbage("collect")
        }
    }
--- request
    GET /t
--- response_body eval
"URI http://crl3.digicert.com/sha2-ev-server-g2.crl
URI http://crl4.digicert.com/sha2-ev-server-g2.crl
"
--- no_error_log
[error]

=== TEST 18: Set CRL distribution points
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            -- NYI
        }
    }
--- request
    GET /t
--- no_error_log
[error]

=== TEST 19: Get OCSP url
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)

            local ocsp, err = c:get_ocsp_url()
            if err then ngx.log(ngx.ERR, err) end
            ngx.say(ocsp)

            local ocsp, err = c:get_ocsp_url(true)
            if err then ngx.log(ngx.ERR, err) end
            ngx.say(require("cjson").encode(ocsp))
        }
    }
--- request
    GET /t
--- response_body eval
'http://ocsp.digicert.com
["http:\/\/ocsp.digicert.com"]
'
--- no_error_log
[error]

=== TEST 20: Get CRL url
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)

            local crl, err = c:get_crl_url()
            if err then ngx.log(ngx.ERR, err) end
            ngx.say(crl)

            local crl, err = c:get_crl_url(true)
            if err then ngx.log(ngx.ERR, err) end
            ngx.say(require("cjson").encode(crl))
        }
    }
--- request
    GET /t
--- response_body eval
'http://crl3.digicert.com/sha2-ev-server-g2.crl
["http:\/\/crl3.digicert.com\/sha2-ev-server-g2.crl","http:\/\/crl4.digicert.com\/sha2-ev-server-g2.crl"]
'
--- no_error_log
[error]