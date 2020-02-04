# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

my $use_luacov = $ENV{'TEST_NGINX_USE_LUACOV'} // '';

our $HttpConfig = qq{
    lua_package_path "$pwd/t/openssl/x509/?.lua;$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
    init_by_lua_block {
        if "1" == "$use_luacov" then
            require 'luacov.tick'
            jit.off()
        end
    }
};

no_long_string();

run_tests();

__DATA__
=== TEST 1: Loads a cert
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
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
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
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
              local c2, err = require("resty.openssl.x509").new(pem, typ)
              if err then
                  ngx.say(err)
                  return
              end
            end
            local c2, err = require("resty.openssl.x509").new(pem, "DER")
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body_like eval
"x509.new.+nested asn1 error.+"
--- no_error_log
[error]

=== TEST 3: Converts and loads DER format
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
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
              local c2, err = require("resty.openssl.x509").new(pem, typ)
              if err then
                  ngx.say(err)
                  return
              end
            end
            local c2, err = require("resty.openssl.x509").new(pem, "PEM")
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body_like eval
"x509.new.+no start line.+"
--- no_error_log
[error]

=== TEST 4: Rejectes invalid cert
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
x509.new: .*not enough data
"
--- no_error_log
[error]

=== TEST 5: Calculates cert digest
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

=== TEST 6: Calculates pubkey digest
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

=== TEST 7: Gets extension
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

=== TEST 8: Adds extension
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

=== TEST 9: Set extension
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


=== TEST 10: Reads basic constraints
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

=== TEST 11: Set basic constraints
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

=== TEST 12: Get authority info access
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

=== TEST 13: Set authority info access
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

=== TEST 14: Get CRL distribution points
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

=== TEST 15: Set CRL distribution points
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

=== TEST 16: Get OCSP url
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

=== TEST 17: Get CRL url
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

# START AUTO GENERATED CODE


=== TEST 18: x509:get_serial_number (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_serial_number()
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            get = get:to_hex()
            ngx.print(get)
        }
    }
--- request
    GET /t
--- response_body eval
"0A0630427F5BBCED6957396593B6451F"
--- no_error_log
[error]

=== TEST 19: x509:set_serial_number (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            local toset = require("resty.openssl.bn").new(math.random(1, 2333333))
            local ok, err = c:set_serial_number(toset)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_serial_number()
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            get = get:to_hex()
            toset = toset:to_hex()
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

=== TEST 18: x509:get_not_before (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_not_before()
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
"1525737600"
--- no_error_log
[error]

=== TEST 19: x509:set_not_before (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            local toset = ngx.time()
            local ok, err = c:set_not_before(toset)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_not_before()
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

=== TEST 18: x509:get_not_after (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_not_after()
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
"1591185600"
--- no_error_log
[error]

=== TEST 19: x509:set_not_after (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            local toset = ngx.time()
            local ok, err = c:set_not_after(toset)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_not_after()
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

=== TEST 18: x509:get_pubkey (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_pubkey()
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            get = get:to_PEM()
            ngx.print(get)
        }
    }
--- request
    GET /t
--- response_body eval
"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxjyq8jyXDDrBTyitcnB9
0865tWBzpHSbindG/XqYQkzFMBlXmqkzC+FdTRBYyneZw5Pz+XWQvL+74JW6LsWN
c2EF0xCEqLOJuC9zjPAqbr7uroNLghGxYf13YdqbG5oj/4x+ogEG3dF/U5YIwVr6
58DKyESMV6eoYV9mDVfTuJastkqcwero+5ZAKfYVMLUEsMwFtoTDJFmVf6JlkOWw
sxp1WcQ/MRQK1cyqOoUFUgYylgdh3yeCDPeF22Ax8AlQxbcaI+GwfQL1FB7Jy+h+
KjME9lE/UpgV6Qt2R1xNSmvFCBWu+NFX6epwFP/JRbkMfLz0beYFUvmMgLtwVpEP
SwIDAQAB
-----END PUBLIC KEY-----
"
--- no_error_log
[error]

=== TEST 19: x509:set_pubkey (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            local toset = require("resty.openssl.pkey").new()
            local ok, err = c:set_pubkey(toset)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_pubkey()
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            get = get:to_PEM()
            toset = toset:to_PEM()
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

=== TEST 18: x509:get_subject_name (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_subject_name()
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
"C=US/CN=github.com/L=San Francisco/O=GitHub, Inc./ST=California/businessCategory=Private Organization/jurisdictionC=US/jurisdictionST=Delaware/serialNumber=5157550"
--- no_error_log
[error]

=== TEST 19: x509:set_subject_name (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            local toset = require("resty.openssl.x509.name").new():add('CN', 'earth.galaxy')
            local ok, err = c:set_subject_name(toset)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_subject_name()
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

=== TEST 18: x509:get_issuer_name (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
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
"C=US/CN=DigiCert SHA2 Extended Validation Server CA/O=DigiCert Inc/OU=www.digicert.com"
--- no_error_log
[error]

=== TEST 19: x509:set_issuer_name (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
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

=== TEST 18: x509:get_version (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
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
"3"
--- no_error_log
[error]

=== TEST 19: x509:set_version (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
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

=== TEST 18: x509:get_subject_alt_name (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_subject_alt_name()
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
"DNS=www.github.com"
--- no_error_log
[error]

=== TEST 19: x509:set_subject_alt_name (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            local toset = require("resty.openssl.x509.altname").new():add('DNS', 'earth.galaxy')
            local ok, err = c:set_subject_alt_name(toset)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local get, err = c:get_subject_alt_name()
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

=== TEST 21: x509:get/set_subject_alt_name_critical (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)

            local crit, err = c:get_subject_alt_name_critical()
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local ok, err = c:set_subject_alt_name_critical(not crit)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            ngx.say(c:get_subject_alt_name_critical() == not crit)
        }
    }
--- request
    GET /t
--- response_body
true
--- no_error_log
[error]

=== TEST 19: x509:get/set_basic_constraints_critical (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)

            local crit, err = c:get_basic_constraints_critical()
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local ok, err = c:set_basic_constraints_critical(not crit)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            ngx.say(c:get_basic_constraints_critical() == not crit)
        }
    }
--- request
    GET /t
--- response_body
true
--- no_error_log
[error]

=== TEST 19: x509:get/set_info_access_critical (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)

            local crit, err = c:get_info_access_critical()
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local ok, err = c:set_info_access_critical(not crit)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            ngx.say(c:get_info_access_critical() == not crit)
        }
    }
--- request
    GET /t
--- response_body
true
--- no_error_log
[error]

=== TEST 19: x509:get/set_crl_distribution_points_critical (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/Github.pem"):read("*a")
            local c, err = require("resty.openssl.x509").new(f)

            local crit, err = c:get_crl_distribution_points_critical()
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end

            local ok, err = c:set_crl_distribution_points_critical(not crit)
            if err then
              ngx.log(ngx.ERR, err)
              ngx.exit(0)
            end
            ngx.say(c:get_crl_distribution_points_critical() == not crit)
        }
    }
--- request
    GET /t
--- response_body
true
--- no_error_log
[error]
# END AUTO GENERATED CODE