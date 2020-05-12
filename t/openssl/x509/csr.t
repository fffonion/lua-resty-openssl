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
=== TEST 1: Loads a csr
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/test.csr"):read("*a")
            local c, err = require("resty.openssl.x509.csr").new(f)
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
            local f = io.open("t/fixtures/test.csr"):read("*a")
            local c, err = require("resty.openssl.x509.csr").new(f)
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
              local c2, err = require("resty.openssl.x509.csr").new(pem, typ)
              if err then
                  ngx.say(err)
                  return
              end
            end
            local c2, err = require("resty.openssl.x509.csr").new(pem, "DER")
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body_like eval
"x509.csr.new.+nested asn1 error.+"
--- no_error_log
[error]

=== TEST 3: Converts and loads DER format
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/test.csr"):read("*a")
            local c, err = require("resty.openssl.x509.csr").new(f)
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
              local c2, err = require("resty.openssl.x509.csr").new(pem, typ)
              if err then
                  ngx.say(err)
                  return
              end
            end
            local c2, err = require("resty.openssl.x509.csr").new(pem, "PEM")
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body_like eval
"x509.csr.new.+no start line.+"
--- no_error_log
[error]

=== TEST 4: Generates CSR with RSA pkey correctly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local util = require("csr")
            local pkey = require("resty.openssl.pkey").new()
            local der, err = util.create_csr(pkey, "dns1.com", "dns2.com", "dns3.com")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.update_time()
            local fname = "ci_" .. math.floor(ngx.now() * 1000)
            local f = io.open(fname, "wb")
            f:write(der)
            f:close()
            ngx.say(io.popen("openssl req -inform der -in " .. fname .. " -noout -text", 'r'):read("*a"))
            os.remove(fname)
        }
    }
--- request
    GET /t
--- response_body_like eval
".+CN\\s*=\\s*dns1.com.+rsaEncryption.+2048 bit.+DNS:dns1.com.+DNS:dns2.com.+DNS:dns3.com"
--- no_error_log
[error]

=== TEST 5: Rejects invalid arguments
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local csr = require("resty.openssl.x509.csr").new()
            ok, err = csr:set_subject_name("not a subject")
            ngx.say(err)
            ok, err = csr:set_subject_alt_name("not an alt")
            ngx.say(err)
            ok, err = csr:set_pubkey("not a pkey")
            ngx.say(err)
            ok, err = csr:sign("not a pkey")
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body eval
"x509.csr:set_subject_name: expect a x509.name instance at #1
x509.csr:set_subject_alt_name: expect a x509.altname instance at #1
x509.csr:set_pubkey: expect a pkey instance at #1
x509.csr:sign: expect a pkey instance at #1
"
--- no_error_log
[error]

# START AUTO GENERATED CODE


=== TEST 6: x509.csr:get_subject_name (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/test.csr"):read("*a")
            local c, err = require("resty.openssl.x509.csr").new(f)
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
"C=US/CN=test.mars/L=San Francisco/O=Mars Co./OU=Terraforming Department/ST=California"
--- no_error_log
[error]

=== TEST 7: x509.csr:set_subject_name (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/test.csr"):read("*a")
            local c, err = require("resty.openssl.x509.csr").new(f)
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

=== TEST 8: x509.csr:get_pubkey (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/test.csr"):read("*a")
            local c, err = require("resty.openssl.x509.csr").new(f)
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
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy00jcwmJKMr9+/RwQd0G
CAvw685rqAJD1uKuBotlHTeN95xHI+xZCsRpFblAdhtaDb5Xlc33Fn+cjJ8nF2WS
1HslaZVM51m3sePsDlufBuVCKh+7KqQk64pNejYBasSR+jG7WWEjivR8yclQouJZ
T7WaF6SEET2dxiqXWAWmSbT4J3heP4b3xAAEqsa9kZJX9vQNOB5mqOyvrtqlULNm
WJkKjf8gOtuZePfopEHuyUK2YGVBHCciIfHKeBsIPc2EMajEZYSl0N5/1i4zFxdU
XlLP/qQqafrc2noEz6lv5LXbK2v4T05/5L+klJzcVnCnWnVsaYAUkaEJ5kNyIHpU
AQIDAQAB
-----END PUBLIC KEY-----
"
--- no_error_log
[error]

=== TEST 9: x509.csr:set_pubkey (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/test.csr"):read("*a")
            local c, err = require("resty.openssl.x509.csr").new(f)
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

=== TEST 10: x509.csr:get_version (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/test.csr"):read("*a")
            local c, err = require("resty.openssl.x509.csr").new(f)
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
"1"
--- no_error_log
[error]

=== TEST 11: x509.csr:set_version (AUTOGEN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/test.csr"):read("*a")
            local c, err = require("resty.openssl.x509.csr").new(f)
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