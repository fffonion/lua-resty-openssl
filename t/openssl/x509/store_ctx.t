# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

my $use_luacov = $ENV{'TEST_NGINX_USE_LUACOV'} // '';

our $HttpConfig = qq{
    lua_package_path "$pwd/t/openssl/?.lua;$pwd/t/openssl/x509/?.lua;$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
    init_by_lua_block {
        if "1" == "$use_luacov" then
            require 'luacov.tick'
            jit.off()
        end
        _G.myassert = require("helper").myassert

        local x509 = require("resty.openssl.x509")
        local store = myassert(require("resty.openssl.x509.store").new())
        local partial_store = myassert(require("resty.openssl.x509.store").new())
        local f = io.open("t/fixtures/crl/rootca.cert.pem"):read("*a")
        local rootca = myassert(x509.new(f))
        local f = io.open("t/fixtures/crl/subca.cert.pem"):read("*a")
        local subca = myassert(x509.new(f))
        myassert(store:add(rootca))
        myassert(store:add(subca))
        -- only the subca
        myassert(partial_store:add(subca))
        _G.store = store
        _G.partial_store = partial_store

        local f = io.open("t/fixtures/crl/valid.cert.pem"):read("*a")
        local valid_cert = myassert(x509.new(f))
        local f = io.open("t/fixtures/crl/revoked.cert.pem"):read("*a")
        local revoked_cert = myassert(x509.new(f))
        local invalid_cert = require("helper").create_self_signed()
        _G.valid_cert = valid_cert
        _G.revoked_cert = revoked_cert
        _G.invalid_cert = invalid_cert

        local crl_lib = myassert(require("resty.openssl.x509.crl"))
        local f = io.open("t/fixtures/crl/crl.pem"):read("*a")
        local crl = myassert(crl_lib.new(f))
        _G.crl = crl
    }
};


run_tests();

__DATA__
=== TEST 1: Creates store_ctx properly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local ctx = myassert(require("resty.openssl.x509.store_ctx").new())
            myassert(ctx:init(store, valid_cert))
        }
    }
--- request
    GET /t
--- response_body eval
""
--- no_error_log
[error]


=== TEST 2: Verify against full chain store
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local lib = myassert(require("resty.openssl.x509.store_ctx"))
            local c1 = myassert(lib.new())
            local c2 = myassert(lib.new())
            myassert(c1:init(store, valid_cert))
            myassert(c2:init(store, invalid_cert))

            local ok, err = c1:verify()
            ngx.say(ok, err)

            local ok, err = c2:verify()
            ngx.say(ok, err)
        }
    }
--- request
    GET /t
--- response_body_like eval
"truenil
nil(?:self signed|self-signed) certificate
"
--- no_error_log
[error]


=== TEST 3: Verify against partial chain store
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local lib = myassert(require("resty.openssl.x509.store_ctx"))
            local c1 = myassert(lib.new())
            local c2 = myassert(lib.new())
            myassert(c1:init(partial_store, valid_cert))
            myassert(c2:init(partial_store, invalid_cert))

            local ok, err = c1:verify()
            ngx.say(ok, err)

            local ok, err = c2:verify()
            ngx.say(ok, err)
        }
    }
--- request
    GET /t
--- response_body_like eval
"nilunable to get issuer certificate
nil(?:self signed|self-signed) certificate
"
--- no_error_log
[error]


=== TEST 4: Verify against partial chain store (set flag X509_V_FLAG_PARTIAL_CHAIN)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local lib = myassert(require("resty.openssl.x509.store_ctx"))
            local c1 = myassert(lib.new())
            local c2 = myassert(lib.new())
            myassert(c1:init(partial_store, valid_cert))
            myassert(c2:init(partial_store, invalid_cert))
            myassert(c1:set_flags(c1.verify_flags.X509_V_FLAG_PARTIAL_CHAIN))
            myassert(c2:set_flags(c2.verify_flags.X509_V_FLAG_PARTIAL_CHAIN))

            local ok, err = c1:verify()
            ngx.say(ok, err)

            local ok, err = c2:verify()
            ngx.say(ok, err)
        }
    }
--- request
    GET /t
--- response_body_like eval
"truenil
nil(?:self signed|self-signed) certificate
"
--- no_error_log
[error]


=== TEST 5: Verify with set_purpose/set_default
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local lib = myassert(require("resty.openssl.x509.store_ctx"))
            local c1 = myassert(lib.new())
            local c2 = myassert(lib.new())
            local c3 = myassert(lib.new())
            myassert(c1:init(store, valid_cert))
            myassert(c2:init(store, valid_cert))
            myassert(c3:init(store, valid_cert))
            myassert(c1:set_default("ssl_server"))
            myassert(c2:set_default("default"))
            myassert(c3:set_default("default"))
            myassert(c3:set_purpose("sslserver"))

            local ok, err = c1:verify()
            ngx.say(ok, err)

            local ok, err = c2:verify()
            ngx.say(ok, err)

            local ok, err = c3:verify()
            ngx.say(ok, err)
        }
    }
--- request
    GET /t
--- response_body_like eval
"nil(?:unsupported|unsuitable) certificate purpose
truenil
nil(?:unsupported|unsuitable) certificate purpose
"
--- no_error_log
[error]


=== TEST 6: Verify against full chain store with crl file added in store
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local lib = myassert(require("resty.openssl.x509.store_ctx"))
            local c1 = myassert(lib.new())
            local c2 = myassert(lib.new())
            myassert(store:add(crl))
            myassert(c1:init(store, valid_cert))
            myassert(c2:init(store, revoked_cert))

            local ok, err = c1:verify()
            ngx.say(ok, err)

            local ok, err = c2:verify()
            ngx.say(ok, err)
        }
    }
--- request
    GET /t
--- response_body eval
"truenil
nilcertificate revoked
"
--- no_error_log
[error]


=== TEST 7: Verify against full chain store with crl file set in store_ctx
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local lib = myassert(require("resty.openssl.x509.store_ctx"))
            local crl_stack = myassert(require("resty.openssl.x509.crl_stack").new())
            myassert(crl_stack:add(crl))
            local c1 = myassert(lib.new())
            local c2 = myassert(lib.new())
            myassert(c1:init(store, valid_cert))
            myassert(c2:init(store, revoked_cert))
            myassert(c1:set_crls(crl_stack))
            myassert(c2:set_crls(crl_stack))

            local ok, err = c1:verify()
            ngx.say(ok, err)

            local ok, err = c2:verify()
            ngx.say(ok, err)
        }
    }
--- request
    GET /t
--- response_body eval
"truenil
nilcertificate revoked
"
--- no_error_log
[error]


=== TEST 8: Return chain after verifying success
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local lib = myassert(require("resty.openssl.x509.store_ctx"))
            local c1 = myassert(lib.new())
            local c2 = myassert(lib.new())
            myassert(c1:init(store, valid_cert))
            myassert(c2:init(store, invalid_cert))

            local chain = myassert(c1:verify(true))
            for _, c in ipairs(chain) do
                local n = myassert(c:get_serial_number())
                ngx.say(myassert(n:to_hex():upper()))
            end

            local chain, err = c2:verify(true)
            ngx.say(chain, err)
        }
    }
--- request
    GET /t
--- response_body_like eval
"2000
1000
256C40A9DE2B83C07822837355FDD514BD0BA0A6
nil(?:self signed|self-signed) certificate
"
--- no_error_log
[error]


=== TEST 9: Check revocation after verifying
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local lib = myassert(require("resty.openssl.x509.store_ctx"))
            local crl_stack = myassert(require("resty.openssl.x509.crl_stack").new())
            myassert(crl_stack:add(crl))
            local c1 = myassert(lib.new())
            local c2 = myassert(lib.new())
            local c3 = myassert(lib.new())

            myassert(c1:init(store, valid_cert))
            myassert(c2:init(store, revoked_cert))
            myassert(c3:init(store, invalid_cert))

            local ok, err = c1:verify()
            ngx.say(ok, err)

            myassert(c1:set_crls(crl_stack))
            local ok, err = c1:check_revocation()
            ngx.say(ok, err)

            local ok, err = c2:verify()
            ngx.say(ok, err)

            myassert(c2:set_crls(crl_stack))
            local ok, err = c2:check_revocation()
            ngx.say(ok, err)

            local ok, err = c3:verify()
            ngx.say(ok, err)

            myassert(c3:set_crls(crl_stack))
            local ok, err = c3:check_revocation()
            ngx.say(ok, err)
        }
    }
--- request
    GET /t
--- response_body_like eval
"truenil
truenil
truenil
nilcertificate revoked
nil(?:self signed|self-signed) certificate
nilx509.store_ctx:check_revocation: store_ctx isn't verified and verified_chain argument isn't passed
"
--- no_error_log
[error]
--- skip_openssl
3: < 1.1.0


=== TEST 10: Check revocation without verifying
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local lib = myassert(require("resty.openssl.x509.store_ctx"))
            local crl_stack = myassert(require("resty.openssl.x509.crl_stack").new())
            myassert(crl_stack:add(crl))
            local c1 = myassert(lib.new())
            local c2 = myassert(lib.new())
            local c3 = myassert(lib.new())
            local c4 = myassert(lib.new())

            myassert(c1:init(store, valid_cert))
            myassert(c2:init(store, revoked_cert))
            myassert(c3:init(store, valid_cert))
            myassert(c4:init(store, revoked_cert))

            -- to get the verified_chain first
            local chain1 = myassert(c1:verify(true))
            local chain2 = myassert(c2:verify(true))

            myassert(c3:set_crls(crl_stack))
            local ok, err = c3:check_revocation()
            ngx.say(ok, err)

            local ok, err = c3:check_revocation(chain1)
            ngx.say(ok, err)

            myassert(c4:set_crls(crl_stack))
            local ok, err = c4:check_revocation()
            ngx.say(ok, err)

            local ok, err = c4:check_revocation(chain2)
            ngx.say(ok, err)

        }
    }
--- request
    GET /t
--- response_body eval
"nilx509.store_ctx:check_revocation: store_ctx isn't verified and verified_chain argument isn't passed
truenil
nilx509.store_ctx:check_revocation: store_ctx isn't verified and verified_chain argument isn't passed
nilcertificate revoked
"
--- no_error_log
[error]
--- skip_openssl
3: < 1.1.0
