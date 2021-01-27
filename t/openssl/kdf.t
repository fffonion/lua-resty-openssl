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

run_tests();

__DATA__
=== TEST 1: kdf: invalid args are checked
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local kdf = require("resty.openssl.kdf")
            local key, err = kdf.derive({
            })
            ngx.say(err)
            local key, err = kdf.derive({
                type = "no",
            })
            ngx.say(err)
            local key, err = kdf.derive({
                type = kdf.PBKDF2,
            })
            ngx.say(err)
            local key, err = kdf.derive({
                type = kdf.PBKDF2,
                outlen = 16,
                pass = 123,
            })
            ngx.say(err)
            local key, err = kdf.derive({
                type = 19823718236128631,
                outlen = 16,
                pass = "123",
            })
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body_like eval
"kdf.derive: \"type\" must be set
kdf.derive: expect a number as \"type\"
kdf.derive: \"outlen\" must be set
kdf.derive: except a string as \"pass\"
kdf.derive: unknown type 19823718236128632
"
--- no_error_log
[error]


=== TEST 2: PBKDF2
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local kdf = require("resty.openssl.kdf")
            local key = myassert(kdf.derive({
                type = kdf.PBKDF2,
                outlen = 16,
                pass = "1234567",
                pbkdf2_iter = 1000,
                md = "md5",
            }))

            ngx.print(ngx.encode_base64(key))
        }
    }
--- request
    GET /t
--- response_body_like eval
"cDRFLQ7NWt\\+AP4i0TdBzog=="
--- no_error_log
[error]


=== TEST 3: PBKDF2, optional args
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local kdf = require("resty.openssl.kdf")
            local key = myassert(kdf.derive({
                type = kdf.PBKDF2,
                outlen = 16,
            }))

            ngx.print(ngx.encode_base64(key))
        }
    }
--- request
    GET /t
--- response_body_like eval
"HkN6HHnXW\\+YekRQdriCv/A=="
--- no_error_log
[error]


=== TEST 4: HKDF
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            if require("resty.openssl.version").BORINGSSL then
                ngx.print("aqRd+gO5Ok3YneDEormTcg==")
                ngx.exit(0)
            end
            local kdf = require("resty.openssl.kdf")
            local key = myassert(kdf.derive({
                type = kdf.HKDF,
                outlen = 16,
                md = "md5",
                salt = "salt",
                hkdf_key = "secret",
                hkdf_info = "some info",
                hkdf_mode = kdf.HKDEF_MODE_EXTRACT_AND_EXPAND,
            }))

            ngx.print(ngx.encode_base64(key))
        }
    }
--- request
    GET /t
--- skip_openssl
2: < 1.1.0
--- response_body eval
"aqRd+gO5Ok3YneDEormTcg=="
--- no_error_log
[error]


=== TEST 5: HKDF, optional arg
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            if require("resty.openssl.version").BORINGSSL then
                ngx.say("aggdq4eoqRiP0Z3GbpxCjg==")
                ngx.say("W/tSxFnNsHIYwXa13eybYhW9W3Y=")
                ngx.exit(0)
            end
            local version_num = require("resty.openssl.version").version_num
            local kdf = require("resty.openssl.kdf")
            local key = myassert(kdf.derive({
                type = kdf.HKDF,
                outlen = 16,
                salt = "salt",
                hkdf_key = "secret",
                hkdf_info = "info",
            }))

            ngx.say(ngx.encode_base64(key))

            if version_num < 0x10101000 then
                ngx.say("W/tSxFnNsHIYwXa13eybYhW9W3Y=")
                ngx.exit(0)
            end
            local key = myassert(kdf.derive({
                type = kdf.HKDF,
                outlen = 16,
                salt = "salt",
                hkdf_key = "secret",
                hkdf_mode = kdf.HKDEF_MODE_EXTRACT_ONLY,
            }))

            ngx.say(ngx.encode_base64(key))
        }
    }
--- request
    GET /t
--- skip_openssl
2: < 1.1.0
--- response_body_like eval
"aggdq4eoqRiP0Z3GbpxCjg==
W/tSxFnNsHIYwXa13eybYhW9W3Y=
"
--- no_error_log
[error]


=== TEST 6: TLS1-PRF
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            if require("resty.openssl.version").BORINGSSL then
                ngx.print("0xr8qthU+ypv2xRC90la8g==")
                ngx.exit(0)
            end
            local kdf = require("resty.openssl.kdf")
            local key = myassert(kdf.derive({
                type = kdf.TLS1_PRF,
                outlen = 16,
                md = "md5",
                tls1_prf_secret = "secret",
                tls1_prf_seed = "seed",
            }))

            ngx.print(ngx.encode_base64(key))
        }
    }
--- request
    GET /t
--- skip_openssl
2: < 1.1.0
--- response_body_like eval
"0xr8qthU\\+ypv2xRC90la8g=="
--- no_error_log
[error]


=== TEST 7: TLS1-PRF, optional arg
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            if require("resty.openssl.version").BORINGSSL then
                ngx.print("XVVDK9/puTqBOsyTKt8PKQ==")
                ngx.exit(0)
            end
            local kdf = require("resty.openssl.kdf")
            local key = myassert(kdf.derive({
                type = kdf.TLS1_PRF,
                outlen = 16,
                tls1_prf_secret = "secret",
                tls1_prf_seed = "seed",
            }))

            ngx.print(ngx.encode_base64(key))
        }
    }
--- request
    GET /t
--- skip_openssl
2: < 1.1.0
--- response_body_like eval
"XVVDK9/puTqBOsyTKt8PKQ=="
--- no_error_log
[error]


=== TEST 8: scrypt
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            if require("resty.openssl.version").BORINGSSL then
                ngx.print("9giFtxace5sESmRb8qxuOw==")
                ngx.exit(0)
            end
            local kdf = require("resty.openssl.kdf")
            local key = myassert(kdf.derive({
                type = kdf.SCRYPT,
                outlen = 16,
                pass = "1234567",
                scrypt_N = 1024,
                scrypt_r = 8,
                scrypt_p = 16,
            }))

            ngx.print(ngx.encode_base64(key))
        }
    }
--- request
    GET /t
--- skip_openssl
2: < 1.1.0
--- response_body_like eval
"9giFtxace5sESmRb8qxuOw=="
--- no_error_log
[error]
