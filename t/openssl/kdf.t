# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

my $use_luacov = $ENV{'TEST_NGINX_USE_LUACOV'} // '';

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
    init_by_lua_block {
        if "1" == "$use_luacov" then
            require 'luacov.tick'
            jit.off()
        end
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
                type = "PBKDF2",
            })
            ngx.say(err)
            local key, err = kdf.derive({
                type = "PBKDF2",
                outlen = 16,
                pass = 123,
            })
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body_like eval
"\"type\" must be set
invalid NID text no
\"outlen\" must be set
except a string as \"pass\"
"
--- no_error_log
[error]


=== TEST 2: PBKDF2
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local kdf = require("resty.openssl.kdf")
            local key, err = kdf.derive({
                type = "PBKDF2",
                outlen = 16,
                pass = "1234567",
                pbkdf2_iter = 1000,
                md = "md5",
            })
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
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
            local key, err = kdf.derive({
                type = "PBKDF2",
                outlen = 16,
            })
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
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
            local version_num = require("resty.openssl.version").version_num
            if version_num < 0x10100000 then
                ngx.say("tIBQd46amKgA6uRytksrXA==")
                ngx.exit(0)
            end
            local kdf = require("resty.openssl.kdf")
            local key, err = kdf.derive({
                type = "HKDF",
                outlen = 16,
                md = "md5",
                hkdf_key = "secret",
                hkdf_info = "some info",
                hkdf_mode = kdf.HKDEF_MODE_EXTRACT_AND_EXPAND,
            })
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.print(ngx.encode_base64(key))
        }
    }
--- request
    GET /t
--- response_body_like eval
"tIBQd46amKgA6uRytksrXA=="
--- no_error_log
[error]


=== TEST 5: HKDF, optional arg
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version_num = require("resty.openssl.version").version_num
            if version_num < 0x10100000 then
                ngx.say("ckFzOqiMeR5Sl21W4zpczA==")
                ngx.say("SlKh6iSRnnZV92zOAbLduQ==")
                ngx.exit(0)
            end
            local kdf = require("resty.openssl.kdf")
            local key, err = kdf.derive({
                type = "HKDF",
                outlen = 16,
                hkdf_key = "secret",
            })
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(ngx.encode_base64(key))

            if version_num < 0x10101000 then
                ngx.say("SlKh6iSRnnZV92zOAbLduQ==")
                ngx.exit(0)
            end
            local key, err = kdf.derive({
                type = "HKDF",
                outlen = 16,
                hkdf_key = "secret",
                hkdf_mode = kdf.HKDEF_MODE_EXTRACT_ONLY,
            })
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(ngx.encode_base64(key))
        }
    }
--- request
    GET /t
--- response_body_like eval
"ckFzOqiMeR5Sl21W4zpczA==
SlKh6iSRnnZV92zOAbLduQ==
"
--- no_error_log
[error]


=== TEST 6: TLS1-PRF
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version_num = require("resty.openssl.version").version_num
            if version_num < 0x10100000 then
                ngx.say("0xr8qthU+ypv2xRC90la8g==")
                ngx.exit(0)
            end
            local kdf = require("resty.openssl.kdf")
            local key, err = kdf.derive({
                type = "TLS1-PRF",
                outlen = 16,
                md = "md5",
                tls1_prf_secret = "secret",
                tls1_prf_seed = "seed",
            })
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.print(ngx.encode_base64(key))
        }
    }
--- request
    GET /t
--- response_body_like eval
"0xr8qthU\\+ypv2xRC90la8g=="
--- no_error_log
[error]


=== TEST 7: TLS1-PRF, optional arg
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version_num = require("resty.openssl.version").version_num
            if version_num < 0x10100000 then
                ngx.say("XVVDK9/puTqBOsyTKt8PKQ==")
                ngx.exit(0)
            end
            local kdf = require("resty.openssl.kdf")
            local key, err = kdf.derive({
                type = "TLS1-PRF",
                outlen = 16,
                tls1_prf_secret = "secret",
                tls1_prf_seed = "seed",
            })
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.print(ngx.encode_base64(key))
        }
    }
--- request
    GET /t
--- response_body_like eval
"XVVDK9/puTqBOsyTKt8PKQ=="
--- no_error_log
[error]


=== TEST 8: scrypt
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version_num = require("resty.openssl.version").version_num
            if version_num < 0x10100000 then
                ngx.say("9giFtxace5sESmRb8qxuOw==")
                ngx.exit(0)
            end
            local kdf = require("resty.openssl.kdf")
            local key, err = kdf.derive({
                type = "id-scrypt",
                outlen = 16,
                pass = "1234567",
                scrypt_N = 1024,
                scrypt_r = 8,
                scrypt_p = 16,
            })
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.print(ngx.encode_base64(key))
        }
    }
--- request
    GET /t
--- response_body_like eval
"9giFtxace5sESmRb8qxuOw=="
--- no_error_log
[error]
