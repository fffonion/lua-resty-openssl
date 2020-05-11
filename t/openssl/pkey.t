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

no_long_string();

run_tests();

__DATA__
=== TEST 1: Generates RSA key by default
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = require("resty.openssl.pkey").new()
            ngx.say(p:to_PEM('private'))
        }
    }
--- request
    GET /t
--- response_body_like eval
"-----BEGIN PRIVATE KEY-----"
--- no_error_log
[error]

=== TEST 2: Generates RSA key explictly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = require("resty.openssl.pkey").new({
                type = 'RSA',
                bits = 2048,
            })
            ngx.say(p:to_PEM('private'))
        }
    }
--- request
    GET /t
--- response_body_like eval
"-----BEGIN PRIVATE KEY-----"
--- no_error_log
[error]

=== TEST 3: Generates EC key
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = require("resty.openssl.pkey").new({
                type = 'EC',
                curve = 'prime256v1',
            })
            ngx.say(p:to_PEM('private'))
        }
    }
--- request
    GET /t
--- response_body_like eval
"-----BEGIN PRIVATE KEY-----"
--- no_error_log
[error]

=== TEST 4: Rejects invalid arg
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local pkey = require("resty.openssl.pkey")
            local p, err = pkey.new(123)
            ngx.say(err)
            local p, err = pkey.new('PRIVATE KEY')
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body_like eval
"unexpected type.+
pkey.new:load_pkey: .+
"
--- no_error_log
[error]

=== TEST 5: Loads PEM format
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local pkey = require("resty.openssl.pkey")
            local p1, err = pkey.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local p2, err = pkey.new(p1:to_PEM('private'))
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.print(p1:to_PEM('private') == p2:to_PEM('private'))
        }
    }
--- request
    GET /t
--- response_body eval
"true"
--- no_error_log
[error]

=== TEST 6: Loads DER format
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local pkey = require("resty.openssl.pkey")
            local p1, err = pkey.new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local pem = p1:to_PEM('private')
            local der, err = require("ngx.ssl").priv_key_pem_to_der(pem)
            local p2, err = pkey.new(der)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.print(p2 and pem == p2:to_PEM('private'))
        }
    }
--- request
    GET /t
--- response_body eval
"true"
--- no_error_log
[error]

=== TEST 7: Extracts parameters
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p, err = require("resty.openssl.pkey").new({
                exp = 65537,
            })
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local params, err = p:get_parameters()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            for _, k in ipairs(require("resty.openssl.rsa").params) do
                local b, err = params[k]:to_hex()
                if err then
                    ngx.log(ngx.ERR, err)
                end
                ngx.say(b)
            end
        }
    }
--- request
    GET /t
--- response_body_like eval
"[A-F0-9]+
[A-F0-9]+
[A-F0-9]+
[A-F0-9]+
[A-F0-9]+
[A-F0-9]+
[A-F0-9]+
"
--- no_error_log
[error]

=== TEST 8: Sign and verify
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p, err = require("resty.openssl.pkey").new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            
            local digest, err = require("resty.openssl.digest").new("SHA256")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local _, err = digest:update("🕶️", "+1s")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local s, err = p:sign(digest)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(#s)
            local v, err = p:verify(s, digest)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(v)
        }
    }
--- request
    GET /t
--- response_body eval
"256
true
"
--- no_error_log
[error]

=== TEST 9: Error on bad digest or verify parameters
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p, err = require("resty.openssl.pkey").new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end

            local s, err = p:sign("not a cdata")
            ngx.say(err)
            local v, err = p:verify(s, "not a cdata")
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body eval
"expect a digest instance at #1
expect a digest instance at #2
"
--- no_error_log
[error]

=== TEST 10: Outputs public key
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p, err = require("resty.openssl.pkey").new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(p:to_PEM())
        }
    }
--- request
    GET /t
--- response_body_like eval
"-----BEGIN PUBLIC KEY-----"
--- no_error_log
[error]

=== TEST 11: Encrypt and decrypt
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local privkey, err = require("resty.openssl.pkey").new()
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local pubkey, err = require("resty.openssl.pkey").new(assert(privkey:to_PEM("public")))
            if err then
                ngx.log(ngx.ERR, err)
                return
            end

            local s, err = pubkey:encrypt("23333")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(#s)
            local decrypted, err = privkey:decrypt(s)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(decrypted)
        }
    }
--- request
    GET /t
--- response_body eval
"256
23333
"
--- no_error_log
[error]


=== TEST 12: Loads encrypted PEM pkey with passphrase
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/ec_key_encrypted.pem"):read("*a")
            local privkey, err = require("resty.openssl.pkey").new(f, {
                format = "PEM",
                type = "pr",
                passphrase = "wrongpasswrod",
            })
            ngx.say(err)
            local privkey, err = require("resty.openssl.pkey").new(f, {
                format = "PEM",
                type = "pr",
                passphrase = "123456",
            })
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say("ok")
        }
    }
--- request
    GET /t
--- response_body_like eval
"pkey.new.+bad decrypt
ok
"
--- no_error_log
[error]


=== TEST 13: Loads encrypted PEM pkey with passphrase callback
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/ec_key_encrypted.pem"):read("*a")
            local privkey, err = require("resty.openssl.pkey").new(f, {
                format = "PEM",
                type = "pr",
                passphrase_cb = function()
                    return "wrongpassword"
                end,
            })
            ngx.say(err)
            local privkey, err = require("resty.openssl.pkey").new(f, {
                format = "PEM",
                type = "pr",
                passphrase_cb = function()
                    return "123456"
                end,
            })
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say("ok")
        }
    }
--- request
    GET /t
--- response_body_like eval
"pkey.new.+bad decrypt
ok
"
--- no_error_log
[error]

=== TEST 14: Loads JWK RSA key
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local jwk = require("cjson").encode({
                kty = "RSA",
                n   = "pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w",
                e   = "AQAB",
                d   = "ksDmucdMJXkFGZxiomNHnroOZxe8AmDLDGO1vhs-POa5PZM7mtUPonxwjVmthmpbZzla-kg55OFfO7YcXhg-Hm2OWTKwm73_rLh3JavaHjvBqsVKuorX3V3RYkSro6HyYIzFJ1Ek7sLxbjDRcDOj4ievSX0oN9l-JZhaDYlPlci5uJsoqro_YrE0PRRWVhtGynd-_aWgQv1YzkfZuMD-hJtDi1Im2humOWxA4eZrFs9eG-whXcOvaSwO4sSGbS99ecQZHM2TcdXeAs1PvjVgQ_dKnZlGN3lTWoWfQP55Z7Tgt8Nf1q4ZAKd-NlMe-7iqCFfsnFwXjSiaOa2CRGZn-Q",
                p   = "4A5nU4ahEww7B65yuzmGeCUUi8ikWzv1C81pSyUKvKzu8CX41hp9J6oRaLGesKImYiuVQK47FhZ--wwfpRwHvSxtNU9qXb8ewo-BvadyO1eVrIk4tNV543QlSe7pQAoJGkxCia5rfznAE3InKF4JvIlchyqs0RQ8wx7lULqwnn0",
                q   = "ven83GM6SfrmO-TBHbjTk6JhP_3CMsIvmSdo4KrbQNvp4vHO3w1_0zJ3URkmkYGhz2tgPlfd7v1l2I6QkIh4Bumdj6FyFZEBpxjE4MpfdNVcNINvVj87cLyTRmIcaGxmfylY7QErP8GFA-k4UoH_eQmGKGK44TRzYj5hZYGWIC8",
                dp  = "lmmU_AG5SGxBhJqb8wxfNXDPJjf__i92BgJT2Vp4pskBbr5PGoyV0HbfUQVMnw977RONEurkR6O6gxZUeCclGt4kQlGZ-m0_XSWx13v9t9DIbheAtgVJ2mQyVDvK4m7aRYlEceFh0PsX8vYDS5o1txgPwb3oXkPTtrmbAGMUBpE",
                dq  = "mxRTU3QDyR2EnCv0Nl0TCF90oliJGAHR9HJmBe__EjuCBbwHfcT8OG3hWOv8vpzokQPRl5cQt3NckzX3fs6xlJN4Ai2Hh2zduKFVQ2p-AF2p6Yfahscjtq-GY9cB85NxLy2IXCC0PF--Sq9LOrTE9QV988SJy_yUrAjcZ5MmECk",
                qi  = "ldHXIrEmMZVaNwGzDF9WG8sHj2mOZmQpw9yrjLK9hAsmsNr5LTyqWAqJIYZSwPTYWhY4nu2O0EY9G9uYiqewXfCKw_UngrJt8Xwfq1Zruz0YY869zPN4GiE9-9rzdZB33RBw8kIOquY3MK74FMwCihYx_LiU2YTHkaoJ3ncvtvg"
            })
            local privkey, err = require("resty.openssl.pkey").new(jwk)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local privkey, err = require("resty.openssl.pkey").new(jwk, {
                format = "JWK",
            })
            if err then
                ngx.log(ngx.ERR, err)
                return
            end

            -- pubkey only
            jwk = require("cjson").encode({
                kty = "RSA",
                n   = "pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w",
                e   = "AQAB",
            })
            local pubkey, err = require("resty.openssl.pkey").new(jwk)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end

            local s, err = pubkey:encrypt("23333")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local s, err = privkey:decrypt(s)
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            ngx.say(s)
        }
    }
--- request
    GET /t
--- response_body_like eval
"23333
"
--- no_error_log
[error]