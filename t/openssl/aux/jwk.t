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
=== TEST 1: Loads JWK RSA key
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
            local privkey = myassert(require("resty.openssl.pkey").new(jwk))
            local privkey = myassert(require("resty.openssl.pkey").new(jwk, {
                format = "JWK",
            }))

            -- errors
            local _, err = require("resty.openssl.pkey").new('asdasd', {
                format = "JWK",
            })
            ngx.say(err)
            local _, err = require("resty.openssl.pkey").new(require("cjson").encode({
                kty = "RSA",
                n   = "pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w",
            }), {
                format = "JWK",
            })
            ngx.say(err)

            -- pubkey only
            jwk = require("cjson").encode({
                kty = "RSA",
                n   = "pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w",
                e   = "AQAB",
            })
            local pubkey = myassert(require("resty.openssl.pkey").new(jwk))

            local s = myassert(pubkey:encrypt("23333"))
            local s = myassert(privkey:decrypt(s))
            ngx.say(s)
        }
    }
--- request
    GET /t
--- response_body_like eval
'pkey.new:load_key: (jwk:load_jwk: )?error decoding JSON from JWK: Expected value but found invalid token at character 1
(pkey.new:load_key: failed to construct RSA key from JWK: at least "n" and "e" parameter is required|pkey.new:load_key: jwk:load_jwk: missing required parameter "e")
23333
'
--- no_error_log
[error]

=== TEST 2: Loads JWK EC key
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local jwk = require("cjson").encode({
                kty = "EC",
                crv = "P-256",
                x   = "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
                y   = "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
                d   = "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
            })
            local privkey = myassert(require("resty.openssl.pkey").new(jwk))
            local privkey = myassert(require("resty.openssl.pkey").new(jwk, {
                format = "JWK",
            }))

            -- errors
            local _, err = require("resty.openssl.pkey").new(require("cjson").encode({
                kty = "EC",
                crv = "P-256",
                x   = "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
            }), {
                format = "JWK",
            })
            ngx.say(err)

            -- pubkey only
            jwk = require("cjson").encode({
                kty = "EC",
                crv = "P-256",
                x   = "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
                y   = "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
            })
            local pubkey = myassert(require("resty.openssl.pkey").new(jwk))

            local d = require("resty.openssl.digest").new("sha256")
            d:update("23333")
            local s = myassert(privkey:sign(d))
            local ok = myassert(pubkey:verify(s, d))
            ngx.say(ok)
        }
    }
--- request
    GET /t
--- response_body_like eval
'(pkey.new:load_key: failed to construct EC key from JWK: at least "x" and "y" parameter is required|pkey.new:load_key: jwk:load_jwk: missing required parameter "y")
true
'
--- no_error_log
[error]

=== TEST 3: Loads JWK Ed25519 key
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local jwk = require("cjson").encode({
                kty = "OKP",
                crv = "Ed25519",
                x   = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
                d   = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
            })
            local privkey = myassert(require("resty.openssl.pkey").new(jwk))
            local privkey = myassert(require("resty.openssl.pkey").new(jwk, {
                format = "JWK",
            }))

            -- errors
            local _, err = require("resty.openssl.pkey").new(require("cjson").encode({
                kty = "OKP",
                crv = "Ed25519",
            }), {
                format = "JWK",
            })
            ngx.say(err)

            -- pubkey only
            jwk = require("cjson").encode({
                kty = "OKP",
                crv = "Ed25519",
                x   = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            })
            local pubkey = myassert(require("resty.openssl.pkey").new(jwk))

        }
    }
--- request
    GET /t
--- response_body_link eval
'(pkey.new:load_key: failed to construct OKP key from JWK: at least "x" or "d" parameter is required|pkey.new:load_key: jwk:load_jwk: missing required parameter "e")
'
--- no_error_log
[error]

=== TEST 4: Errors if tries to export privkey using pubkey
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local privkey = myassert(require("resty.openssl.pkey").new({ type = 'EC', curve = 'prime256v1'}))

            local pem = myassert(privkey:tostring("public"))

            local pubkey = myassert(require("resty.openssl.pkey").new(pem))

            local _, err = pubkey:tostring("private", "JWK")
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body eval
'jwk.dump_jwk: could not dump public key as private key
'
--- no_error_log
[error]


=== TEST 5: Dump pubkey from privkey doesn't contain private part
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
            local privkey = myassert(require("resty.openssl.pkey").new(jwk))
            local jwk = require("cjson").decode(myassert(privkey:tostring("public", "JWK")))
            for k, _ in pairs(jwk) do
                if k ~= "kty" and k ~= "kid" and k ~= "n" and k ~="e" then
                    ngx.say("RSA JWK pubkey contains private part: " .. k)
                end
            end

            local jwk = require("cjson").encode({
                kty = "EC",
                crv = "P-256",
                x   = "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
                y   = "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
                d   = "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
            })
            local privkey = myassert(require("resty.openssl.pkey").new(jwk))
            local jwk = require("cjson").decode(myassert(privkey:tostring("public", "JWK")))
            for k, _ in pairs(jwk) do
                if k ~= "kty" and k ~= "kid" and k ~= "crv" and k ~= "x" and k ~="y" then
                    ngx.say("EC JWK pubkey contains private part: " .. k)
                end
            end

            local jwk = require("cjson").encode({
                kty = "OKP",
                crv = "Ed25519",
                x   = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
                d   = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
            })
            local privkey = myassert(require("resty.openssl.pkey").new(jwk))
            local jwk = require("cjson").decode(myassert(privkey:tostring("public", "JWK")))
            for k, _ in pairs(jwk) do
                if k ~= "kty" and k ~= "kid" and k ~= "crv" and k ~= "x" then
                    ngx.say("ECX JWK pubkey contains private part: " .. k)
                end
            end
        }
    }
--- request
    GET /t
--- response_body eval
''
--- no_error_log
[error]


=== TEST 6: Loads only the pubkey part of private JWK material
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            if not require("resty.openssl.version").OPENSSL_3X then
                ngx.say("false\nfalse\nfalse")
                ngx.exit(0)
            end

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
            local key = myassert(require("resty.openssl.pkey").new(jwk, {
                format = "JWK",
                type = "pu"
            }))
            ngx.say(key:is_private())

            local jwk = require("cjson").encode({
                kty = "EC",
                crv = "P-256",
                x   = "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
                y   = "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
                d   = "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
            })
            local key = myassert(require("resty.openssl.pkey").new(jwk, {
                format = "JWK",
                type = "pu"
            }))
            ngx.say(key:is_private())

             local jwk = require("cjson").encode({
                kty = "OKP",
                crv = "Ed25519",
                x   = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
                d   = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
            })
            local key = myassert(require("resty.openssl.pkey").new(jwk, {
                format = "JWK",
                type = "pu"
            }))
            ngx.say(key:is_private())
        }
    }
--- request
    GET /t
--- response_body_like eval
'false
'
--- no_error_log
[error]