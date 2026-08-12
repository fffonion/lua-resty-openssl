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

no_long_string();

run_tests();

__DATA__

=== TEST 1: keygen: Generates RSA key by default
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = myassert(require("resty.openssl.pkey").new())
            ngx.say(myassert(p:to_PEM('private')))
        }
    }
--- request
    GET /t
--- response_body_like eval
"-----BEGIN PRIVATE KEY-----"
--- no_error_log
[error]



=== TEST 2: keygen: Generates and loads RSA key
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local pkey = require("resty.openssl.pkey")
            local p = myassert(pkey.new({
                type = 'RSA',
                bits = 2048,
            }))
            local pem = myassert(p:to_PEM('private'))
            ngx.say(pem)
            ngx.say(pem == pkey.new(pem):to_PEM('private'))
        }
    }
--- request
    GET /t
--- response_body_like eval
"-----BEGIN PRIVATE KEY-----
.+
true"
--- no_error_log
[error]



=== TEST 3: keygen: Generates and loads EC key explictly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local pkey = require("resty.openssl.pkey")
            local p = myassert(pkey.new({
                type = "EC",
                curve = 'prime256v1',
            }))
            local pem = myassert(p:to_PEM('private'))
            ngx.say(pem)
            ngx.say(pem == pkey.new(pem):to_PEM('private'))
        }
    }
--- request
    GET /t
--- response_body_like eval
"-----BEGIN PRIVATE KEY-----
.+
true"
--- no_error_log
[error]



=== TEST 4: keygen: Generates and loads Ed25519 key explictly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local pkey = require("resty.openssl.pkey")
            local p = myassert(pkey.new({
                type = 'Ed25519',
            }))
            local pem = myassert(p:to_PEM('private'))
            ngx.say(pem)
            ngx.say(pem == pkey.new(pem):to_PEM('private'))
        }
    }
--- request
    GET /t
--- response_body_like eval
"-----BEGIN PRIVATE KEY-----
.+
true"
--- no_error_log
[error]



=== TEST 5: keygen: Generates and loads DH key explictly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local pkey = require("resty.openssl.pkey")
            local p = myassert(pkey.new({
                type = 'DH',
                bits = 512
            }))
            local pem = myassert(p:to_PEM('private'))
            ngx.say(pem)
            ngx.say(pem == pkey.new(pem):to_PEM('private'))
            -- skip for 3.0 since it only allows 2048 bits and is toooo slow
        }
    }
--- request
    GET /t
--- response_body_like eval
"-----BEGIN PRIVATE KEY-----
.+
true"
--- no_error_log
[error]



=== TEST 6: keygen: Uses DH predefined groups
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local pkey = require("resty.openssl.pkey")
            local p = myassert(pkey.new({
                type = 'DH',
                group = "dh_1024_160",
            }))
            local pem = myassert(p:to_PEM('private'))
            ngx.say(pem)
            ngx.say(pem == pkey.new(pem):to_PEM('private'))
        }
    }
--- request
    GET /t
--- response_body_like eval
"-----BEGIN PRIVATE KEY-----
.+
true"
--- no_error_log
[error]



=== TEST 7: keygen: Rejects invalid arg
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
"pkey.new: unexpected type.+
pkey.new:load_key: .+
"
--- no_error_log
[error]



=== TEST 8: keygen: Keygen and paramgen with ctrl str
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p_384 = myassert(require("resty.openssl.pkey").new({
                type = "EC",
                "ec_paramgen_curve:secp384r1",
            }))
            ngx.say(myassert(p_384:get_parameters()).group)

            local _, err = myassert(require("resty.openssl.pkey").paramgen({
                type = "EC",
                "ec_paramgen_curve:secp384r1",
            }))
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
715
nil
--- no_error_log
[error]



=== TEST 9: compose: Compose key from parameters
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p_384 = myassert(require("resty.openssl.pkey").new({
                type = "EC",
                "ec_paramgen_curve:secp384r1",
            }))
            local out = myassert(p_384:to_PEM('private'))
            local params = p_384:get_parameters()

            local newp_384, err = myassert(require("resty.openssl.pkey").new({
                type = "EC",
                params = {
                    private = params.private,
                    public = params.public,
                    group = params.group
                }
            }))
            local out2 = myassert(newp_384:to_PEM('private'))
            ngx.say(out == out2)

            local p_ecx = myassert(require("resty.openssl.pkey").new({
                type = "Ed25519",
            }))
            local out = myassert(p_ecx:to_PEM('private'))
            local params = p_ecx:get_parameters()

            local newp_ecx, err = myassert(require("resty.openssl.pkey").new({
                type = "Ed25519",
                params = {
                    private = params.private,
                    public = params.public,
                }
            }))
            local out2 = myassert(newp_ecx:to_PEM('private'))
            ngx.say(out == out2)


        }
    }
--- request
    GET /t
--- response_body
true
true
--- no_error_log
[error]



=== TEST 10: compose: Compose provider keys from raw parameters
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version = require("resty.openssl.version")
            if version.version_num < 0x30500000 then
                ngx.say("ML-KEM-512 800 1632 false true")
                ngx.say("ML-DSA-44 1312 2560 false true")
                ngx.say("SLH-DSA-SHA2-128s 32 64 false true")
                ngx.say("X25519MLKEM768 1216 2432 false true")
                ngx.say("X448MLKEM1024 1624 3224 false true")
                ngx.say("SecP256r1MLKEM768 1249 nil false nil")
                ngx.say("SecP384r1MLKEM1024 1665 nil false nil")
                ngx.exit(0)
            end

            local pkey = require("resty.openssl.pkey")
            local types = {
                "ML-KEM-512", "ML-DSA-44", "SLH-DSA-SHA2-128s",
                "X25519MLKEM768", "X448MLKEM1024",
                "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
            }

            for _, typ in ipairs(types) do
                local private = myassert(pkey.new({ type = typ }))
                local params = myassert(private:get_parameters())
                local public = myassert(pkey.new({
                    type = typ,
                    params = { public = params.public },
                }))
                local copied_private

                if params.private ~= nil then
                    local copied = myassert(pkey.new({
                        type = typ,
                        params = { private = params.private },
                    }))
                    copied_private = copied:is_private()
                end
                ngx.say(typ, " ", #params.public, " ",
                        params.private and #params.private, " ",
                        public:is_private(), " ", copied_private)
            end
        }
    }
--- request
    GET /t
--- response_body
ML-KEM-512 800 1632 false true
ML-DSA-44 1312 2560 false true
SLH-DSA-SHA2-128s 32 64 false true
X25519MLKEM768 1216 2432 false true
X448MLKEM1024 1624 3224 false true
SecP256r1MLKEM768 1249 nil false nil
SecP384r1MLKEM1024 1665 nil false nil
--- no_error_log
[error]



=== TEST 11: paramgen: Outpus DH and EC params
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local pkey = require("resty.openssl.pkey")
            ngx.say(myassert(pkey.paramgen({
                type = 'DH',
                group = "dh_1024_160",
            })))
            ngx.say(myassert(pkey.paramgen({
                type = "EC",
                curve = "prime256v1",
            })))
            collectgarbage()
        }
    }
--- request
    GET /t
--- response_body_like eval
"-----BEGIN DH PARAMETERS-----
.+
-----BEGIN EC PARAMETERS-----"
--- no_error_log
[error]



=== TEST 12: paramgen: Load parameters for keygen
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local pem = myassert(require("resty.openssl.pkey").paramgen({
                type = "DH",
                group = "dh_1024_160",
            }))

            local p = myassert(require("resty.openssl.pkey").new({
                type = "DH",
                param = pem,
            }))

            ngx.say(myassert(p:get_parameters().p:to_hex()))

            local pem = myassert(require("resty.openssl.pkey").paramgen({
                type = "EC",
                curve = "prime192v1",
            }))

            local p = myassert(require("resty.openssl.pkey").new({
                type = "EC",
                param = pem,
            }))

            ngx.say(myassert(p:get_parameters().group))

            collectgarbage()
        }
    }
--- request
    GET /t
--- response_body_like eval
"B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
409
"
--- no_error_log
[error]



=== TEST 13: load: Loads encrypted PEM pkey with passphrase
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
            local privkey = myassert(require("resty.openssl.pkey").new(f, {
                format = "PEM",
                type = "pr",
                passphrase = "123456",
            }))

            ngx.say("ok")
        }
    }
--- request
    GET /t
--- response_body_like eval
"pkey.new.+(?:bad decrypt|failed).*
ok
"
--- no_error_log
[error]



=== TEST 14: load: Loads encrypted PEM pkey with passphrase callback
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
            local privkey = myassert(require("resty.openssl.pkey").new(f, {
                format = "PEM",
                type = "pr",
                passphrase_cb = function()
                    return "123456"
                end,
            }))

            ngx.say("ok")
        }
    }
--- request
    GET /t
--- response_body_like eval
"pkey.new.+(?:bad decrypt|failed).*
ok
"
--- no_error_log
[error]



=== TEST 15: load: PEM passphrase_cb won't overflow
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local pkey = require("resty.openssl.pkey")
            local ffi = require("ffi")
            local f = function() end
            local pok, perr, last_ff
            while true do
                pok, pret = pcall(ffi.cast, "pem_password_cb", f)
                if not pok then
                    last_ff:free()
                    break
                end
                last_ff = pret
            end
            ngx.say("errored out with ", pret)

            local f = io.open("t/fixtures/ec_key_encrypted.pem"):read("*a")
            local privkey, err
            for i=1, 5 do
                privkey, err = pkey.new(f, {
                    format = "PEM",
                    passphrase_cb = function()
                        return "wrongpassword"
                    end,
                })
            end
            -- with random order in lua tables, this could be loaded
            -- by PEM_read_bio_PUBKEY, in such case, error will be
            -- PEM routines:get_name:no start line
            ngx.say(err)

            for i=1, 5 do
                local privkey = myassert(pkey.new(f, {
                    format = "PEM",
                    passphrase_cb = function()
                        return "123456"
                    end,
                }))
            end
            ngx.say("ok")

            local p = myassert(pkey.new({
                type = "EC",
                curve = 'prime256v1',
            }))
            local pem = myassert(p:to_PEM('private'))

            for i=1, 5 do
                local privkey = myassert(pkey.new(p, {
                        format = "PEM",
                        passphrase_cb = function()
                            error("should not reach here")
                        end,
                    }))
                end
            ngx.say("ok")
        }
    }
--- request
    GET /t
--- response_body_like eval
"errored out with too many callbacks
pkey.new.+(?:bad decrypt|failed|no start line|DECODER routines:OSSL_DECODER_from_bio:unsupported).*
ok
ok
"
--- no_error_log
[error]



=== TEST 16: load: Loads DER format
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local pkey = require("resty.openssl.pkey")
            local p1 = myassert(pkey.new())

            local pem = p1:to_PEM('private')
            local der = myassert(p1:tostring('private', 'DER'))
            local p2 = myassert(pkey.new(der))

            ngx.print(p2 and pem == p2:to_PEM('private'))
        }
    }
--- request
    GET /t
--- response_body eval
"true"
--- no_error_log
[error]



=== TEST 17: load: Reads and write pkcs1 rsa key
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local pkey = require("resty.openssl.pkey")

            local f = io.open("t/fixtures/test.key"):read("*a") -- pkcs8
            local key = myassert(pkey.new(f))

            -- read
            for _, fp in ipairs({"rsa-pkcs1-priv.key", "rsa-pkcs1-pub.key"}) do
                local f = io.open("t/fixtures/" .. fp):read("*a") -- pkcs8
                myassert(pkey.new(f))
            end

            local p = myassert(pkey.new({ type = "EC", curve = 'prime256v1' }))
            ngx.say(p:to_PEM(nil, true))
            ngx.say(key:tostring(nil, "DER", true))

            if require("resty.openssl.version").OPENSSL_3_UP then
                ngx.say('BEGIN RSA PUBLIC KEY\ntrue')
                ngx.say('BEGIN RSA PRIVATE KEY\ntrue')
                ngx.exit(0)
            end

            -- write (and read back)
            for _, kt in ipairs({"public", "private"}) do
                local pkcs1_pem = key:to_PEM(kt, true)
                ngx.say(pkcs1_pem:match("BEGIN RSA " .. kt:upper() .. " KEY"))

                local key2 = myassert(pkey.new(pkcs1_pem))
                ngx.say(key2:to_PEM(kt) == key:to_PEM(kt))
            end
        }
    }
--- request
    GET /t
--- response_body
nilPKCS#1 format is only supported to encode RSA key in "PEM" format
nilPKCS#1 format is only supported to encode RSA key in "PEM" format
BEGIN RSA PUBLIC KEY
true
BEGIN RSA PRIVATE KEY
true
--- no_error_log
[error]



=== TEST 18: write: Outputs DER and JWK
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = myassert(require("resty.openssl.pkey").new({
                type = "EC",
                curve = 'prime256v1',
            }))
            local t = myassert(p:tostring('private', "PEM"))
            ngx.say(t)

            local t = myassert(p:tostring('private', "DER"))
            ngx.say(#t)

            local t = myassert(p:tostring('private', "JWK"))
            ngx.say(t)
        }
    }
--- request
    GET /t
--- response_body_like eval
"-----BEGIN PRIVATE KEY-----
.+
-----END PRIVATE KEY-----

(121|138|364)
.+kid.+"
--- no_error_log
[error]



=== TEST 19: write: Outputs public key
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = myassert(require("resty.openssl.pkey").new())
            ngx.say(p:to_PEM())
        }
    }
--- request
    GET /t
--- response_body_like eval
"-----BEGIN PUBLIC KEY-----"
--- no_error_log
[error]



=== TEST 20: write: Outputs post-quantum PEM and DER keys
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version = require("resty.openssl.version")
            if version.version_num < 0x30500000 then
                ngx.say("ML-KEM-512 PRIVATE KEY PUBLIC KEY 1730 822 true false")
                ngx.say("ML-DSA-44 PRIVATE KEY PUBLIC KEY 2626 1334 true false")
                ngx.say("SLH-DSA-SHA2-128s PRIVATE KEY PUBLIC KEY 84 50 true false")
                ngx.exit(0)
            end

            local pkey = require("resty.openssl.pkey")
            local types = {
                "ML-KEM-512", "ML-DSA-44", "SLH-DSA-SHA2-128s",
            }
            for _, typ in ipairs(types) do
                local private = myassert(pkey.new({ type = typ }))
                local private_pem = myassert(private:tostring("private", "PEM"))
                local public_pem = myassert(private:tostring("public", "PEM"))
                local private_der = myassert(private:tostring("private", "DER"))
                local public_der = myassert(private:tostring("public", "DER"))
                local loaded_private = myassert(pkey.new(
                    private_der, { format = "DER", type = "pr" }))
                local loaded_public = myassert(pkey.new(
                    public_der, { format = "DER", type = "pu" }))
                ngx.say(typ, " ", private_pem:match("BEGIN ([^-]+)"), " ",
                        public_pem:match("BEGIN ([^-]+)"), " ",
                        #private_der, " ", #public_der, " ",
                        loaded_private:is_private(), " ",
                        loaded_public:is_private())
            end
        }
    }
--- request
    GET /t
--- response_body
ML-KEM-512 PRIVATE KEY PUBLIC KEY 1730 822 true false
ML-DSA-44 PRIVATE KEY PUBLIC KEY 2626 1334 true false
SLH-DSA-SHA2-128s PRIVATE KEY PUBLIC KEY 84 50 true false
--- no_error_log
[error]



=== TEST 21: parameters: Extracts RSA parameters
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = myassert(require("resty.openssl.pkey").new({
                exp = 65537,
            }))

            local params = myassert(p:get_parameters())

            for _, k in ipairs(require("resty.openssl.rsa").params) do
                local b = myassert(params[k]:to_hex())
                ngx.say(b)
            end
            local got = params.dne
            ngx.say(got)
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
[A-F0-9]+
nil
"
--- no_error_log
[error]



=== TEST 22: parameters: Extracts EC parameters
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = myassert(require("resty.openssl.pkey").new({
                type = "EC",
            }))

            local params = myassert(p:get_parameters())

            local group = params["group"]
            ngx.say(group)
            for _, k in ipairs(require("resty.openssl.ec").params) do
                if k ~= "group" then
                    local b = myassert(params[k]:to_hex())

                    ngx.say(b)
                end
            end
            local got = params.dne
            ngx.say(got)
        }
    }
--- request
    GET /t
--- response_body_like eval
"409
[A-F0-9]{1,98}
[A-F0-9]{1,48}
[A-F0-9]{1,48}
[A-F0-9]{1,48}
nil
"
--- no_error_log
[error]



=== TEST 23: parameters: Extracts Ed25519 parameters
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = myassert(require("resty.openssl.pkey").new({
                type = "Ed25519",
            }))

            local params = myassert(p:get_parameters())

            ngx.say(#params.private)
            ngx.say(#params.public)
        }
    }
--- request
    GET /t
--- response_body_like eval
"32
32
"
--- no_error_log
[error]



=== TEST 24: parameters: Extracts and sets post-quantum parameters
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version = require("resty.openssl.version")
            if version.version_num < 0x30500000 then
                ngx.say("ML-KEM-512 800 1632 false true")
                ngx.say("ML-DSA-44 1312 2560 false true")
                ngx.say("SLH-DSA-SHA2-128s 32 64 false true")
                ngx.say("X25519MLKEM768 1216 2432 false true")
                ngx.say("SecP256r1MLKEM768 1249 nil false nil")
                ngx.exit(0)
            end

            local pkey = require("resty.openssl.pkey")
            local types = {
                "ML-KEM-512", "ML-DSA-44", "SLH-DSA-SHA2-128s",
                "X25519MLKEM768", "SecP256r1MLKEM768",
            }
            for _, typ in ipairs(types) do
                local private = myassert(pkey.new({ type = typ }))
                local params = myassert(private:get_parameters())
                local reset = myassert(pkey.new({ type = typ }))
                myassert(reset:set_parameters({ public = params.public }))
                local public_only = reset:is_private()
                local restored
                if params.private ~= nil then
                    myassert(reset:set_parameters({ private = params.private }))
                    restored = reset:is_private()
                end
                ngx.say(typ, " ", #params.public, " ",
                        params.private and #params.private, " ",
                        public_only, " ", restored)
            end
        }
    }
--- request
    GET /t
--- response_body
ML-KEM-512 800 1632 false true
ML-DSA-44 1312 2560 false true
SLH-DSA-SHA2-128s 32 64 false true
X25519MLKEM768 1216 2432 false true
SecP256r1MLKEM768 1249 nil false nil
--- no_error_log
[error]



=== TEST 25: parameters: Set DH parameters
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = myassert(require("resty.openssl.pkey").new({
                type = "DH",
                group = "dh_1024_160",
            }))

            local params1 = myassert(p:get_parameters())

            local p = myassert(require("resty.openssl.pkey").new({
                type = "DH",
                group = "dh_2048_224",
            }))

            myassert(p:set_parameters({
                p = params1.p,
                g = params1.g,
                private = params1.private,
                public = params1.public,
            }))

            local params = myassert(p:get_parameters())

            ngx.say(params.p:to_hex())
            ngx.say(params.g:to_hex())
            ngx.say(params.private:to_hex())
            ngx.say(params.public:to_hex())

            collectgarbage()
        }
    }
--- request
    GET /t
--- response_body_like eval
"B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5
[A-F0-9]{1,256}
[A-F0-9]{1,256}
"
--- no_error_log
[error]



=== TEST 26: encryption: Encrypt and decrypt
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local privkey = myassert(require("resty.openssl.pkey").new())
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local pubkey = myassert(require("resty.openssl.pkey").new(assert(privkey:to_PEM("public"))))

            local s = myassert(pubkey:encrypt("23333"))
            ngx.say(#s)

            local decrypted = myassert(privkey:decrypt(s))
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



=== TEST 27: encryption: Encrypt and decrypt with ctrl str
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local privkey = myassert(require("resty.openssl.pkey").new())
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
            local pubkey = myassert(require("resty.openssl.pkey").new(assert(privkey:to_PEM("public"))))

            local s = myassert(pubkey:encrypt("23333", privkey.PADDINGS.RSA_PKCS1_OAEP_PADDING, {
                oaep_md = "sha256",
            }))
            ngx.say(#s)

            local decrypted = myassert(privkey:decrypt(s, privkey.PADDINGS.RSA_PKCS1_OAEP_PADDING,{
                "rsa_oaep_md:sha256",
                "rsa_mgf1_md:sha256",
            }))
            ngx.say(decrypted)

            local ok, err = privkey:decrypt(s, privkey.PADDINGS.RSA_PKCS1_OAEP_PADDING,{
                "rsa_oaep_md:sha256",
                "rsa_mgf1_md:sha384",
            })
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body_like eval
"256
23333
.+oaep decoding error.*
"
--- no_error_log
[error]



=== TEST 28: encryption: invalid padding error message preserves user input
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local privkey = myassert(require("resty.openssl.pkey").new())
            local pubkey = myassert(require("resty.openssl.pkey").new(assert(privkey:to_PEM("public"))))

            local ok, err = pubkey:encrypt("23333", "bad_pad")
            ngx.say(ok)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body eval
"nil
invalid padding: bad_pad
"
--- no_error_log
[error]



=== TEST 29: encryption: Post-quantum signature keys are unsupported
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version = require("resty.openssl.version")
            if version.version_num < 0x30500000 then
                ngx.say("pkey:asymmetric_routine EVP_PKEY_encrypt_init")
                ngx.say("pkey:asymmetric_routine EVP_PKEY_decrypt_init")
                ngx.exit(0)
            end

            local key = myassert(require("resty.openssl.pkey").new({
                type = "ML-DSA-44",
            }))
            local _, encrypt_err = key:encrypt("x")
            local _, decrypt_err = key:decrypt("x")
            ngx.say(encrypt_err:match("^(.-): code:"))
            ngx.say(decrypt_err:match("^(.-): code:"))
        }
    }
--- request
    GET /t
--- response_body
pkey:asymmetric_routine EVP_PKEY_encrypt_init
pkey:asymmetric_routine EVP_PKEY_decrypt_init
--- no_error_log
[error]



=== TEST 30: signature: Sign and verify
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = myassert(require("resty.openssl.pkey").new())

            local digest = myassert(require("resty.openssl.digest").new("SHA256"))

            myassert(digest:update("🕶️", "+1s"))

            local s = myassert(p:sign(digest))
            ngx.say(#s)

            local v = myassert(p:verify(s, digest))
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



=== TEST 31: signature: One shot sign and verify
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            -- pureeddsa
            local p = myassert(require("resty.openssl.pkey").new({
                type = "Ed25519"
            }))
            local digest = "23333"
            local s = myassert(p:sign(digest))
            ngx.say(#s)

            local v = myassert(p:verify(s, digest))
            ngx.say(v)

            -- uses default md type
            local p = myassert(require("resty.openssl.pkey").new({
                type = "RSA"
            }))
            local digest = "23333"
            local s = myassert(p:sign(digest))
            ngx.say(#s)

            local v = myassert(p:verify(s, digest))
            ngx.say(v)
        }
    }
--- request
    GET /t
--- response_body eval
"64
true
256
true
"
--- no_error_log
[error]



=== TEST 32: signature: Post-quantum one-shot sign and verify
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version = require("resty.openssl.version")
            if version.version_num < 0x30500000 then
                ngx.say("2420 true\n7856 true\n7856 true")
                ngx.say("pkey:asymmetric_routine EVP_PKEY_sign_init: code: -2")
                ngx.say("pkey:asymmetric_routine EVP_PKEY_verify_init: code: -2")
                ngx.say("pkey:asymmetric_routine EVP_PKEY_verify_recover_init: code: -2")
                ngx.exit(0)
            end

            local pkey = require("resty.openssl.pkey")
            local types = {
                "ML-DSA-44",
                "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128s",
            }
            for _, typ in ipairs(types) do
                local private = myassert(pkey.new({ type = typ }))
                local public = myassert(pkey.new(
                    myassert(private:to_PEM("public")),
                    { format = "PEM", type = "pu" }
                ))
                local signature = myassert(private:sign("post quantum", nil))
                local verified = myassert(public:verify(
                    signature, "post quantum", nil))
                ngx.say(#signature, " ", verified)
            end

            local key = myassert(pkey.new({ type = "ML-DSA-44" }))
            local _, sign_err = key:sign_raw("x")
            local _, verify_err = key:verify_raw("x", "x")
            local _, recover_err = key:verify_recover("x")
            ngx.say(sign_err:match("^(.-) error:") or sign_err)
            ngx.say(verify_err:match("^(.-) error:") or verify_err)
            ngx.say(recover_err:match("^(.-) error:") or recover_err)
        }
    }
--- request
    GET /t
--- response_body
2420 true
7856 true
7856 true
pkey:asymmetric_routine EVP_PKEY_sign_init: code: -2
pkey:asymmetric_routine EVP_PKEY_verify_init: code: -2
pkey:asymmetric_routine EVP_PKEY_verify_recover_init: code: -2
--- no_error_log
[error]



=== TEST 33: signature: Error on bad digest or verify parameters
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = myassert(require("resty.openssl.pkey").new({
                type = "EC",
                curve = "prime256v1",
            }))
            local s, err = p:sign(false)
            ngx.say(err)
            local v, err = p:verify("", false)
            ngx.say(err)
            local v, err = p:verify(false, "1")
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body eval
"pkey:sign: expect a digest instance or a string at #1
pkey:verify: expect a digest instance or a string at #2
pkey:verify: expect a string at #1
"
--- no_error_log
[error]



=== TEST 34: signature: Raw sign, raw verify and recover
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = myassert(require("resty.openssl.pkey").new())

            local s = myassert(p:sign_raw("🕶️"))
            ngx.say(#s)

            local v = myassert(p:verify_recover(s))
            ngx.say(v == "🕶️")

            local p = myassert(require("resty.openssl.pkey").new({
                type = "EC",
                curve = "prime256v1",
            }))

            local hashed = myassert(require("resty.openssl.digest").new("sha384"):final("🕶️"))

            local s = myassert(p:sign_raw(hashed))

            local v = myassert(p:verify_raw(s, hashed, "sha384"))
            ngx.say(v == true)
        }
    }
--- request
    GET /t
--- response_body eval
"256
true
true
"
--- no_error_log
[error]



=== TEST 35: signature: Streaming sign and one shot sign can cross verify
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = myassert(require("resty.openssl.pkey").new())
            local pec = myassert(require("resty.openssl.pkey").new({
                type = "EC",
                curve = "prime256v1",
            }))

            -- one shot sign RSA, verify with digest instance
            local s = myassert(p:sign("🕶️+1s"))

            local digest = myassert(require("resty.openssl.digest").new("SHA256"))
            digest:update("🕶️+1s")
            local v, err = p:verify(s, digest)
            ngx.say(v)

            -- sign with digest RSA, one shot verify
            local digest = myassert(require("resty.openssl.digest").new("SHA256"))
            digest:update("🕶️+1s")
            local s = myassert(p:sign(digest))

            local v, err = p:verify(s, "🕶️+1s")
            ngx.say(v)

            -- one shot sign EC, verify with digest instance
            local s = myassert(pec:sign("🕶️+1s"))

            local digest = myassert(require("resty.openssl.digest").new("SHA256"))
            digest:update("🕶️+1s")
            local v, err = pec:verify(s, digest)
            ngx.say(v)

            -- sign with digest EC, one shot verify
            local digest = myassert(require("resty.openssl.digest").new("SHA256"))
            digest:update("🕶️+1s")
            local s = myassert(pec:sign(digest))

            local v, err = pec:verify(s, "🕶️+1s")
            ngx.say(v)
        }
    }
--- request
    GET /t
--- response_body eval
"true
true
true
true
"
--- no_error_log
[error]



=== TEST 36: signature: Sign/verify with md_alg
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            -- uses default md type
            local p = myassert(require("resty.openssl.pkey").new({
                type = "RSA"
            }))
            local digest = "23333"
            local s = myassert(p:sign(digest, "sha512"))
            ngx.say(#s)

            local ok = myassert(p:verify(s, digest, "sha512"))
            ngx.say(ok)

            -- use wrong md type, should not pass
            local ok, e = p:verify(s, digest, "sha256")
            ngx.say(ok)
            local ok, e = p:verify(s, digest, "md5")
            ngx.say(ok)
        }
    }
--- request
    GET /t
--- response_body eval
"256
true
false
false
"
--- no_error_log
[error]



=== TEST 37: signature: Sign/verify with paddings
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            -- uses default md type

            local p = myassert(require("resty.openssl.pkey").new({
                type = "RSA"
            }))
            local digest = "23333"
            local s = myassert(p:sign(digest, md, p.PADDINGS.RSA_PKCS1_PSS_PADDING))
            ngx.say(#s)

            local ok = myassert(p:verify(s, digest, md, p.PADDINGS.RSA_PKCS1_PSS_PADDING))
            ngx.say(ok)

            -- use wrong padding scheme, should not pass
            local ok, e = p:verify(s, digest, nil)
            if ok ~= false then ngx.say(e) else ngx.say(ok) end
            local ok, e = p:verify(s, digest, nil, p.PADDINGS.RSA_PKCS1_PADDING)
            if ok ~= false then ngx.say(e) else ngx.say(ok) end
        }
    }
--- request
    GET /t
--- response_body eval
"256
true
false
false
"
--- no_error_log
[error]



=== TEST 38: signature: Sign/verify with PSS custom salt_len
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = myassert(require("resty.openssl.pkey").new({
                type = "RSA"
            }))
            local digest = "23333"
            local s = myassert(p:sign(digest, nil, p.PADDINGS.RSA_PKCS1_PSS_PADDING, {
                pss_saltlen = 64,
            }))
            ngx.say(#s)

            local ok = myassert(p:verify(s, digest, nil, p.PADDINGS.RSA_PKCS1_PSS_PADDING, {
                pss_saltlen = 64,
            }))
            ngx.say(ok)
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



=== TEST 39: signature: Sign/verify with binary ecdsa sig
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local opts = { ecdsa_use_raw = true }
            local p = myassert(require("resty.openssl.pkey").new({
                type = "EC",
                curve = "prime256v1",
            }))

            local digest = myassert(require("resty.openssl.digest").new("SHA256"))

            myassert(digest:update("🕶️", "+1s"))

            local s = myassert(p:sign(digest, nil, nil, opts))
            ngx.say(#s)

            local s2 = myassert(p:sign(digest))
            ngx.say(#s2 > 64) -- normally 72

            local v = myassert(p:verify(s, digest, nil, nil, opts))
            ngx.say(v)

            ngx.say(p:verify(s2, digest)) -- this is ok
            ngx.say(p:verify(s, digest)) -- this should fail
            ngx.say(p:verify(s2, digest, nil, nil, opts)) -- this should also fail
        }
    }
--- request
    GET /t
--- response_body_like eval
"64
true
true
truenil
false.+
nilpkey:sign: ecdsa.sig_raw2der: invalid signature length, expect 64 but got \\d+
"
--- no_error_log
[error]



=== TEST 40: signature: Sign/verify with binary ecdsa sig length
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local opts = { ecdsa_use_raw = true }
            local p_521 = myassert(require("resty.openssl.pkey").new({
                type = "EC",
                curve = "secp521r1",
            }))

            local p_384 = myassert(require("resty.openssl.pkey").new({
                type = "EC",
                curve = "secp384r1",
            }))
            local digest = myassert(require("resty.openssl.digest").new("SHA256"))

            myassert(digest:update("🕶️", "+1s"))

            local s_512 = myassert(p_521:sign(digest, nil, nil, opts))
            ngx.say(#s_512)
            local s_384 = myassert(p_384:sign(digest, nil, nil, opts))
            ngx.say(#s_384)

            local v_512 = myassert(p_521:verify(s_512, digest, nil, nil, opts))
            ngx.say(v_512)
            local v_384 = myassert(p_384:verify(s_384, digest, nil, nil, opts))
            ngx.say(v_384)
        }
    }
--- request
    GET /t
--- response_body
132
96
true
true
--- no_error_log
[error]



=== TEST 41: signature: Sign and verify with ctrl str
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = myassert(require("resty.openssl.pkey").new({
                type = "RSA"
            }))
            local digest = "23333"
            local s = myassert(p:sign(digest, nil, p.PADDINGS.RSA_PKCS1_PSS_PADDING, {
                pss_saltlen = 64,
            }))
            ngx.say(#s)

            local ok = myassert(p:verify(s, digest, nil, p.PADDINGS.RSA_PKCS1_PSS_PADDING, {
                "rsa_pss_saltlen:64",
            }))
            ngx.say(ok)
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



=== TEST 42: signature: Get default digest type
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local pkey = require("resty.openssl.pkey")
            local p = myassert(pkey.new({ type = "EC" }))
            local algo = myassert(p:get_default_digest_type())
            ngx.say(require("cjson").encode(algo))
        }
    }
--- request
    GET /t
--- response_body_like
.+sha256.+
--- no_error_log
[error]



=== TEST 43: derivation: Key derivation for EC, X448 and X25519
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            for i, t in ipairs({"EC", "X25519", "X448"}) do
                local p = myassert(require("resty.openssl.pkey").new({
                    type = t,
                    curve = t == "EC" and "prime256v1" or nil,
                }))

                -- usually the peer key is the pubkey from other key pair
                -- we use the same key here just for simplicity
                local k = myassert(p:derive(p))
                ngx.say(#k)
            ::next::
            end
        }
    }
--- request
    GET /t
--- response_body_like eval
"32
32
56"
--- no_error_log
[error]



=== TEST 44: KEM: Post-quantum encapsulate and decapsulate
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version = require("resty.openssl.version")
            if version.version_num < 0x30500000 then
                ngx.say("ML-KEM-512 768 32 true")
                ngx.say("ML-KEM-768 1088 32 true")
                ngx.say("ML-KEM-1024 1568 32 true")
                ngx.say("X25519MLKEM768 1120 64 true")
                ngx.say("X448MLKEM1024 1624 88 true")
                ngx.say("SecP256r1MLKEM768 1153 64 true")
                ngx.say("SecP384r1MLKEM1024 1665 80 true")
                ngx.say("pkey:derive: EVP_PKEY_derive_init: code: -2")
                ngx.exit(0)
            end

            local pkey = require("resty.openssl.pkey")
            local types = {
                "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
                "X25519MLKEM768", "X448MLKEM1024",
                "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
            }
            for _, typ in ipairs(types) do
                local private = myassert(pkey.new({ type = typ }))
                local params = myassert(private:get_parameters())
                local public = myassert(pkey.new({
                    type = typ,
                    params = { public = params.public },
                }))
                local wrapped, secret = public:encapsulate()
                assert(wrapped, secret)
                ngx.say(typ, " ", #wrapped, " ", #secret, " ",
                        myassert(private:decapsulate(wrapped)) == secret)
            end

            local signature_key = myassert(pkey.new({ type = "ML-DSA-44" }))
            local _, derive_err = signature_key:derive(signature_key)
            ngx.say(derive_err:match("^(.-) error:") or derive_err)
        }
    }
--- request
    GET /t
--- response_body
ML-KEM-512 768 32 true
ML-KEM-768 1088 32 true
ML-KEM-1024 1568 32 true
X25519MLKEM768 1120 64 true
X448MLKEM1024 1624 88 true
SecP256r1MLKEM768 1153 64 true
SecP384r1MLKEM1024 1665 80 true
pkey:derive: EVP_PKEY_derive_init: code: -2
--- no_error_log
[error]



=== TEST 45: KEM: RSA, EC, X25519 and X448
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version = require("resty.openssl.version")
            if version.version_num < 0x30500000 then
                ngx.say("RSA 128 128 true")
                ngx.say("EC 65 32 true")
                ngx.say("X25519 32 32 true")
                ngx.say("X448 56 64 true")
                ngx.exit(0)
            end

            local pkey = require("resty.openssl.pkey")
            local configs = {
                { type = "RSA", bits = 1024 },
                { type = "EC", curve = "prime256v1" },
                { type = "X25519" },
                { type = "X448" },
            }
            for _, config in ipairs(configs) do
                local private = myassert(pkey.new(config))
                local public = myassert(pkey.new(
                    myassert(private:to_PEM("public")),
                    { type = "pu", format = "PEM" }
                ))
                local wrapped, secret = public:encapsulate()
                assert(wrapped, secret)
                ngx.say(config.type, " ", #wrapped, " ", #secret, " ",
                        myassert(private:decapsulate(wrapped)) == secret)
            end
        }
    }
--- request
    GET /t
--- response_body
RSA 128 128 true
EC 65 32 true
X25519 32 32 true
X448 56 64 true
--- no_error_log
[error]



=== TEST 46: misc: get key type
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p, err = myassert(require("resty.openssl.pkey").new({
                type = 'RSA',
            }))
            ngx.say(encode_sorted_json(p:get_key_type()))
            ngx.say(p:get_key_type(true))

            p = myassert(require("resty.openssl.pkey").new({
                type = 'EC',
                curve = 'prime256v1',
            }))
            ngx.say(encode_sorted_json(p:get_key_type()))
            ngx.say(p:get_key_type(true))
        }
    }
--- request
    GET /t
--- response_body
{"id":"1.2.840.113549.1.1.1","ln":"rsaEncryption","nid":6,"sn":"rsaEncryption"}
6
{"id":"1.2.840.10045.2.1","ln":"id-ecPublicKey","nid":408,"sn":"id-ecPublicKey"}
408
--- no_error_log
[error]



=== TEST 47: misc: provider and post-quantum key types
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version = require("resty.openssl.version")
            local types = {
                "ML-KEM-512",
                "ML-DSA-44",
                "SLH-DSA-SHA2-128s",
            }

            if version.version_num < 0x30500000 then
                ngx.say('{"id":"2.16.840.1.101.3.4.4.1","ln":"ML-KEM-512","nid":1454,"sn":"id-alg-ml-kem-512"}')
                ngx.say(1454)
                ngx.say('{"id":"2.16.840.1.101.3.4.3.17","ln":"ML-DSA-44","nid":1457,"sn":"id-ml-dsa-44"}')
                ngx.say(1457)
                ngx.say('{"id":"2.16.840.1.101.3.4.3.20","ln":"SLH-DSA-SHA2-128s","nid":1460,"sn":"id-slh-dsa-sha2-128s"}')
                ngx.say(1460)
                ngx.say("nil")
                ngx.say("pkey:get_key_type: key type has no ASN.1 NID")
                ngx.exit(0)
            end

            local pkey = require("resty.openssl.pkey")
            for _, typ in ipairs(types) do
                local key = myassert(pkey.new({ type = typ }))
                local info = myassert(key:get_key_type())
                local nid = myassert(key:get_key_type(true))

                ngx.say(encode_sorted_json(info))
                ngx.say(nid)
            end

            -- Provider-only hybrid key types don't have an ASN.1 NID, but
            -- they must still be accepted as pkey objects.
            local hybrid = myassert(pkey.new({ type = "X25519MLKEM768" }))
            local info, err = hybrid:get_key_type()
            ngx.say(info)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
{"id":"2.16.840.1.101.3.4.4.1","ln":"ML-KEM-512","nid":1454,"sn":"id-alg-ml-kem-512"}
1454
{"id":"2.16.840.1.101.3.4.3.17","ln":"ML-DSA-44","nid":1457,"sn":"id-ml-dsa-44"}
1457
{"id":"2.16.840.1.101.3.4.3.20","ln":"SLH-DSA-SHA2-128s","nid":1460,"sn":"id-slh-dsa-sha2-128s"}
1460
nil
pkey:get_key_type: key type has no ASN.1 NID
--- no_error_log
[error]



=== TEST 48: misc: post-quantum key metadata
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version = require("resty.openssl.version")
            if version.version_num < 0x30500000 then
                ngx.say("true\n2420\ndefault\nnil\nget_default_digest: code: 0")
                ngx.exit(0)
            end

            local pkey = require("resty.openssl.pkey")
            local key = myassert(pkey.new({ type = "ML-DSA-44" }))
            ngx.say(pkey.istype(key))
            ngx.say(key:get_size())
            ngx.say(myassert(key:get_provider_name()))
            local digest, err = key:get_default_digest_type()
            ngx.say(digest)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body
true
2420
default
nil
get_default_digest: code: 0
--- no_error_log
[error]



=== TEST 49: misc: get size
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p, err = myassert(require("resty.openssl.pkey").new({
                type = 'EC',
            }))
            ngx.say(p:get_size())
        }
    }
--- request
    GET /t
--- response_body
56
--- no_error_log
[error]



=== TEST 50: misc: Checks if it's private key
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local opts = {
                { type = 'RSA', bits = 1024 },
                { type = "EC", curve = "prime256v1" },
                { type = 'DH', group = "dh_1024_160",},
            }
            for _, opt in ipairs(opts) do
                local priv = myassert(require("resty.openssl.pkey").new(opt))

                local ok, err = priv:is_private()
                if not ok then
                    ngx.say(opt.type .. ": should be a private key, but returns false: ".. (err or "nil"))
                end

                local pem = myassert(priv:to_PEM("public"))

                local pub = myassert(require("resty.openssl.pkey").new(pem))

                local ok, err = pub:is_private()
                if ok then
                    ngx.say(opt.type .. ": should not be a private key, but returns true: ".. (err or "nil"))
                end
            end
        }
    }
--- request
    GET /t
--- response_body eval
""
--- no_error_log
[error]



=== TEST 51: misc: Checks if it's private key: ecx
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local opts = {
                { type = 'Ed25519'},
            }
            for _, opt in ipairs(opts) do
                local priv = myassert(require("resty.openssl.pkey").new(opt))

                local ok, err = priv:is_private()
                if not ok then
                    ngx.say(opt.type .. ": should be a private key, but returns false: ".. (err or "nil"))
                end

                local pem = myassert(priv:to_PEM("public"))

                local pub = myassert(require("resty.openssl.pkey").new(pem))

                local ok, err = pub:is_private()
                if ok then
                    ngx.say(opt.type .. ": should not be a private key, but returns true: ".. (err or "nil"))
                end
            end
        }
    }
--- request
    GET /t
--- response_body eval
""
--- no_error_log
[error]



=== TEST 52: misc: Returns provider
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            if not require("resty.openssl.version").OPENSSL_3_UP then
                ngx.say("default")
                ngx.exit(0)
            end

            local pkey = require("resty.openssl.pkey")
            local p = myassert(pkey.new({ type = "EC" }))
            ngx.say(myassert(p:get_provider_name()))
        }
    }
--- request
    GET /t
--- response_body
default
--- no_error_log
[error]



=== TEST 53: params: Returns gettable, settable params
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            if not require("resty.openssl.version").OPENSSL_3_UP then
                ngx.say("-bits-\n-encoding-")
                ngx.exit(0)
            end

            local pkey = require("resty.openssl.pkey")
            local p = myassert(pkey.new({ type = "EC" }))
            ngx.say(require("cjson").encode(myassert(p:gettable_params())))
            ngx.say(require("cjson").encode(myassert(p:settable_params())))
        }
    }
--- request
    GET /t
--- response_body_like
.+bits.+
.+encoding.+
--- no_error_log
[error]



=== TEST 54: params: Get params, set params
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            if not require("resty.openssl.version").OPENSSL_3_UP then
                ngx.say("true")
                ngx.exit(0)
            end

            local pkey = require("resty.openssl.pkey")
            local p = myassert(pkey.new({ type = "EC" }))
            local priv = myassert(p:get_param("priv", nil, "bn"))
            local priv2 = p:get_parameters().private
            ngx.say(priv == priv2)

            myassert(p:set_params({["point-format"] = "UNCOMPRESSED"}))
        }
    }
--- request
    GET /t
--- response_body eval
"true
"
--- no_error_log
[error]



=== TEST 55: params: Post-quantum generic EVP params
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version = require("resty.openssl.version")
            if version.version_num < 0x30500000 then
                ngx.say("ML-KEM-512 128")
                ngx.say("ML-DSA-44 128")
                ngx.say("SLH-DSA-SHA2-128s 128")
                ngx.say("X25519MLKEM768 192")
                ngx.say("SecP256r1MLKEM768 192")
                ngx.exit(0)
            end

            local pkey = require("resty.openssl.pkey")
            local types = {
                "ML-KEM-512", "ML-DSA-44", "SLH-DSA-SHA2-128s",
                "X25519MLKEM768", "SecP256r1MLKEM768",
            }
            for _, typ in ipairs(types) do
                local key = myassert(pkey.new({ type = typ }))
                assert(type(key:gettable_params()) == "table")
                assert(type(key:settable_params()) == "table")
                ngx.say(typ, " ", myassert(key:get_param("security-bits")))
                myassert(key:set_params({}))
            end
        }
    }
--- request
    GET /t
--- response_body
ML-KEM-512 128
ML-DSA-44 128
SLH-DSA-SHA2-128s 128
X25519MLKEM768 192
SecP256r1MLKEM768 192
--- no_error_log
[error]
