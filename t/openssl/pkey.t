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
=== TEST 1: Generates RSA key by default
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

=== TEST 2: Generates and loads RSA key
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

=== TEST 3: Generates and loads EC key explictly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local pkey = require("resty.openssl.pkey")
            local p = myassert(pkey.new({
                type = 'EC',
                curve = 'prime192v1',
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

=== TEST 4: Generates and loads Ed25519 key explictly
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
--- skip_openssl
2: < 1.1.1
--- response_body_like eval
"-----BEGIN PRIVATE KEY-----
.+
true"
--- no_error_log
[error]

=== TEST 5: Generates and loads DH key explictly
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
--- skip_openssl
2: > 1.1.1
--- response_body_like eval
"-----BEGIN PRIVATE KEY-----
.+
true"
--- no_error_log
[error]

=== TEST 6: Uses DH predefined groups
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

=== TEST 7: Rejects invalid arg
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

=== TEST 8: Loads encrypted PEM pkey with passphrase
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
"pkey.new.+bad decrypt
ok
"
--- no_error_log
[error]

=== TEST 9: Loads encrypted PEM pkey with passphrase callback
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
"pkey.new.+bad decrypt
ok
"
--- no_error_log
[error]

=== TEST 10: Loads DER format
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local pkey = require("resty.openssl.pkey")
            local p1 = myassert(pkey.new())

            local pem = p1:to_PEM('private')
            local der, err = require("ngx.ssl").priv_key_pem_to_der(pem)
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

=== TEST 11: Outputs DER and JWK
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = require("resty.openssl.pkey").new({
                type = 'EC',
                curve = 'prime256v1',
            })
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

=== TEST 12: Outputs public key
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

=== TEST 13: Extracts RSA parameters
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

=== TEST 14: Extracts EC parameters
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

=== TEST 15: Extracts Ed25519 parameters
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
--- skip_openssl
2: < 1.1.1
--- response_body_like eval
"32
32
"
--- no_error_log
[error]

=== TEST 16: Extracts DH parameters
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = myassert(require("resty.openssl.pkey").new({
                type = "DH",
                group = "dh_1024_160",
            }))

            local params = myassert(p:get_parameters())

            ngx.say(params.p:to_hex())
            ngx.say(params.g:to_hex())
            ngx.say(params.private:to_hex())
            ngx.say(params.public:to_hex())
        }
    }
--- request
    GET /t
--- response_body_like eval
"B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5
[A-F0-9]+
[A-F0-9]+
"
--- no_error_log
[error]

=== TEST 17: Encrypt and decrypt
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


=== TEST 18: Sign and verify
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

=== TEST 19: One shot sign and verify
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
--- skip_openssl
2: < 1.1.1
--- response_body eval
"64
true
256
true
"
--- no_error_log
[error]

=== TEST 20: Error on bad digest or verify parameters
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = myassert(require("resty.openssl.pkey").new())

            local s, err = p:sign(p)
            ngx.say(err)
            local v, err = p:verify(s, p)
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body eval
"pkey:sign: expect a digest instance or a string at #1
pkey:verify: expect a digest instance or a string at #2
"
--- no_error_log
[error]

=== TEST 21: Key derivation for EC, X448 and X25519
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version_num = require("resty.openssl.version").version_num
            local expected = { 24, 32, 56 }
            for i, t in ipairs({"EC", "X25519", "X448"}) do
                if (version_num < 0x10101000 and i == 3) or
                   (version_num < 0x10100000 and i == 2)then
                    ngx.say(expected[i])
                    goto next
                end
                local p = myassert(require("resty.openssl.pkey").new({
                    type = t,
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
"24
32
56"
--- no_error_log
[error]

=== TEST 22: get key type
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p, err = myassert(require("resty.openssl.pkey").new({
                type = 'RSA',
            }))
            ngx.say(encode_sorted_json(p:get_key_type()))
        }
    }
--- request
    GET /t
--- response_body_like eval
'{"id":"1.2.840.113549.1.1.1","ln":"rsaEncryption","nid":6,"sn":"rsaEncryption"}'
--- no_error_log
[error]

=== TEST 23: Raw sign and recover
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = myassert(require("resty.openssl.pkey").new())

            local s = myassert(p:sign_raw("🕶️"))
            ngx.say(#s)

            local v = myassert(p:verify_recover(s))
            ngx.say(v == "🕶️")
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

=== TEST 24: Streaming sign and one shot sign can cross verify
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = myassert(require("resty.openssl.pkey").new())
            local pec = myassert(require("resty.openssl.pkey").new({
                type = "EC",
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
--- skip_openssl
2: < 1.1.1
--- response_body eval
"true
true
true
true
"
--- no_error_log
[error]

=== TEST 25: Outpus DH and EC params
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
                type = 'EC',
                curve = "prime192v1",
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


=== TEST 26: Set DH parameters
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

=== TEST 27: Load parameters for keygen
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
