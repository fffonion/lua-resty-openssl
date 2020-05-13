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
            local version_num = require("resty.openssl.version").version_num
            if version_num < 0x10101000 then
                ngx.say('-----BEGIN PRIVATE KEY-----')
                ngx.say('fake')
                ngx.say('true')
                return
            end
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

=== TEST 5: Rejects invalid arg
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

=== TEST 6: Loads encrypted PEM pkey with passphrase
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

=== TEST 7: Loads encrypted PEM pkey with passphrase callback
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

=== TEST 8: Loads DER format
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

=== TEST 9: Outputs DER and JWK
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

121
.+kid.+"
--- no_error_log
[error]

=== TEST 10: Outputs public key
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

=== TEST 11: Extracts RSA parameters
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
"[A-F0-9]{512}
[A-F0-9]{6}
[A-F0-9]{512}
[A-F0-9]{256}
[A-F0-9]{256}
[A-F0-9]{256}
[A-F0-9]{256}
[A-F0-9]{256}
nil
"
--- no_error_log
[error]

=== TEST 12: Extracts EC parameters
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
[A-F0-9]{98}
[A-F0-9]{48}
[A-F0-9]{48}
[A-F0-9]{48}
nil
"
--- no_error_log
[error]

=== TEST 13: Extracts Ed25519 parameters
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version_num = require("resty.openssl.version").version_num
            if version_num < 0x10101000 then
                ngx.say('32')
                ngx.say('32')
                return
            end
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

=== TEST 14: Encrypt and decrypt
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


=== TEST 15: Sign and verify
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

=== TEST 16: One shot sign and verify
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version_num = require("resty.openssl.version").version_num
            if version_num < 0x10101000 then
                ngx.say('64')
                ngx.say('true')
                return
            end
            local p = myassert(require("resty.openssl.pkey").new({
                type = "Ed25519"
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
"
--- no_error_log
[error]

=== TEST 17: Error on bad digest or verify parameters
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p = myassert(require("resty.openssl.pkey").new())

            local s, err = p:sign("not a cdata")
            ngx.say(err)
            local v, err = p:verify(s, "not a cdata")
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body eval
"pkey:sign: expect a digest instance at #1
pkey:verify: expect a digest instance at #2
"
--- no_error_log
[error]

=== TEST 18: Key derivation for EC, X448 and X25519
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

=== TEST 19: get key type
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local p, err = require("resty.openssl.pkey").new({
                type = 'RSA',
            })
            ngx.say(require("cjson").encode(p:get_key_type()))
        }
    }
--- request
    GET /t
--- response_body_like eval
'{"ln":"rsaEncryption","nid":6,"sn":"rsaEncryption","id":"1.2.840.113549.1.1.1"}'
--- no_error_log
[error]
