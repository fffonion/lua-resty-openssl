# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/t/openssl/x509/?.lua;$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
};


run_tests();

__DATA__
=== TEST 1: Loads a pem cert (FLICKY)
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            os.execute("openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem -subj '/'")
            ngx.update_time()
            local nb_expected = math.floor(ngx.now())
            local na_expected = math.floor(nb_expected + 365 * 86400)
            local pem = io.open("cert.pem"):read("*a")
            local x509 = require("resty.openssl.x509")
            local p, err = x509.new(pem)
            if err then
                ngx.say("1 " .. err)
                ngx.exit(0)
            end
            local not_before, not_after, err = p:get_lifetime()
            if err then
                ngx.say("2 " .. err)
                ngx.exit(0)
            end
            ngx.say(not_before == nb_expected or {not_before, "!=", nb_expected})
            ngx.say(not_after == na_expected or {not_after, "!=", na_expected})
            os.remove("key.pem")
            os.remove("cert.pem")
        }
    }
--- request
    GET /t
--- response_body eval
"true
true
"
--- no_error_log
[error]

=== TEST 2: Rejectes invalid cert
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
x509.new: .*pem_lib.c.+
"
--- no_error_log
[error]


=== TEST 3: Exports public key
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local c, key = require("helper").create_self_signed()
            local p, err = c:get_pubkey()
            if err then
                ngx.say("2 " .. err)
                ngx.exit(0)
            end
            ngx.say(p:to_PEM():sub(1, 26))
            ngx.print(c:get_pubkey():to_PEM() == key:to_PEM("public"))
        }
    }
--- request
    GET /t
--- response_body eval
"-----BEGIN PUBLIC KEY-----
true"
--- no_error_log
[error]


=== TEST 4: Calculates cert digest
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

=== TEST 5: Calculates pubkey digest
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