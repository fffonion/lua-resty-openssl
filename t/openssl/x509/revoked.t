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
=== TEST 1:revoked.new should create new revoked instance
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
           local revoked =  myassert(require("resty.openssl.x509.revoked"))
            local toset = ngx.time()
            local r, err = revoked.new(1234, toset, 1)
            if err then
              ngx.say(err)
            elseif not revoked.istype(r) then
             ngx.say("it should be instance of revoked")
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

=== TEST 2:revoked.new should fail when invalid parameters are given
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local f = io.open("t/fixtures/TrustAsiaEVTLSProCAG2.crl"):read("*a")
            local revoked =  myassert(require("resty.openssl.x509.revoked"))
            local toset = ngx.time()
            local r, err = revoked.new("1234", toset, 40)
            if r ~= nil then
                ngx.say("false")
            elseif err ~= "revoked.new: sn should be number or a bn instance" then
                ngx.say("false")
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