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
=== TEST 1: Convert nid to table
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local o = require("resty.openssl.objects")
            ngx.print(require("cjson").encode(o.nid2table(87)))
        }
    }
--- request
    GET /t
--- response_body_like eval
'{"ln":"X509v3 Basic Constraints","nid":87,"sn":"basicConstraints","id":"2.5.29.19"}'
--- no_error_log
[error]


=== TEST 2: Convert txt to nid
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local o = require("resty.openssl.objects")
            local t = {
                ln = "X509v3 Basic Constraints",
                sn = "basicConstraints",
                id = "2.5.29.19"
            }
            for k, v in pairs(t) do
                ngx.say(k, " ", o.txt2nid(v))
            end
        }
    }
--- request
    GET /t
--- response_body_like eval
"id 87
sn 87
ln 87
"
--- no_error_log
[error]