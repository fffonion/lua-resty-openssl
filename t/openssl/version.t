# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
};

run_tests();

__DATA__
=== TEST 1: Prints version text properly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version = require("resty.openssl.version")
            ngx.say(version.version_text)
        }
    }
--- request
    GET /t
--- response_body_like
OpenSSL 1.\d.\d.+
--- no_error_log
[error]

=== TEST 2: Prints version text using version()
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version = require("resty.openssl.version")
            ngx.say(version.version(version.VERSION))
            ngx.say(version.version(version.CFLAGS))
        }
    }
--- request
    GET /t
--- response_body_like
OpenSSL 1.\d.\d.+
compiler:.+
--- no_error_log
[error]
