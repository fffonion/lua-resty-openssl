# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
};

run_tests();

__DATA__
=== TEST 1: Don't cry if there's no error
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local format_error = require("resty.openssl.err").format_error

            ngx.print(format_error("fake function"))
        }
    }
--- request
    GET /t
--- response_body eval
"fake function failed"
--- no_error_log
[error]
