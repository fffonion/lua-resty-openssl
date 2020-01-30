# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/t/openssl/x509/?.lua;$pwd/lib/?.lua;$pwd/lib/?/init.lua;$pwd/../lib/?.lua;$pwd/../lib/?/init.lua;;";
};


run_tests();

__DATA__
=== TEST 1: NOOP
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
        }
    }
--- request
    GET /t
--- no_error_log
[error]