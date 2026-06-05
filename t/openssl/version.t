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
OpenSSL \d.\d.\d.+
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
OpenSSL \d.\d.\d.+
compiler:.+
--- no_error_log
[error]



=== TEST 3: Classifies OpenSSL 4 as provider-era
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version = require("resty.openssl.version")
            if version.version_num >= 0x40000000 and version.version_num < 0x50000000 then
                ngx.say(version.OPENSSL_4X)
                ngx.say(version.OPENSSL_3_UP)
                ngx.say(version.OPENSSL_3X)
                return
            end

            ngx.say("not 4x")
        }
    }
--- request
    GET /t
--- response_body_like
(?:true\s+true\s+false|not 4x)
--- no_error_log
[error]



=== TEST 4: Handles removed OpenSSL 4 info entries
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local version = require("resty.openssl.version")
            if not version.OPENSSL_3_UP then
                ngx.say("not 3x up")
                return
            end

            local info = version.info(version.INFO_ENGINES_DIR)
            if version.OPENSSL_4X then
                ngx.say(info == nil)
                return
            end

            ngx.say(type(info) == "string")
        }
    }
--- request
    GET /t
--- response_body_like
(?:true|not 3x up)
--- no_error_log
[error]
