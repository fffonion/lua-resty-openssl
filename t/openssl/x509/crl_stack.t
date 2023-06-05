# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

my $use_luacov = $ENV{'TEST_NGINX_USE_LUACOV'} // '';
our $crl = qq{-----BEGIN X509 CRL-----
MIIDVzCCAT8CAQEwDQYJKoZIhvcNAQELBQAwWzELMAkGA1UEBhMCVVMxCzAJBgNV
BAgMAkNBMQ0wCwYDVQQKDARrb25nMQwwCgYDVQQLDANGVFQxIjAgBgNVBAMMGXd3
dy5pbnRlcm1lZGlhdGUua29uZy5jb20XDTIzMDYwMTA3NDcxM1oXDTIzMDcwMTA3
NDcxM1owfjATAgIQBBcNMjMwNjAxMDc0NzEzWjATAgIQBRcNMjMwNjAxMDc0NzEz
WjATAgIQBhcNMjMwNjAxMDc0NzEzWjATAgIQChcNMjMwNjAxMDc0NzEzWjATAgIQ
CxcNMjMwNjAxMDc0NzEzWjATAgIQDBcNMjMwNjAxMDc0NzEzWqAwMC4wHwYDVR0j
BBgwFoAUWSprg/Oa2fI9gK2FTD7w1mrqD64wCwYDVR0UBAQCAhAGMA0GCSqGSIb3
DQEBCwUAA4ICAQAYPNSgDSk2okFG3dXbTwbX5bDPFUSy92u1YsHV0k1Zu66qf3Hq
v2YjXkBj56cuEFX5m+y47fYwAuKzcb8FdWk+k6ArHoE24wpWjJmcvQwzZyKkUQZA
nlCXYI6UCvzSBbnG/+fF6WOUHOh2su7GqmxdIJw/Cf58ldoB0HQ/ubFcjLe3ecF5
sxvtqBIU5LD4Dlq17IQVE152NuyuzsqCLy30/t4h8cyeY+XjGbj9Coq9b10hde1o
oHa4oySQO/qIYKBC4+YjhwOWIjq9+ABwSUkQFR59yifeJSXA+Q9a7uNHgByBXw60
0ayYX6qbqIwRuLc+uyb2RZTXUbbty2tzKtkx1LBPVweY7ZQDRYDajbihTxkwEJEe
exj05M0+OwpcUQuTa+7AqL294FIKB9/n3x0M0gB99gSUdWB3JgSDMth+ANX642cS
pcZm7l0VYAKJGELbRkOoENF2v1IsV69OHCPGt4L9ST6bQX6tWgNJrA87jRD4RaBW
cCxs2RsuYnV9+1YwUVlT31Qksrks4YKAc8QnCxDkAOwJV2FNjMxjQKaXcAz5dApY
Dx/6wD0QMN2Wops0zzAZekZAnc9bdo6hAvsqd+PyOTXTTZoWYdLH6wKv5E1Q36bW
2iVSM1K1x5UCWHS1ABLHGjROooT8PbbwBkr0oHYOe26raieVNPQTt8CaBQ==
-----END X509 CRL-----
};

our $HttpConfig = qq{
    lua_package_path "$pwd/t/openssl/?.lua;$pwd/t/openssl/x509/?.lua;$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
    init_by_lua_block {
        if "1" == "$use_luacov" then
            require 'luacov.tick'
            jit.off()
        end
        _G.myassert = require("helper").myassert
    }
};


run_tests();

__DATA__
=== TEST 1: Creates stack properly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local crl_stack_lib = require("resty.openssl.x509.crl_stack")
            local c = myassert(crl_stack_lib.new())

            ngx.say(#c)
        }
    }
--- request
    GET /t
--- response_body eval
"0
"
--- no_error_log
[error]

=== TEST 2: Adds elements to stack properly
--- http_config eval: $::HttpConfig
--- config eval
"
    location =/t {
        content_by_lua_block {
            local crl_lib = require('resty.openssl.x509.crl')
            local crl = crl_lib.new([[$::crl]])
            local crl_stack_lib = require('resty.openssl.x509.crl_stack')
            local c = myassert(crl_stack_lib.new())

            for i=0,2,1 do
                local ok = myassert(c:add(crl))
            end
            ngx.say(#c)
            ngx.say(#c:all())
        }
    }
"
--- request
    GET /t
--- response_body eval
"3
3
"
--- no_error_log
[error]

=== TEST 3: Element can be indexed properly
--- http_config eval: $::HttpConfig
--- config eval
"
    location =/t {
        content_by_lua_block {
            local crl_lib = require('resty.openssl.x509.crl')
            local crl = crl_lib.new([[$::crl]])
            local crl_stack_lib = require('resty.openssl.x509.crl_stack')
            local c = myassert(crl_stack_lib.new())

            for i=0,2,1 do
                local ok = myassert(c:add(crl))
            end

            collectgarbage()
            
            for _, cc in ipairs(c) do
                ngx.say(cc:to_PEM())
            end
        }
    }
"
--- request
    GET /t
--- response_body eval
"$::crl
$::crl
$::crl
"
--- no_error_log
[error]

=== TEST 4: Element is duplicated when added to stack
--- http_config eval: $::HttpConfig
--- config eval
"
    location =/t {
        content_by_lua_block {
            local crl_lib = require('resty.openssl.x509.crl')
            local crl = crl_lib.new([[$::crl]])
            local crl_stack_lib = require('resty.openssl.x509.crl_stack')
            local c = myassert(crl_stack_lib.new())

            local ok = myassert(c:add(crl))

            crl = nil
            collectgarbage('collect')
            ngx.say(c[1]:to_PEM())
        }
    }
"
--- request
    GET /t
--- response_body eval
"$::crl
"
--- no_error_log
[error]

=== TEST 5: Element is duplicated when returned
--- http_config eval: $::HttpConfig
--- config eval
"
    location =/t {
        content_by_lua_block {
            local crl_lib = require('resty.openssl.x509.crl')
            local crl = crl_lib.new([[$::crl]])
            local crl_stack_lib = require('resty.openssl.x509.crl_stack')
            local c = myassert(crl_stack_lib.new())

            local ok = myassert(c:add(crl))

            local cc = c[1]
            c = nil
            collectgarbage('collect') 
            ngx.say(cc:to_PEM())
        }
    }
"
--- request
    GET /t
--- response_body eval
"$::crl
"
--- no_error_log
[error]

=== TEST 6: Element is not freed when stack is duplicated
--- http_config eval: $::HttpConfig
--- config eval
"
    location =/t {
        content_by_lua_block {
            local crl_lib = require('resty.openssl.x509.crl')
            local crl = crl_lib.new([[$::crl]])
            local crl_stack_lib = require('resty.openssl.x509.crl_stack')
            local c = myassert(crl_stack_lib.new())

            local ok = myassert(c:add(crl))

            local c2 = myassert(crl_stack_lib.dup(c.ctx))

            c = nil
            collectgarbage('collect') 
            ngx.say(c2:count())
            ngx.say(c2[1]:to_PEM())
        }
    }
"
--- request
    GET /t
--- response_body eval
"1
$::crl
"
--- no_error_log
[error]
