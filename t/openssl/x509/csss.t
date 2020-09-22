# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

my $use_luacov = $ENV{'TEST_NGINX_USE_LUACOV'} // '';

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

no_long_string();

run_tests();

__DATA__
=== TEST 4: Generates CSR with RSA pkey correctly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local util = require("csr")
            local pkey = require("resty.openssl.pkey").new()
            local der = myassert(util.create_csr(pkey, "dns1.com", "dns2.com", "dns3.com"))

            ngx.update_time()
            local fname = "ci_" .. math.floor(ngx.now() * 1000)
            local f = io.open(fname, "wb")
            f:write(der)
            f:close()
            ngx.say(io.popen("openssl req -inform der -in " .. fname .. " -noout -text", 'r'):read("*a"))
            os.remove(fname)
        }
    }
--- request
    GET /t
--- response_body_like eval
".+CN\\s*=\\s*dns1.com.+rsaEncryption.+2048 bit.+DNS:dns1.com.+DNS:dns2.com.+DNS:dns3.com"
--- no_error_log
[error]

