# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/t/openssl/x509/?.lua;$pwd/lib/?.lua;$pwd/lib/?/init.lua;$pwd/../lib/?.lua;$pwd/../lib/?/init.lua;;";
};


run_tests();

__DATA__
=== TEST 1: Generates CSR with RSA pkey correctly
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local util = require("csr")
            local pkey = require("resty.openssl.pkey").new()
            local der, err = util.create_csr(pkey, "dns1.com", "dns2.com", "dns3.com")
            if err then
                ngx.log(ngx.ERR, err)
                return
            end
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

=== TEST 2: Rejects invalid arguments
--- http_config eval: $::HttpConfig
--- config
    location =/t {
        content_by_lua_block {
            local csr = require("resty.openssl.x509.csr").new()
            err = csr:set_subject_name("not a subject")
            ngx.say(err)
            err = csr:set_subject_alt("not an alt")
            ngx.say(err)
            err = csr:set_pubkey("not a pkey")
            ngx.say(err)
            err = csr:sign("not a pkey")
            ngx.say(err)
        }
    }
--- request
    GET /t
--- response_body eval
"expect a x509.name instance at #1
expect a x509.altname instance at #1
expect a pkey instance at #1
expect a pkey instance at #1
"
--- no_error_log
[error]