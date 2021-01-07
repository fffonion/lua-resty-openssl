# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);


repeat_each(2);

my $pwd = cwd();

my $use_luacov = $ENV{'TEST_NGINX_USE_LUACOV'} // '';

add_block_preprocessor(sub {
    my ($block) = @_;

    my $name = $block->name;

    my $http_config = $block->http_config;

    if (defined $http_config ) {

        my $new_http_config = <<_EOC_;
    lua_package_path "$pwd/t/openssl/?.lua;$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";

    init_by_lua_block {
        if "1" == "$use_luacov" then
            require 'luacov.tick'
            jit.off()
        end
        _G.myassert = require("helper").myassert
        _G.encode_sorted_json = require("helper").encode_sorted_json
    }

    ssl_certificate $pwd/t/fixtures/test.crt;
    ssl_certificate_key $pwd/t/fixtures/test.key;

    lua_ssl_trusted_certificate $pwd/t/fixtures/test.crt;

$http_config

_EOC_

        $block->set_value("http_config", $new_http_config);
    }

});


our $ClientContentBy = qq{

};

no_long_string();

run_tests();

__DATA__
=== TEST 1: SSL (server) ger peer ciphers
--- http_config
    server {
        listen unix:/tmp/nginx.sock ssl;
        server_name   test.com;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;

        location /t {
            content_by_lua_block {
                local ssl = require "resty.openssl.ssl"
                local sess = myassert(ssl.from_request())

                local ciphers = myassert(sess:get_ciphers())
                ngx.say(require("cjson").encode(ciphers))

                local cipher = myassert(sess:get_current_cipher())
                ngx.say(cipher)
            }
        }
    }
--- config
    location /t {
        proxy_pass https://unix:/tmp/nginx.sock:;
        proxy_ssl_server_name on;
        proxy_ssl_name test.com;
        # valgrind be happy
        proxy_ssl_session_reuse off;
    }
--- request
    GET /t
--- response_body_like
\[".+,.+"\]
ECDHE-RSA-AES256-GCM-SHA384

--- no_error_log
[error]
[alert]
[emerg]


=== TEST 2: SSL (server) ger peer certificate
--- http_config
    server {
        listen unix:/tmp/nginx.sock ssl;
        server_name   test.com;

        ssl_verify_client optional_no_ca;

        location /t {
            content_by_lua_block {
                local ssl = require "resty.openssl.ssl"
                local sess = myassert(ssl.from_request())

                local ciphers = myassert(sess:get_ciphers())

                local crt = myassert(sess:get_peer_certificate())
                ngx.say(myassert(crt:get_subject_name():tostring()))
            }
        }
    }
--- config
    location /t {
        proxy_pass https://unix:/tmp/nginx.sock:;
        proxy_ssl_server_name on;
        proxy_ssl_name test.com;
        # valgrind be happy
        proxy_ssl_session_reuse off;

        proxy_ssl_certificate ../../../t/fixtures/test.crt;
        proxy_ssl_certificate_key ../../../t/fixtures/test.key;
    }
--- request
    GET /t
--- response_body
CN=test.com

--- no_error_log
[error]
[alert]
[emerg]


=== TEST 3: SSL (server) ger peer cert chain
--- http_config
    server {
        listen unix:/tmp/nginx.sock ssl;
        server_name   test.com;

        ssl_verify_client optional_no_ca;

        location /t {
            content_by_lua_block {
                local ssl = require "resty.openssl.ssl"
                local sess = myassert(ssl.from_request())

                local ciphers = myassert(sess:get_ciphers())

                local chain = myassert(sess:get_peer_cert_chain())
                ngx.say(#chain)
            }
        }
    }
--- config
    location /t {
        proxy_pass https://unix:/tmp/nginx.sock:;
        proxy_ssl_server_name on;
        proxy_ssl_name test.com;
        # valgrind be happy
        proxy_ssl_session_reuse off;

        proxy_ssl_certificate ../../../t/fixtures/test.crt;
        proxy_ssl_certificate_key ../../../t/fixtures/test.key;
    }
--- request
    GET /t
--- response_body
0

--- no_error_log
[error]
[alert]
[emerg]


=== TEST 4: SSL (client) ger ciphers
--- http_config
    server {
        listen unix:/tmp/nginx.sock ssl;
        server_name   test.com;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;
    }
--- config
    location /t {
        default_type 'text/plain';
        content_by_lua_block {
            local sock = ngx.socket.tcp()
            myassert(sock:connect("unix:/tmp/nginx.sock"))
            myassert(sock:sslhandshake(nil, "test.com"))
            local ssl = require "resty.openssl.ssl"
            local sess = myassert(ssl.from_socket(sock))

            ngx.say(require("cjson").encode(myassert(sess:get_ciphers())))

            local cipher = myassert(sess:get_current_cipher())
            ngx.say(cipher)
        }
        more_clear_headers Date;
    }
--- request
    GET /t
--- response_body_like
\[".+,.+"\]
ECDHE-RSA-AES256-GCM-SHA384

--- no_error_log
[error]
[alert]
[emerg]


=== TEST 5: SSL (client) ger peer certificate
--- http_config
    server {
        listen unix:/tmp/nginx.sock ssl;
        server_name   test.com;
    }
--- config
    location /t {
        content_by_lua_block {
            local sock = ngx.socket.tcp()
            myassert(sock:connect("unix:/tmp/nginx.sock"))
            myassert(sock:sslhandshake(nil, "test.com"))
            local ssl = require "resty.openssl.ssl"
            local sess = myassert(ssl.from_socket(sock))

            local crt = myassert(sess:get_peer_certificate())
            ngx.say(myassert(crt:get_subject_name():tostring()))
        }
    }
--- request
    GET /t
--- response_body
CN=test.com

--- no_error_log
[error]
[alert]
[emerg]


=== TEST 6: SSL (client) ger peer cert chain
--- http_config
    server {
        listen unix:/tmp/nginx.sock ssl;
        server_name   test.com;
    }
--- config
    location /t {
        default_type 'text/plain';
        content_by_lua_block {
            local sock = ngx.socket.tcp()
            myassert(sock:connect("unix:/tmp/nginx.sock"))
            myassert(sock:sslhandshake(nil, "test.com"))
            local ssl = require "resty.openssl.ssl"
            local sess = myassert(ssl.from_socket(sock))

            local chain = myassert(sess:get_peer_cert_chain())
            ngx.say(#chain)
            local crt = chain[1]
            ngx.say(myassert(crt:get_subject_name():tostring()))
        }
        more_clear_headers Date;
    }
--- request
    GET /t
--- response_body
1
CN=test.com

--- no_error_log
[error]
[alert]
[emerg]
