# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

repeat_each(2);
my $pwd = cwd();

add_block_preprocessor(sub {
    my ($block) = @_;
    my $http_config = $block->http_config // "";
    my $config = $block->config;
    $config =~ s/content_by_lua_block \{/content_by_lua_block {
            package.loaded["resty.openssl.auxiliary.nginx"] = nil
            package.loaded["resty.openssl.auxiliary.nginx_legacy"] = nil
            -- Mock symbol availability so selection tests also run on older binaries.
            local real_ffi = require "ffi"
            package.loaded.ffi = setmetatable({
                C = setmetatable({}, {
                    __index = function(_, name)
                        if name == "ngx_http_lua_ffi_socket_tcp_get_ssl_pointer"
                           or name == "ngx_http_lua_ffi_socket_tcp_get_ssl_ctx"
                           or name == "ngx_stream_lua_ffi_socket_tcp_get_ssl_pointer"
                           or name == "ngx_stream_lua_ffi_socket_tcp_get_ssl_ctx" then
                            return true
                        end
                        return real_ffi.C[name]
                    end,
                }),
            }, { __index = real_ffi })/;
    $block->set_value("config", $config);
    $block->set_value("http_config", qq{
        lua_package_path "$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
        $http_config
    });
});

no_long_string();
run_tests();

__DATA__

=== TEST 1: native request SSL API avoids legacy initialization
--- config
    location /t {
        content_by_lua_block {
            local ffi = require "ffi"
            local expected = ffi.cast("void *", 1)
            require("ngx.ssl").get_req_ssl_pointer = function()
                return expected
            end
            package.preload["resty.openssl.auxiliary.nginx_legacy"] = function()
                error("legacy must not load")
            end
            local aux = require "resty.openssl.auxiliary.nginx"
            local ssl = assert(aux.get_req_ssl())
            ngx.say(ffi.istype("SSL *", ssl))
            ngx.say(ffi.cast("void *", ssl) == expected)
        }
    }
--- request
GET /t
--- response_body
true
true
--- no_error_log
[error]


=== TEST 2: native socket APIs preserve SSL and SSL_CTX pointer types
--- config
    location /t {
        content_by_lua_block {
            local ffi = require "ffi"
            local ssl = ffi.cast("void *", 1)
            local ctx = ffi.cast("void *", 2)
            local sock = {
                getsslpointer = function() return ssl end,
                getsslctx = function() return ctx end,
            }
            package.preload["resty.openssl.auxiliary.nginx_legacy"] = function()
                error("legacy must not load")
            end
            local aux = require "resty.openssl.auxiliary.nginx"
            local actual_ssl = assert(aux.get_socket_ssl(sock))
            local actual_ctx = assert(aux.get_socket_ssl_ctx(sock))
            ngx.say(ffi.istype("SSL *", actual_ssl))
            ngx.say(ffi.istype("SSL_CTX *", actual_ctx))
            ngx.say(ffi.cast("void *", actual_ssl) == ssl)
            ngx.say(ffi.cast("void *", actual_ctx) == ctx)
        }
    }
--- request
GET /t
--- response_body
true
true
true
true
--- no_error_log
[error]


=== TEST 3: native errors are returned without trying legacy getters
--- config
    location /t {
        content_by_lua_block {
            require("ngx.ssl").get_req_ssl_pointer = function()
                return nil, "request has no SSL"
            end
            package.preload["resty.openssl.auxiliary.nginx_legacy"] = function()
                error("legacy must not load")
            end
            local sock = {
                getsslpointer = function() return nil, "socket closed" end,
                getsslctx = function() return nil, "socket has no SSL context" end,
            }
            local aux = require "resty.openssl.auxiliary.nginx"
            local ssl, err = aux.get_req_ssl()
            ngx.say(ssl, ": ", err)
            ssl, err = aux.get_socket_ssl(sock)
            ngx.say(ssl, ": ", err)
            ssl, err = aux.get_socket_ssl_ctx(sock)
            ngx.say(ssl, ": ", err)
        }
    }
--- request
GET /t
--- response_body
nil: request has no SSL
nil: socket closed
nil: socket has no SSL context
--- no_error_log
[error]


=== TEST 4: unavailable getters use lazy legacy getters
--- config
    location /t {
        content_by_lua_block {
            require("ngx.ssl").get_req_ssl_ctx = nil
            local count = 0
            local sock = {}
            package.preload["resty.openssl.auxiliary.nginx_legacy"] = function()
                count = count + 1
                return {
                    get_req_ssl_ctx = function() return "request session_ctx" end,
                    get_socket_ssl = function(s)
                        assert(s == sock)
                        return nil, "legacy socket error"
                    end,
                    get_socket_ssl_ctx = function(s)
                        assert(s == sock)
                        return "socket session_ctx"
                    end,
                }
            end
            local aux = require "resty.openssl.auxiliary.nginx"
            ngx.say(count)
            ngx.say(aux.get_req_ssl_ctx())
            local ssl, err = aux.get_socket_ssl(sock)
            ngx.say(ssl, ": ", err)
            ngx.say(aux.get_socket_ssl_ctx(sock))
            ngx.say(count)
        }
    }
--- request
GET /t
--- response_body
0
request session_ctx
nil: legacy socket error
socket session_ctx
1
--- no_error_log
[error]


=== TEST 5: partial C API availability falls back independently
--- config
    location /t {
        content_by_lua_block {
            local ffi = require "ffi"
            require "resty.core.socket"
            require "ngx.ssl"
            require "resty.openssl.include.ssl"
            package.loaded.ffi = setmetatable({
                C = setmetatable({}, {
                    __index = function(_, name)
                        if name == "ngx_http_lua_ffi_socket_tcp_get_ssl_ctx" then
                            error("missing C symbol")
                        end
                        return ffi.C[name]
                    end,
                }),
            }, { __index = ffi })
            local sock = {
                getsslpointer = function() return ffi.cast("void *", 1) end,
                getsslctx = function() error("unavailable C API called") end,
            }
            package.preload["resty.openssl.auxiliary.nginx_legacy"] = function()
                return {
                    get_socket_ssl = function() error("native SSL API available") end,
                    get_socket_ssl_ctx = function() return "legacy context" end,
                }
            end
            local aux = require "resty.openssl.auxiliary.nginx"
            ngx.say(ffi.istype("SSL *", assert(aux.get_socket_ssl(sock))))
            ngx.say(aux.get_socket_ssl_ctx(sock))
        }
    }
--- request
GET /t
--- response_body
true
legacy context
--- no_error_log
[error]


=== TEST 6: missing lua-resty-core APIs retain legacy support
--- config
    location /t {
        content_by_lua_block {
            for _, name in ipairs({"ngx.ssl", "resty.core.socket"}) do
                package.loaded[name] = nil
                package.preload[name] = function() error("unavailable module") end
            end
            package.preload["resty.openssl.auxiliary.nginx_legacy"] = function()
                return {
                    get_req_ssl = function() return "legacy request SSL" end,
                    get_req_ssl_ctx = function() return "legacy request context" end,
                    get_socket_ssl = function() return "legacy socket SSL" end,
                    get_socket_ssl_ctx = function() return "legacy socket context" end,
                }
            end
            local aux = require "resty.openssl.auxiliary.nginx"
            ngx.say(aux.get_req_ssl())
            ngx.say(aux.get_req_ssl_ctx())
            ngx.say(aux.get_socket_ssl({}))
            ngx.say(aux.get_socket_ssl_ctx({}))
        }
    }
--- request
GET /t
--- response_body
legacy request SSL
legacy request context
legacy socket SSL
legacy socket context
--- no_error_log
[error]


=== TEST 7: C module fallback uses the SSL_CTX getter
--- config
    location /t {
        content_by_lua_block {
            require "resty.openssl.include.ssl"
            local getenv = os.getenv
            os.getenv = function(name)
                if name == "CI_SKIP_NGINX_C" then
                    return nil
                end
                return getenv(name)
            end
            package.loaded["resty.openssl.auxiliary.nginx_c"] = {
                get_socket_ssl = function() return "SSL" end,
                get_socket_ssl_ctx = function() return "SSL_CTX" end,
            }
            local legacy = require "resty.openssl.auxiliary.nginx_legacy"
            ngx.say(legacy.get_socket_ssl({}))
            ngx.say(legacy.get_socket_ssl_ctx({}))
        }
    }
--- request
GET /t
--- response_body
SSL
SSL_CTX
--- no_error_log
[error]


=== TEST 8: stream selects native request and socket APIs
--- config
    location /t {
        content_by_lua_block {
            local ffi = require "ffi"
            local ngx_ssl = require "ngx.ssl"
            require "resty.core.socket"
            ngx.config.subsystem = "stream"
            ngx_ssl.get_req_ssl_pointer = function()
                return ffi.cast("void *", 1)
            end
            ngx_ssl.get_req_ssl_ctx = function()
                return ffi.cast("void *", 4)
            end
            package.preload["resty.openssl.auxiliary.nginx_legacy"] = function()
                error("legacy must not load")
            end
            local sock = {
                getsslpointer = function() return ffi.cast("void *", 2) end,
                getsslctx = function() return ffi.cast("void *", 3) end,
            }
            local aux = require "resty.openssl.auxiliary.nginx"
            ngx.say(ffi.istype("SSL *", assert(aux.get_req_ssl())))
            ngx.say(ffi.istype("SSL_CTX *", assert(aux.get_req_ssl_ctx())))
            ngx.say(ffi.istype("SSL *", assert(aux.get_socket_ssl(sock))))
            ngx.say(ffi.istype("SSL_CTX *", assert(aux.get_socket_ssl_ctx(sock))))
        }
    }
--- request
GET /t
--- response_body
true
true
true
true
--- no_error_log
[error]


=== TEST 9: native request SSL_CTX API avoids legacy initialization
--- config
    location /t {
        content_by_lua_block {
            local ffi = require "ffi"
            local expected = ffi.cast("void *", 4)
            require("ngx.ssl").get_req_ssl_ctx = function()
                return expected
            end
            package.preload["resty.openssl.auxiliary.nginx_legacy"] = function()
                error("legacy must not load")
            end
            local aux = require "resty.openssl.auxiliary.nginx"
            local ctx = assert(aux.get_req_ssl_ctx())
            ngx.say(ffi.istype("SSL_CTX *", ctx))
            ngx.say(ffi.cast("void *", ctx) == expected)
        }
    }
--- request
GET /t
--- response_body
true
true
--- no_error_log
[error]


=== TEST 10: native request SSL_CTX errors do not trigger legacy fallback
--- config
    location /t {
        content_by_lua_block {
            require("ngx.ssl").get_req_ssl_ctx = function()
                return nil, "bad ssl context"
            end
            package.preload["resty.openssl.auxiliary.nginx_legacy"] = function()
                error("legacy must not load")
            end
            local aux = require "resty.openssl.auxiliary.nginx"
            local ctx, err = aux.get_req_ssl_ctx()
            ngx.say(ctx, ": ", err)
        }
    }
--- request
GET /t
--- response_body
nil: bad ssl context
--- no_error_log
[error]
