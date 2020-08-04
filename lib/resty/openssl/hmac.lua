local ffi = require "ffi"
local C = ffi.C
local ffi_gc = ffi.gc
local ffi_str = ffi.string

require "resty.openssl.include.hmac"
local ctypes = require "resty.openssl.aux.ctypes"
local format_error = require("resty.openssl.err").format_error
local OPENSSL_10 = require("resty.openssl.version").OPENSSL_10
local OPENSSL_11_OR_LATER = require("resty.openssl.version").OPENSSL_11_OR_LATER
local hmac_ctx_ptr_ct = ffi.typeof('HMAC_CTX*')
local uchar_array = ctypes.uchar_array
local ptr_of_uint = ctypes.ptr_of_uint

local _M = {}

-- Note: https://www.openssl.org/docs/manmaster/man3/HMAC_Init.html
-- Replace with EVP_MAC_* functions for OpenSSL 3.0

function _M.new(key, typ)
    local ctx
    if OPENSSL_11_OR_LATER then
        ctx = C.HMAC_CTX_new()
        ffi_gc(ctx, C.HMAC_CTX_free)
    elseif OPENSSL_10 then
        ctx = ffi.new('HMAC_CTX')
        C.HMAC_CTX_init(ctx)
        ffi_gc(ctx, C.HMAC_CTX_cleanup)
    end
    if ctx == nil then
        return nil, "hmac.new: failed to create HMAC_CTX"
    end

    local dtyp = C.EVP_get_digestbyname(typ or 'sha1')
    if dtyp == nil then
        return nil, ("hmac.new: invalid digest type \"%s\""):format(typ)
    end

    local code = C.HMAC_Init_ex(ctx, key, #key, dtyp, nil)
    if code ~= 1 then
        return nil, format_error("hmac.new")
    end

    return setmetatable({
        ctx = ctx,
        dtyp = dtyp,
        buf = uchar_array(C.EVP_MD_size(dtyp)),
    }, { __index = _M }), nil
end

function _M.istype(l)
    return l and l.ctx and ffi.istype(hmac_ctx_ptr_ct, l.ctx)
end

function _M.update(self, s)
    if C.HMAC_Update(self.ctx, s, #s) ~= 1 then
        return false, format_error("hmac:update")
    end
    return true, nil
end

function _M.final(self, s)
    if s then
        local _, err = self:update(s)
        if err then
            return nil, err
        end
    end

    local length = ptr_of_uint()
    if C.HMAC_Final(self.ctx, self.buf, length) ~= 1 then
        return nil, format_error("hmac:final: HMAC_Final")
    end
    return ffi_str(self.buf, length[0])
end

function _M.reset(self)
    local code = C.HMAC_Init_ex(self.ctx, nil, 0, nil, nil)
    if code ~= 1 then
        return false, format_error("hmac:reset")
    end
    return true
end

return _M
