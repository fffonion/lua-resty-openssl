local ffi = require "ffi"
local bn_lib = require("resty.openssl.bn")
require("resty.openssl.include.x509.crl")
local NID_crl_reason = 141
local C = ffi.C
local ffi_gc = ffi.gc
local _M = {}
local revoked_ptr_ct = ffi.typeof('X509_REVOKED *')

--- Creates new instance of X509_REVOKED data
-- @tparam number sn Serial number
-- @tparam number time Revocation time
-- @tparam number reason Revocation reason
-- @treturn table instance of the module or nil
-- @treturn[opt] string Returns optional error message in case of error
function _M.new(sn, time, reason)
    sn = bn_lib.new(sn)
    local revoked = C.X509_REVOKED_new()
    time = C.ASN1_TIME_set(nil, time)
    if time == nil then
        return nil, "x509.revoked.new: ASN1_TIME_set() failed"
    end

    local it = C.BN_to_ASN1_INTEGER(sn.ctx, nil)
    if it == nil then
        return nil, "x509.revoked.new: BN_to_ASN1_INTEGER() failed"
    end

    if C.X509_REVOKED_set_revocationDate(revoked, time) == 0 then
        return nil, "x509.revoked.new: X509_REVOKED_set_revocationDate() failed"
    end

    if C.X509_REVOKED_set_serialNumber(revoked, it) == 0 then
        return nil, "x509.revoked.new: X509_REVOKED_set_serialNumber() failed"
    end

    local e = C.ASN1_ENUMERATED_new()
    if e == nil then
        return nil, "x509.revoked.new: ASN1_ENUMERATED_new() failed"
    end

    local ext = C.X509_EXTENSION_new()
    if ext == nil then
        return nil, "x509.revoked.new: X509_EXTENSION_new() failed"
    end

    if C.ASN1_ENUMERATED_set(e, reason) == 0 then
        return nil, "x509.revoked.new: ASN1_ENUMERATED_set() failed"
    end

    if C.X509_EXTENSION_set_data(ext, e) == 0 then
        return nil, "x509.revoked.new: X509_EXTENSION_set_data() failed"
    end
    if C.X509_EXTENSION_set_object(ext, C.OBJ_nid2obj(NID_crl_reason)) == 0 then
        return nil, "x509.revoked.new: X509_EXTENSION_set_object() failed"
    end

    if C.X509_REVOKED_add_ext(revoked, ext, 0) == 0 then
        return nil, "x509.revoked.new: X509_EXTENSION_set_object() failed"
    end

    ffi_gc(time, C.ASN1_ENUMERATED_free)
    ffi_gc(e, C.ASN1_ENUMERATED_free)
    ffi_gc(ext, C.X509_EXTENSION_free)
    ffi_gc(revoked, C.X509_REVOKED_free)
    return { ctx = revoked, { __index = _M } }
end

--- Type check
-- @tparam table Instance of revoked module
-- @treturn boolean true if instance is instance of revoked module false otherwise
function _M.istype(l)
    return l and l.ctx and ffi.istype(revoked_ptr_ct, l.ctx)
end

return _M