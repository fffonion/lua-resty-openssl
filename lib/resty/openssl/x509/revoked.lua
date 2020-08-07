local ffi = require "ffi"
local bn_lib = require("resty.openssl.bn")
require("resty.openssl.include.x509.crl")
require("resty.openssl.include.x509.revoked")
local NID_crl_reason = 141
local C = ffi.C
local ffi_gc = ffi.gc
local _M = {}
local revoked_ptr_ct = ffi.typeof('X509_REVOKED *')

--- Creates new instance of X509_REVOKED data
-- @tparam bn|number sn Serial number as number or bn instance
-- @tparam number time Revocation time
-- @tparam number reason Revocation reason
-- @treturn table instance of the module or nil
-- @treturn[opt] string Returns optional error message in case of error
function _M.new(sn, time, reason)
    --- only convert to bn if it is number
    if type(sn) == "number"then
        sn = bn_lib.new(sn)
    end
    if not bn_lib.istype(sn) then
        return nil, "revoked.new: sn should be number or a bn instance"
    end

    local revoked = C.X509_REVOKED_new()
    ffi_gc(revoked, C.X509_REVOKED_free)

    time = C.ASN1_TIME_set(nil, time)
    if time == nil then
        return nil, "revoked.new: ASN1_TIME_set() failed"
    end
    ffi_gc(time, C.ASN1_STRING_free)

    local it = C.BN_to_ASN1_INTEGER(sn.ctx, nil)
    if it == nil then
        return nil, "revoked.new: BN_to_ASN1_INTEGER() failed"
    end
    C.ASN1_INTEGER_free(it)

    if C.X509_REVOKED_set_revocationDate(revoked, time) == 0 then
        return nil, "revoked.new: X509_REVOKED_set_revocationDate() failed"
    end

    if C.X509_REVOKED_set_serialNumber(revoked, it) == 0 then
        return nil, "revoked.new: X509_REVOKED_set_serialNumber() failed"
    end

    local e = C.ASN1_ENUMERATED_new()
    if e == nil then
        return nil, "revoked.new: ASN1_ENUMERATED_new() failed"
    end
    ffi_gc(e, C.ASN1_ENUMERATED_free)

    local ext = C.X509_EXTENSION_new()
    if ext == nil then
        return nil, "revoked.new: X509_EXTENSION_new() failed"
    end
    ffi_gc(ext, C.X509_EXTENSION_free)

    if C.ASN1_ENUMERATED_set(e, reason) == 0 then
        return nil, "revoked.new: ASN1_ENUMERATED_set() failed"
    end

    if C.X509_EXTENSION_set_data(ext, e) == 0 then
        return nil, "revoked.new: X509_EXTENSION_set_data() failed"
    end
    if C.X509_EXTENSION_set_object(ext, C.OBJ_nid2obj(NID_crl_reason)) == 0 then
        return nil, "revoked.new: X509_EXTENSION_set_object() failed"
    end

    if C.X509_REVOKED_add_ext(revoked, ext, 0) == 0 then
        return nil, "revoked.new: X509_EXTENSION_set_object() failed"
    end

    return { ctx = revoked, { __index = _M } }
end

--- Type check
-- @tparam table Instance of revoked module
-- @treturn boolean true if instance is instance of revoked module false otherwise
function _M.istype(l)
    return l and l.ctx and ffi.istype(revoked_ptr_ct, l.ctx)
end

return _M