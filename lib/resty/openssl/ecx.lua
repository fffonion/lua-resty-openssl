local ffi = require "ffi"
local C = ffi.C
local ffi_str = ffi.string

require "resty.openssl.include.ec"
require "resty.openssl.include.evp"
local ctypes = require "resty.openssl.auxiliary.ctypes"
local format_error = require("resty.openssl.err").format_error

local _M = {}

_M.params = {"public", "private"}

local empty_table = {}

function _M.get_parameters(evp_pkey_st)
  return setmetatable(empty_table, {
    __index = function(_, k)
      local getter
      if k == 'public' or k == "pub_key" then
        getter = C.EVP_PKEY_get_raw_public_key
      elseif k == 'private' or k == "priv_key" then
        getter = C.EVP_PKEY_get_raw_private_key
      else
        return nil, "ecx.get_parameters: unknown raw key parameter \"" .. k .. "\""
      end

      local length = ctypes.ptr_of_size_t()
      if getter(evp_pkey_st, nil, length) ~= 1 then
        return nil
      end
      local buf = ctypes.uchar_array(length[0])
      if getter(evp_pkey_st, buf, length) ~= 1 then
        return nil, format_error("ecx.get_parameters: EVP_PKEY_get_raw_*_key")
      end
      return ffi_str(buf, length[0])
    end
  }), nil
end

function _M.set_parameters(key_type, evp_pkey_st, opts)
  -- for ecx keys we always create a new EVP_PKEY and release the old one
  -- Note: we allow to pass a nil as evp_pkey_st to create a new EVP_PKEY
  local key
  if opts.private then
    local priv = opts.private
    key = C.EVP_PKEY_new_raw_private_key(key_type, nil, priv, #priv)
    if key == nil then
      return nil, format_error("ecx.set_parameters: EVP_PKEY_new_raw_private_key")
    end
  elseif opts.public then
    local pub = opts.public
    key = C.EVP_PKEY_new_raw_public_key(key_type, nil, pub, #pub)
    if key == nil then
      return nil, format_error("ecx.set_parameters: EVP_PKEY_new_raw_public_key")
    end
  else
    return nil, "no parameter is specified"
  end

  if evp_pkey_st ~= nil then
    C.EVP_PKEY_free(evp_pkey_st)
  end
  return key

end

return _M
