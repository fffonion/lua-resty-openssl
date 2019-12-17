-- https://github.com/GUI/lua-openssl-ffi/blob/master/lib/openssl-ffi/version.lua
local ffi = require "ffi"
local C = ffi.C
local ffi_str = ffi.string

ffi.cdef[[
  // 1.0
  unsigned long SSLeay(void);
  const char *SSLeay_version(int t);
  // 1.1
  unsigned long OpenSSL_version_num();
  const char *OpenSSL_version(int t);
]]

local version_func
local types_table

-- >= 1.1
local ok, version_num = pcall(function()
  local num = C.OpenSSL_version_num()
  version_func = C.OpenSSL_version
  types_table = {
    VERSION = 0,
    CFLAGS = 1,
    BUILT_ON = 2,
    PLATFORM = 3,
    DIR = 4,
    ENGINES_DIR = 5,
    VERSION_STRING = 6,
    FULL_VERSION_STRING = 7,
    MODULES_DIR = 8,
    CPU_INFO = 9,
  }
  return num
end)


if not ok then
  -- 1.0.x
  local _
  _, version_num = pcall(function()
    local num = C.SSLeay()
    version_func = C.SSLeay_version
    types_table = {
      VERSION = 0,
      CFLAGS = 2,
      BUILT_ON = 3,
      PLATFORM = 4,
      DIR = 5,
    }
    return num
  end)
end

return setmetatable({
    version_num = tonumber(version_num),
    version_text = ffi_str(version_func(0)),
    version = function(t)
      return ffi_str(version_func(t))
    end,
    OPENSSL_11 = version_num >= 0x10100000 and version_num < 0x10200000,
    OPENSSL_10 = version_num < 0x10100000 and version_num > 0x10000000,
  }, {
    __index = types_table,
})