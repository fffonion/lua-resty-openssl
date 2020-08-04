local ffi = require "ffi"
local ctypes = require "resty.openssl.aux.ctypes"
local C = ffi.C
local ffi_str = ffi.string
local ffi_sizeof = ffi.sizeof
local push, join = table.insert, table.concat

ffi.cdef [[
  unsigned long ERR_peek_error(void);
  unsigned long ERR_peek_last_error_line(const char **file, int *line);
  void ERR_clear_error(void);
  void ERR_error_string_n(unsigned long e, char *buf, size_t len);
]]

local constchar_ptrptr = ffi.typeof("const char*[1]")

local buf = ffi.new('char[256]')

local function format_error(ctx, code)
    local errors = {}
    if code then
        push(errors, ("code: %d"):format(code or 0))
    end
    -- get the OpenSSL errors
    if C.ERR_peek_error() ~= 0 then
        local line = ctypes.ptr_of_int()
        local path = constchar_ptrptr()
        local code = C.ERR_peek_last_error_line(path, line)

        local abs_path = ffi_str(path[0])
        -- ../crypto/asn1/a_d2i_fp.c => crypto/asn1/a_d2i_fp.c
        local start = abs_path:find("/")
        if start then
            abs_path = abs_path:sub(start + 1)
        end

        C.ERR_clear_error()
        C.ERR_error_string_n(code, buf, ffi_sizeof(buf))
        push(errors, ("%s:%d:%s"):format(abs_path, line[0], ffi_str(buf)))
    end

    if #errors > 0 then
        return ("%s%s%s"):format(ctx or "", (ctx and ": " or ""), join(errors, " "))
    else
        return ("%s failed"):format(ctx)
    end
end

return {
    format_error = format_error,
}