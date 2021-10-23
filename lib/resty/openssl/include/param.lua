local ffi = require "ffi"
local C = ffi.C
local ffi_new = ffi.new
local ffi_str = ffi.string

require "resty.openssl.include.ossl_typ"

ffi.cdef [[
  typedef struct ossl_param_st {
    const char *key;             /* the name of the parameter */
    unsigned int data_type;      /* declare what kind of content is in buffer */
    void *data;                  /* value being passed in or out */
    size_t data_size;            /* data size */
    size_t return_size;          /* returned content size */
  } OSSL_PARAM;

  OSSL_PARAM OSSL_PARAM_construct_int(const char *key, int *buf);
  OSSL_PARAM OSSL_PARAM_construct_BN(const char *key, unsigned char *buf,
                                    size_t bsize);
  OSSL_PARAM OSSL_PARAM_construct_utf8_string(const char *key, char *buf,
                                              size_t bsize);
  OSSL_PARAM OSSL_PARAM_construct_octet_string(const char *key, void *buf,
                                                size_t bsize);
  OSSL_PARAM OSSL_PARAM_construct_utf8_ptr(const char *key, char **buf,
                                            size_t bsize);
  OSSL_PARAM OSSL_PARAM_construct_octet_ptr(const char *key, void **buf,
                                            size_t bsize);
  OSSL_PARAM OSSL_PARAM_construct_end(void);
]]

local _M = {
  OSSL_PARAM_INTEGER = 1,
  OSSL_PARAM_UNSIGNED_INTEGER = 2,
  OSSL_PARAM_REAL = 3,
  OSSL_PARAM_UTF8_STRING = 4,
  OSSL_PARAM_OCTET_STRING = 5,
  OSSL_PARAM_UTF8_PTR = 6,
  OSSL_PARAM_OCTET_PTR = 7,
}

function _M.construct(buf_t, length, types_map)
  local params = ffi_new("OSSL_PARAM[?]", length + 1)

  local i = 0
  for key, value in pairs(buf_t) do
    local typ = types_map[key]
    if not typ then
      return nil, "param:construct: unknown key type \"" .. key .. "\""
    end
    local param
    if typ == _M.OSSL_PARAM_UTF8_PTR then -- out
      local buf = ffi_new("char*[1]")
      buf_t[key] = buf
      param = C.OSSL_PARAM_construct_utf8_ptr(key, buf, 0)
    elseif typ == _M.OSSL_PARAM_INTEGER then -- out (and in?)
      local buf = ffi_new("int[1]")
      buf_t[key] = buf
      param = C.OSSL_PARAM_construct_int(key, buf)
    elseif typ == _M.OSSL_PARAM_UTF8_STRING then -- in
      local buf = ffi.cast("char *", buf_t[key])
      param = C.OSSL_PARAM_construct_utf8_string(key, buf, #buf_t[key])
    else
      error("type " .. typ .. " is not yet implemented")
    end
    params[i] = param
    i = i + 1
  end

  params[length] = C.OSSL_PARAM_construct_end()

  return params
end

function _M.parse(buf_t, length, types_map)
  for key, buf in pairs(buf_t) do
    local typ = types_map[key]
    if not typ then
      return nil, "param:parse: unknown key type \"" .. key .. "\""
    end
    if typ == _M.OSSL_PARAM_UTF8_PTR then
      buf_t[key] = ffi_str(buf[0])
    elseif typ == _M.OSSL_PARAM_INTEGER then
      buf_t[key] = tonumber(buf[0])
    else
      error("type " .. typ .. " is not yet implemented")
    end
    -- crypto_macro.OPENSSL_free(req[i-1].data)
  end

  return buf_t
end

return _M