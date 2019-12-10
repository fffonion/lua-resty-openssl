local ffi = require "ffi"
local ffi_str = ffi.string
local floor = math.floor

local asn1_macro = require("resty.openssl.include.asn1")

-- https://github.com/wahern/luaossl/blob/master/src/openssl.c
local function isleap(year)
	return (year % 4) == 0 and ((year % 100) > 0 or (year % 400) == 0)
end

local past = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 }
local function yday(year, mon, mday)
	local d = past[mon] + mday - 1
  if mon > 2 and isleap(year) then
    d = d + 1
  end
	return d
end

local function leaps(year)
  return floor(year / 400) + floor(year / 4) - floor(year / 100)
end

-- make sure this code works after 100 years
local yyyy = tonumber(ngx.today():sub(1, 4))
local yy00 = yyyy - yyyy % 100

local function asn1_to_unix(asn1)
  local s = asn1_macro.ASN1_STRING_get0_data(asn1)
  s = ffi_str(s)
  -- 190303223958Z
  local year = yy00 + tonumber(s:sub(1, 2))
  local month = tonumber(s:sub(3, 4))
  local day = tonumber(s:sub(5, 6))
  local hour = tonumber(s:sub(7, 8))
  local minute = tonumber(s:sub(9, 10))
  local second = tonumber(s:sub(11, 12))

  local tm
  tm = (year - 1970) * 365
  tm = tm + leaps(year - 1) - leaps(1969)
  tm = (tm + yday(year, month, day)) * 24
  tm = (tm + hour) * 60
  tm = (tm + minute) * 60
  tm = tm + second
  return tm
end

return {
  asn1_to_unix = asn1_to_unix,
}
