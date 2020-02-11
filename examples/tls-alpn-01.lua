local pkey = require("resty.openssl.pkey")
local digest = require("resty.openssl.digest")
local x509 = require("resty.openssl.x509")
local altname = require("resty.openssl.x509.altname")
local extension = require("resty.openssl.x509.extension")
local objects = require("resty.openssl.objects")

-- creates the ACME Identifier NID into openssl's internal lookup table
-- if it doesn't exist
local id_pe_acmeIdentifier = "1.3.6.1.5.5.7.1.31"
local nid = objects.txt2nid(id_pe_acmeIdentifier)
if not nid or nid == 0 then
  nid = objects.create(
    id_pe_acmeIdentifier, -- nid
    "pe-acmeIdentifier",  -- sn
    "ACME Identifier"     -- ln
  )
end

-- generate the tls-alpn-01 challenge certificate/key per
-- https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-07
-- with given domain name and challenge token
function serve_challenge_cert(domain, challenge)
  local dgst = assert(digest.new("sha256"):final(challenge))
  -- 0x04: OCTET STRING
  -- 0x20: length
  dgst = "DER:0420" .. dgst:gsub("(.)", function(s) return string.format("%02x", string.byte(s)) end)

  local key = pkey.new()
  local cert = x509.new()
  cert:set_pubkey(key)
  local ext, err = extension.new(nid, dgst)
  if err then
    return nil, nil, err
  end
  ext:set_critical(true)
  cert:add_extension(ext)

  local alt = assert(altname.new():add(
    "DNS", domain
  ))
  local _, err = cert:set_subject_alt_name(alt)
  if err then
    return nil, nil, err
  end
  cert:sign(key)

  return key, cert
end