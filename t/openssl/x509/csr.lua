
local function create_csr(domain_pkey, ...)
  local domains = {...}

  local subject = require("resty.openssl.x509.name").new()
  local _, err = subject:add("CN", domains[1])
  if err then
    return nil, err
  end

  local alt, err
  if #{...} > 1 then
    alt, err = require("resty.openssl.x509.altname").new()
    if err then
      return nil, err
    end

    for _, domain in pairs(domains) do
      _, err = alt:add("DNS", domain)
      if err then
        return nil, err
      end
    end
  end

  local csr = require("resty.openssl.x509.csr").new()
  local ok
  ok, err = csr:set_subject_name(subject)
  if err then
    return nil, err
  end

  if alt then
    ok, err = csr:set_subject_alt_name(alt)
    if err then
      return nil, err
    end
  end

  ok, err = csr:set_pubkey(domain_pkey)
  if err then
    return nil, err
  end

  ok, err = csr:sign(domain_pkey)
  if err then
    return nil, err
  end

  return csr:tostring("DER"), nil
end

return {
    create_csr = create_csr,
}