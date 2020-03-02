-- local GEN_OTHERNAME = 0
local GEN_EMAIL = 1
local GEN_DNS = 2
-- local GEN_X400 = 3
local GEN_DIRNAME = 4
-- local GEN_EDIPARTY = 5
local GEN_URI = 6
local GEN_IPADD = 7
-- local GEN_RID = 8

local types = {
  RFC822Name = GEN_EMAIL,
  RFC822 = GEN_EMAIL,
  Email = GEN_EMAIL,
  UniformResourceIdentifier = GEN_URI,
  URI = GEN_URI,
  DNSName = GEN_DNS,
  DNS = GEN_DNS,
  IPAddress = GEN_IPADD,
  IP = GEN_IPADD,
  DirName = GEN_DIRNAME,
}

local literals = {
  [GEN_EMAIL] = "email",
  [GEN_DNS] = "DNS",
  [GEN_DIRNAME] = "DirName",
  [GEN_URI] = "URI",
  [GEN_IPADD] = "IP",
}

for t, gid in pairs(types) do
  types[t:lower()] = gid
end

return {
  types = types,
  literals = literals,
}