local openssl = require('resty.openssl')
local l_csr = openssl.csr.new(csr_str)
if not