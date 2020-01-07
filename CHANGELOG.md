<a name="unreleased"></a>
## [Unreleased]


<a name="0.4.2"></a>
## [0.4.2] - 2020-01-06
### fix
- **bn:** memory leak in bn:to_hex [6718e9e](https://github.com/fffonion/lua-resty-openssl/commit/6718e9e76a8410c78b32e5abf6d06a628fe8dc8b)
- **compat:** refine luaossl compat mode [0d86eb5](https://github.com/fffonion/lua-resty-openssl/commit/0d86eb58848e970408bec7ee9d77102c241c3a5c)
- **openssl:** typo in luaossl_compat [#1](https://github.com/fffonion/lua-resty-openssl/issues/1) [1c3ea60](https://github.com/fffonion/lua-resty-openssl/commit/1c3ea60877d1532eaaddc13ab3be1550c4c5a7f1)
- **x509:** memory leak in x509:set_not_(before|after) [b4a32f8](https://github.com/fffonion/lua-resty-openssl/commit/b4a32f82c33107d2db729caa06aee141b7f9a016)
- **x509:** and missing x509.get_serial_number code [e7d0fb6](https://github.com/fffonion/lua-resty-openssl/commit/e7d0fb6eace77d357d19043b88bb765ec29a5193)
- **x509.csr:** correctly gc extension [ece5be3](https://github.com/fffonion/lua-resty-openssl/commit/ece5be3f517b69563150973e7da6063d5826a9ad)
- **x509.store:** memory leak in store:add [57815dd](https://github.com/fffonion/lua-resty-openssl/commit/57815dd38bbb2e260e8cdf3e8ddac48d6254b8fc)


<a name="0.4.1"></a>
## [0.4.1] - 2019-12-24
### feat
- **x509:** getters for basic constraints and basic constraints critical [82f5725](https://github.com/fffonion/lua-resty-openssl/commit/82f5725d4738b3bf83fcbf3154fe5979fe8d1af4)

### fix
- **x509:** correct X509_add1_ext_i2d include path [b08b312](https://github.com/fffonion/lua-resty-openssl/commit/b08b3123a0fb2770296f04c830414bd38588e8eb)


<a name="0.4.0"></a>
## [0.4.0] - 2019-12-20
### feat
- ***:** add x509.digest and bn.to_hex [11ea9ae](https://github.com/fffonion/lua-resty-openssl/commit/11ea9aebca6bb5c354ad94525bd2e264debfebbd)
- **version:** add function to print human readable version [7687573](https://github.com/fffonion/lua-resty-openssl/commit/76875731011e5641eef9881ace2becf1bf057cfd)
- **x509:** add x509 stack (chain) support [72154fc](https://github.com/fffonion/lua-resty-openssl/commit/72154fcb7686ce5a754d4fe4f121f07507a1513e)
- **x509.chain:** allow to duplicate a stack [3fa19b7](https://github.com/fffonion/lua-resty-openssl/commit/3fa19b79509c73cf5dce6e3445cbf90a9466d656)
- **x509.name:** allow to iterate over objects and find objects [714a1e5](https://github.com/fffonion/lua-resty-openssl/commit/714a1e541e0ce3ffb33d257d9af50ae628094fb2)
- **x509.store:** support certificate verification [c9dd4bf](https://github.com/fffonion/lua-resty-openssl/commit/c9dd4bf8065a51a97fcf940c33ba046b73ac2049)

### fix
- ***:** always return ok, err if there's no explict return value [3e68167](https://github.com/fffonion/lua-resty-openssl/commit/3e681676f85e26c8c7af6f72a2c4afcb98952cd6)
- **evp:** correct ptr naming [72f8765](https://github.com/fffonion/lua-resty-openssl/commit/72f8765250861d6504a767da81afe19c2d2896a4)


<a name="0.3.0"></a>
## [0.3.0] - 2019-12-12
### feat
- **cipher:** add symmetric cryptography support [9b89e8d](https://github.com/fffonion/lua-resty-openssl/commit/9b89e8dcc1489832c893373150bfeef6a838da34)
- **hmac:** add hmac support [5cc2a15](https://github.com/fffonion/lua-resty-openssl/commit/5cc2a15ce43a9c1c73dccf1a15232ee2a9108460)

### fix
- ***:** move cdef and macros to seperate file [28c3390](https://github.com/fffonion/lua-resty-openssl/commit/28c339085383bfbcb72e192701b96e08fb4344f0)
- ***:** normalize error handling [ff18d54](https://github.com/fffonion/lua-resty-openssl/commit/ff18d54d2b4402de3bc02731f99c32a9953f8784)


<a name="0.2.1"></a>
## [0.2.1] - 2019-10-22
### fix
- **x509:** decrease by set_version by 1 per standard [b6ea5b9](https://github.com/fffonion/lua-resty-openssl/commit/b6ea5b933aadfb8284f7486eb33d8a4c21b7a6de)


<a name="0.2.0"></a>
## [0.2.0] - 2019-10-18
### feat
- ***:** add more x509 API, and rand bytes generator [6630fde](https://github.com/fffonion/lua-resty-openssl/commit/6630fde2e5e9f367e4652dc390678d4eeb57ad5d)
- **error:** add ability to pull error description [d19ece9](https://github.com/fffonion/lua-resty-openssl/commit/d19ece993ac797fdf6708400cf83e3f4ed0bb9f4)
- **x509:** generate certificate [9b4f59b](https://github.com/fffonion/lua-resty-openssl/commit/9b4f59bf94647aab37da6b8076ee99e155ba8023)
- **x509:** export pubkey [ede4f81](https://github.com/fffonion/lua-resty-openssl/commit/ede4f817cb0fe092ad6f9ab5d6ecdcde864a9fd8)

### fix
- ***:** fix working and name test [f6db7ef](https://github.com/fffonion/lua-resty-openssl/commit/f6db7ef3c1ce5f9a75f01dc24f904fd8942c7897)
- ***:** normalize naming, explictly control cdef for different openssl versions [c626b53](https://github.com/fffonion/lua-resty-openssl/commit/c626b538c2dc33272b130503ddd21f21bd9d995f)
- ***:** cleanup cdef [3c02d02](https://github.com/fffonion/lua-resty-openssl/commit/3c02d020822a30fdf7dae0aa7c6aa47c4660aea8)
- ***:** test cdata type before passing in ffi [de99069](https://github.com/fffonion/lua-resty-openssl/commit/de99069e40c075844a15b91720e2d5c9c9a68dd7)


<a name="init"></a>
## init - 2019-09-25

[Unreleased]: https://github.com/fffonion/lua-resty-openssl/compare/0.4.2...HEAD
[0.4.2]: https://github.com/fffonion/lua-resty-openssl/compare/0.4.1...0.4.2
[0.4.1]: https://github.com/fffonion/lua-resty-openssl/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/fffonion/lua-resty-openssl/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/fffonion/lua-resty-openssl/compare/0.2.1...0.3.0
[0.2.1]: https://github.com/fffonion/lua-resty-openssl/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/fffonion/lua-resty-openssl/compare/init...0.2.0
