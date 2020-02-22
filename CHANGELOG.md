<a name="unreleased"></a>
## [Unreleased]


<a name="0.5.3"></a>
## [0.5.3] - 2020-02-22
### feat
- **openssl:** lua-resty-hmac compat [fad844f](https://github.com/fffonion/lua-resty-openssl/commit/fad844f804abe8d73b7d4b7655d562fdb3d84ebf)


<a name="0.5.2"></a>
## [0.5.2] - 2020-02-09
### feat
- **x509.extension:** allow to create an extension by NID [6d66a2d](https://github.com/fffonion/lua-resty-openssl/commit/6d66a2d9fa7cc36cc2e6c85a78ad2236e525f3b0)

### fix
- **pkey:** decrease copy by 1 when generating key [bcc38e9](https://github.com/fffonion/lua-resty-openssl/commit/bcc38e9fc5e733a8f3f9d09e5eef1e2eb3c15d4d)


<a name="0.5.1"></a>
## [0.5.1] - 2020-02-04
### feat
- **pkey:** load encrypted PEM key [7fa7a29](https://github.com/fffonion/lua-resty-openssl/commit/7fa7a29882bbcef294f83cd1f66b9960344a0e07)
- **x509.extension:** add tostring() as synonym to text() [87c162d](https://github.com/fffonion/lua-resty-openssl/commit/87c162de9fa7bb3e3930bd760ff7dfece30f1b49)

### fix
- **x509.crl:** fix creating empty crl instance [046ca36](https://github.com/fffonion/lua-resty-openssl/commit/046ca36228f639c191c81a7b84dfedfc523d0340)


<a name="0.5.0"></a>
## [0.5.0] - 2020-02-03
### feat
- ***:** add iterater and helpers for stack-like objects [46bb723](https://github.com/fffonion/lua-resty-openssl/commit/46bb7237028a16e67878d8310c25e908ceece009)
- **autogen:** generate tests for x509, csr and crl [1392428](https://github.com/fffonion/lua-resty-openssl/commit/1392428352164d2a1a6e0c03075ff65b55aecdee)
- **objects:** add helper function for ASN1_OBJECT [d037706](https://github.com/fffonion/lua-resty-openssl/commit/d037706c11d716afe3616bdaf4658afc1763081d)
- **pkey:** asymmetric encryption and decryption [6d60451](https://github.com/fffonion/lua-resty-openssl/commit/6d60451157edbf9cefb634f888dfa3e6d9be302f)
- **x509:** getter/setters for extensions [243f40d](https://github.com/fffonion/lua-resty-openssl/commit/243f40d35562a516f404188a5c7eb8f5134d9b30)
- **x509:** add get_ocsp_url and get_crl_url [6141b6f](https://github.com/fffonion/lua-resty-openssl/commit/6141b6f5aed38706b477a71d8c4383bf55da7eee)
- **x509.altname:** support iterate and decode over the stack [083a201](https://github.com/fffonion/lua-resty-openssl/commit/083a201746e02d51f6c5c640ad9bf8c6730ebe0b)
- **x509.crl:** add crl module [242f8cb](https://github.com/fffonion/lua-resty-openssl/commit/242f8cb45d6c2df5918f26540c92a430d42feb5d)
- **x509.csr:** autogen some csr functions as well [9800e36](https://github.com/fffonion/lua-resty-openssl/commit/9800e36c2ff8a299b88f24091cc722940a8652bb)
- **x509.extension:** decode object, set/get critical flag and get text representation [8cb585f](https://github.com/fffonion/lua-resty-openssl/commit/8cb585fc51de04065cd7eeeea06e6240e7251614)
- **x509.extension:** add x509.extension.dist_points and x509.extension.info_access [63d3992](https://github.com/fffonion/lua-resty-openssl/commit/63d3992163144ed75474a8046398d605570c30b7)

### fix
- ***:** add missing crl.dup function, organize store:add gc handler [6815e5d](https://github.com/fffonion/lua-resty-openssl/commit/6815e5df04fdb77c83b0345f166664759a573962)
- **asn1:** support GENERALIZEDTIME string format [8c7e2d6](https://github.com/fffonion/lua-resty-openssl/commit/8c7e2d67857cb6875cf52fadf43cadf05d8c5c40)
- **error:** return latest error string not earliest in some cases [0b5955d](https://github.com/fffonion/lua-resty-openssl/commit/0b5955d4cb73f3c7d3321ed7384ae862640a6a7f)
- **stack:** protective over first argument [bf455ff](https://github.com/fffonion/lua-resty-openssl/commit/bf455ff310b94b26a3bed513ffc9f308f65691ed)
- **x509:** guard around oscp stack index [1b59b85](https://github.com/fffonion/lua-resty-openssl/commit/1b59b8565b5dee4cb1dd14d22bc24ec04dfbf3d6)
- **x509.store:** correctly save x509 instance references [d8d755f](https://github.com/fffonion/lua-resty-openssl/commit/d8d755f7a281ad09d896a1d78ad9e53f6c028bdc)


<a name="0.4.3"></a>
## [0.4.3] - 2020-01-15
### fix
- **asn1:** support GENERALIZEDTIME string format [cc6326f](https://github.com/fffonion/lua-resty-openssl/commit/cc6326fed1bc53e64042d4742208ed68d7bb42ac)


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

[Unreleased]: https://github.com/fffonion/lua-resty-openssl/compare/0.5.3...HEAD
[0.5.3]: https://github.com/fffonion/lua-resty-openssl/compare/0.5.2...0.5.3
[0.5.2]: https://github.com/fffonion/lua-resty-openssl/compare/0.5.1...0.5.2
[0.5.1]: https://github.com/fffonion/lua-resty-openssl/compare/0.5.0...0.5.1
[0.5.0]: https://github.com/fffonion/lua-resty-openssl/compare/0.4.3...0.5.0
[0.4.3]: https://github.com/fffonion/lua-resty-openssl/compare/0.4.2...0.4.3
[0.4.2]: https://github.com/fffonion/lua-resty-openssl/compare/0.4.1...0.4.2
[0.4.1]: https://github.com/fffonion/lua-resty-openssl/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/fffonion/lua-resty-openssl/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/fffonion/lua-resty-openssl/compare/0.2.1...0.3.0
[0.2.1]: https://github.com/fffonion/lua-resty-openssl/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/fffonion/lua-resty-openssl/compare/init...0.2.0
