local ffi = require "ffi"
local bit = require("bit")

require "resty.openssl.include.ossl_typ"
local OPENSSL_10 = require("resty.openssl.version").OPENSSL_10
local OPENSSL_11 = require("resty.openssl.version").OPENSSL_11

ffi.cdef [[
  EVP_PKEY *EVP_PKEY_new(void);
  void EVP_PKEY_free(EVP_PKEY *pkey);

  struct rsa_st *EVP_PKEY_get0_RSA(EVP_PKEY *pkey);
  struct ec_key_st *EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey);
  int EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key);
  int EVP_PKEY_base_id(const EVP_PKEY *pkey);
  int EVP_PKEY_size(const EVP_PKEY *pkey);

  EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
  EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e);
  void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
  int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
                      int cmd, int p1, void *p2);
  int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);
  int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
                        unsigned char *out, size_t *outlen,
                        const unsigned char *in, size_t inlen);
  int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);
  int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,
                        unsigned char *out, size_t *outlen,
                        const unsigned char *in, size_t inlen);

  /*__owur*/ int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type,
                                 ENGINE *impl);
  /*__owur*/ int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d,
                                  size_t cnt);
  /*__owur*/ int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md,
                                  unsigned int *s);
  const EVP_MD *EVP_get_digestbyname(const char *name);
  /*__owur*/ int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d,
                                size_t cnt);
  /*__owur*/ int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md,
                                unsigned int *s);
  /*__owur*/ int EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s,
                         EVP_PKEY *pkey);
  /*__owur*/ int EVP_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf,
                           unsigned int siglen, EVP_PKEY *pkey);
  int EVP_MD_size(const EVP_MD *md);

  int EVP_PKEY_get_default_digest_nid(EVP_PKEY *pkey, int *pnid);
  const EVP_MD *EVP_get_digestbyname(const char *name);


  /*__owur*/ int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,
                           const EVP_CIPHER *cipher, ENGINE *impl,
                           const unsigned char *key,
                           const unsigned char *iv, int enc);
  /*__owur*/ int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           int *outl, const unsigned char *in, int inl);
  /*__owur*/ int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                           int *outl);

  int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx);
  int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx);
  int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx);
  int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);

  const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx);
  const EVP_CIPHER *EVP_get_cipherbyname(const char *name);

  int EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md,
    const unsigned char *salt,
    const unsigned char *data, int datal, int count,
    unsigned char *key, unsigned char *iv);

  /* KDF */
  int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
    const unsigned char *salt, int saltlen, int iter,
    const EVP_MD *digest, int keylen, unsigned char *out);

  int EVP_PBE_scrypt(const char *pass, size_t passlen,
    const unsigned char *salt, size_t saltlen,
    uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem,
    unsigned char *key, size_t keylen);

  int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
  int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
]]

if OPENSSL_11 then
  ffi.cdef [[
    EVP_MD_CTX *EVP_MD_CTX_new(void);
    void EVP_MD_CTX_free(EVP_MD_CTX *ctx);

    EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
    int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *c);
    void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c);
  ]]
elseif OPENSSL_10 then
  ffi.cdef [[
    EVP_MD_CTX *EVP_MD_CTX_create(void);
    void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx);
    // crypto/evp/evp.h
    // only needed for openssl 1.0.x where getters are not available
    // needed to get key to extract parameters
    // Note: this struct is trimmed
    struct evp_pkey_st {
      int type;
      int save_type;
      const EVP_PKEY_ASN1_METHOD *ameth;
      ENGINE *engine;
      ENGINE *pmeth_engine;
      union {
          void *ptr;
          struct rsa_st *rsa;
          struct dsa_st *dsa;
          struct dh_st *dh;
          struct ec_key_st *ec;
      } pkey;
      // trimmed

      // CRYPTO_REF_COUNT references;
      // CRYPTO_RWLOCK *lock;
      // STACK_OF(X509_ATTRIBUTE) *attributes;
      // int save_parameters;

      // struct {
      //     EVP_KEYMGMT *keymgmt;
      //     void *provkey;
      // } pkeys[10];
      // size_t dirty_cnt_copy;
    };

    // crypto/evp/evp.h
    // only needed for openssl 1.0.x where initializer for HMAC_CTX is not avaiable
    // HACK: renamed from env_md_ctx_st to evp_md_ctx_st to match typedef (lazily)
    // it's an internal struct thus name is not exported so we will be fine
    struct evp_md_ctx_st {
      const EVP_MD *digest;
      ENGINE *engine;             /* functional reference if 'digest' is
                                   * ENGINE-provided */
      unsigned long flags;
      void *md_data;
      /* Public key context for sign/verify */
      EVP_PKEY_CTX *pctx;
      /* Update function: usually copied from EVP_MD */
      int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
    } /* EVP_MD_CTX */ ;

    void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);
    int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a);

    // # define EVP_MAX_IV_LENGTH               16
    // # define EVP_MAX_BLOCK_LENGTH            32

    struct evp_cipher_ctx_st {
      const EVP_CIPHER *cipher;
      ENGINE *engine;             /* functional reference if 'cipher' is
                                   * ENGINE-provided */
      int encrypt;                /* encrypt or decrypt */
      int buf_len;                /* number we have left */
      unsigned char oiv[16]; /* original iv EVP_MAX_IV_LENGTH */
      unsigned char iv[16]; /* working iv EVP_MAX_IV_LENGTH */
      unsigned char buf[32]; /* saved partial block EVP_MAX_BLOCK_LENGTH */
      int num;                    /* used by cfb/ofb/ctr mode */
      void *app_data;             /* application stuff */
      int key_len;                /* May change for variable length cipher */
      unsigned long flags;        /* Various flags */
      void *cipher_data;          /* per EVP data */
      int final_used;
      int block_mask;
      unsigned char final[32]; /* possible final block EVP_MAX_BLOCK_LENGTH */
    } /* EVP_CIPHER_CTX */ ;
  ]]
end

return {
  EVP_PKEY_RSA = 6,
  EVP_PKEY_DH = 28,
  EVP_PKEY_EC = 408,

  EVP_PKEY_OP_DERIVE = bit.lshift(1, 10),

  EVP_PKEY_ALG_CTRL = 0x1000,
  EVP_PKEY_CTRL_RSA_PADDING = 0x1000 + 1,
}
