local ffi = require "ffi"

require "resty.openssl.include.ossl_typ"
require "resty.openssl.include.stack"
require "resty.openssl.include.asn1"

ffi.cdef [[
  typedef struct EDIPartyName_st EDIPARTYNAME;

  typedef struct otherName_st OTHERNAME;

  typedef struct GENERAL_NAME_st {
      int type;
      union {
        char *ptr;
        OTHERNAME *otherName;   /* otherName */
        ASN1_IA5STRING *rfc822Name;
        ASN1_IA5STRING *dNSName;
        ASN1_TYPE *x400Address;
        X509_NAME *directoryName;
        EDIPARTYNAME *ediPartyName;
        ASN1_IA5STRING *uniformResourceIdentifier;
        ASN1_OCTET_STRING *iPAddress;
        ASN1_OBJECT *registeredID;
        /* Old names */
        ASN1_OCTET_STRING *ip;  /* iPAddress */
        X509_NAME *dirn;        /* dirn */
        ASN1_IA5STRING *ia5;    /* rfc822Name, dNSName,
                                    * uniformResourceIdentifier */
        ASN1_OBJECT *rid;       /* registeredID */
        ASN1_TYPE *other;       /* x400Address */
      } d;
    } GENERAL_NAME;

  // STACK_OF(GENERAL_NAME)
  typedef struct stack_st GENERAL_NAMES;

  GENERAL_NAME *GENERAL_NAME_new(void);
  void GENERAL_NAME_free(GENERAL_NAME *a);

  // STACK_OF(X509_EXTENSION)
  int X509V3_add1_i2d(OPENSSL_STACK **x, int nid, void *value,
                    int crit, unsigned long flags);

  int X509_add1_ext_i2d(X509 *x, int nid, void *value, int crit,
                    unsigned long flags);
  // although the struct has plural form, it's not a stack
  typedef struct BASIC_CONSTRAINTS_st {
    int ca;
    ASN1_INTEGER *pathlen;
  } BASIC_CONSTRAINTS;
  // DECLARE_ASN1_FUNCTIONS(BASIC_CONSTRAINTS), NYI
  BASIC_CONSTRAINTS *BASIC_CONSTRAINTS_new(void);
  void BASIC_CONSTRAINTS_free(BASIC_CONSTRAINTS *a);

  void X509V3_set_ctx(X509V3_CTX *ctx, X509 *issuer, X509 *subject,
    X509_REQ *req, X509_CRL *crl, int flags);

  X509_EXTENSION *X509V3_EXT_nconf_nid(CONF *conf, X509V3_CTX *ctx, int ext_nid,
                                     const char *value);
  X509_EXTENSION *X509V3_EXT_nconf(CONF *conf, X509V3_CTX *ctx, const char *name,
                                 const char *value);
  int X509V3_EXT_print(BIO *out, X509_EXTENSION *ext, unsigned long flag,
    int indent);
]]
