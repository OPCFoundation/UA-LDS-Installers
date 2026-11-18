/* ========================================================================
 * Copyright (c) 2005-2026, OPC Federation AISBL, All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

#include "certops.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif

/* ---------------------------------------------------------------------------
 * Startup
 * ------------------------------------------------------------------------ */
void cg_certops_startup(void)
{
    /* OpenSSL 3.x initialises itself on first use; all that is needed is the
     * error strings for cg_fail_openssl, and the legacy algorithms are not
     * used here at all. */
    ERR_load_crypto_strings();
}

void cg_certops_shutdown(void)
{
    ERR_clear_error();
}

/* ---------------------------------------------------------------------------
 * Subject name
 * ------------------------------------------------------------------------ */
typedef struct {
    cg_list names;
    cg_list values;
} cg_name_fields;

static void cg_name_fields_init(cg_name_fields *fields)
{
    cg_list_init(&fields->names);
    cg_list_init(&fields->values);
}

static void cg_name_fields_free(cg_name_fields *fields)
{
    cg_list_free(&fields->names);
    cg_list_free(&fields->values);
}

static int cg_name_fields_add(cg_name_fields *fields, const char *name, const char *value)
{
    if (cg_list_add(&fields->names, name) != 0) return -1;
    if (cg_list_add(&fields->values, value) != 0) return -1;
    return 0;
}

/* Parses "CN=Hello/O=World" into parallel name/value lists.
 *
 * Field names are [alnum or '.']+, then optional whitespace, then '=', then the
 * value up to the next '/' or end of string.  A double-quoted value may contain
 * '/'.  Matches OpcUa_Certificate_ParseSubjectName. */
static unsigned int cg_parse_subject_name(const char *text, cg_name_fields *fields)
{
    size_t length = strlen(text);
    size_t ii = 0;

    while (ii < length)
    {
        size_t start;
        cg_str name;
        cg_str value;

        while (ii < length && isspace((unsigned char)text[ii])) ii++;

        if (ii >= length)
        {
            break;
        }

        start = ii;
        while (ii < length && (isalnum((unsigned char)text[ii]) || text[ii] == '.')) ii++;

        if (start == ii)
        {
            return cg_fail(CG_BAD_SYNTAX_ERROR,
                           "Could not parse the subject name: %s", text);
        }

        cg_str_init(&name);
        {
            size_t jj;
            for (jj = start; jj < ii; jj++)
            {
                cg_str_append_char(&name, text[jj]);
            }
        }

        while (ii < length && isspace((unsigned char)text[ii])) ii++;

        if (ii >= length || text[ii] != '=')
        {
            cg_str_free(&name);
            return cg_fail(CG_BAD_SYNTAX_ERROR,
                           "Could not parse the subject name: %s", text);
        }

        ii++;   /* past '=' */

        while (ii < length && isspace((unsigned char)text[ii])) ii++;

        cg_str_init(&value);

        if (ii < length && text[ii] == '"')
        {
            ii++;
            while (ii < length && text[ii] != '"')
            {
                cg_str_append_char(&value, text[ii++]);
            }

            if (ii < length) ii++;              /* past closing quote */
            while (ii < length && text[ii] != '/') ii++;
            if (ii < length) ii++;              /* past separator */
        }
        else
        {
            while (ii < length && text[ii] != '/')
            {
                cg_str_append_char(&value, text[ii++]);
            }

            if (ii < length) ii++;              /* past separator */
            cg_str_trim(&value);
        }

        if (cg_name_fields_add(fields, name.data, value.data) != 0)
        {
            cg_str_free(&name);
            cg_str_free(&value);
            return cg_fail(CG_BAD_OUT_OF_MEMORY, "Memory allocation failed.");
        }

        cg_str_free(&name);
        cg_str_free(&value);
    }

    return CG_GOOD;
}

/* Builds the X509_NAME.
 *
 * LEGACY: the fields are added in reverse order, as the legacy implementation
 * did, so "CN=A/O=B" yields a DN of O=B, CN=A.  Changing this would change
 * every generated subject name. */
static unsigned int cg_build_x509_name(const cg_name_fields *fields, X509_NAME **result)
{
    X509_NAME *name = X509_NAME_new();
    size_t     count = fields->names.count;
    size_t     ii;

    *result = NULL;

    if (name == NULL)
    {
        return cg_fail(CG_BAD_OUT_OF_MEMORY, "Memory allocation failed.");
    }

    for (ii = 0; ii < count; ii++)
    {
        const char *key = fields->names.items[count - 1 - ii];
        const char *value = fields->values.items[count - 1 - ii];

        if (value == NULL || *value == 0)
        {
            continue;
        }

        if (X509_NAME_add_entry_by_txt(name, key, MBSTRING_UTF8,
                                       (const unsigned char *)value, -1, -1, 0) != 1)
        {
            X509_NAME_free(name);
            return cg_fail(CG_BAD_SYNTAX_ERROR,
                           "Could not add the subject name field '%s' to the certificate.", key);
        }
    }

    *result = name;
    return CG_GOOD;
}

/* ---------------------------------------------------------------------------
 * Keys
 * ------------------------------------------------------------------------ */

/* Maps a -keyType to its OpenSSL curve NID. Returns 0 for RSA. */
static int cg_curve_nid(cg_key_type type)
{
    switch (type)
    {
        case CG_KEY_EC_NIST_P256:        return NID_X9_62_prime256v1;
        case CG_KEY_EC_NIST_P384:        return NID_secp384r1;
        case CG_KEY_EC_BRAINPOOL_P256R1: return NID_brainpoolP256r1;
        case CG_KEY_EC_BRAINPOOL_P384R1: return NID_brainpoolP384r1;
        default:                         return 0;
    }
}

/* True for every -keyType other than rsa. */
static int cg_is_ec_key_type(cg_key_type type)
{
    return (type != CG_KEY_RSA);
}

/* The hash an OPC UA ECC SecurityPolicy pairs with its curve:
 *
 *   ECC_nistP256   / ECC_brainpoolP256r1  ->  ECDSA-SHA2-256
 *   ECC_nistP384   / ECC_brainpoolP384r1  ->  ECDSA-SHA2-384
 *   ECC_curve25519 ->  PureEdDSA-25519  (Ed25519 hashes internally, no EVP_MD)
 *   ECC_curve448   ->  PureEdDSA-448    (Ed448 likewise)
 *
 * Taken from the key rather than from -keyType, because the key that signs a
 * CA-issued certificate is the issuer's, loaded from a file, about which
 * -keyType says nothing.  The EdDSA curves never reach here - they are handled
 * separately with a NULL digest. */
static unsigned short cg_signing_key_hash_size(EVP_PKEY *key)
{
    return (EVP_PKEY_get_bits(key) >= 384) ? 384 : 256;
}

static const char *cg_key_type_name(cg_key_type type)
{
    switch (type)
    {
        case CG_KEY_RSA:                 return "rsa";
        case CG_KEY_EC_NIST_P256:        return "nistP256";
        case CG_KEY_EC_NIST_P384:        return "nistP384";
        case CG_KEY_EC_BRAINPOOL_P256R1: return "brainpoolP256r1";
        case CG_KEY_EC_BRAINPOOL_P384R1: return "brainpoolP384r1";
        case CG_KEY_EC_CURVE25519:       return "curve25519";
        case CG_KEY_EC_CURVE448:         return "curve448";
        default:                         return "unknown";
    }
}

/* Generates a key pair using the OpenSSL 3.x generic keygen interface. */
static unsigned int cg_generate_key(cg_key_type type, unsigned int bits, EVP_PKEY **result)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY     *key = NULL;
    unsigned int  status = CG_GOOD;

    *result = NULL;

    if (type == CG_KEY_RSA)
    {
        if (bits == 0)
        {
            bits = 2048;
        }

        ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

        if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0)
        {
            status = cg_fail_openssl(CG_BAD_UNEXPECTED_ERROR, "RSA key generation setup");
            goto cleanup;
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int)bits) <= 0)
        {
            status = cg_fail_openssl(CG_BAD_INVALID_ARGUMENT, "RSA key size selection");
            goto cleanup;
        }
    }
    else if (type == CG_KEY_EC_CURVE25519 || type == CG_KEY_EC_CURVE448)
    {
#if defined(OPENSSL_NO_ECX)
        status = cg_fail(CG_BAD_NOT_SUPPORTED,
                         "Key type '%s' is not available: this build of OpenSSL was configured "
                         "with no-ec/no-ecx. Rebuild OpenSSL with elliptic curve support, or use "
                         "-keyType rsa.",
                         cg_key_type_name(type));
        goto cleanup;
#else
        const char *name = (type == CG_KEY_EC_CURVE25519) ? "ED25519" : "ED448";

        ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);

        if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0)
        {
            status = cg_fail_openssl(CG_BAD_UNEXPECTED_ERROR, "EdDSA key generation setup");
            goto cleanup;
        }
#endif
    }
    else
    {
#if defined(OPENSSL_NO_EC)
        status = cg_fail(CG_BAD_NOT_SUPPORTED,
                         "Key type '%s' is not available: this build of OpenSSL was configured "
                         "with no-ec. Rebuild OpenSSL with elliptic curve support, or use "
                         "-keyType rsa.",
                         cg_key_type_name(type));
        goto cleanup;
#else
        int nid = cg_curve_nid(type);

        ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

        if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0)
        {
            status = cg_fail_openssl(CG_BAD_UNEXPECTED_ERROR, "EC key generation setup");
            goto cleanup;
        }

        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0)
        {
            status = cg_fail_openssl(CG_BAD_INVALID_ARGUMENT, "EC curve selection");
            goto cleanup;
        }

        /* Named curve, not explicit parameters - required for interoperability. */
        EVP_PKEY_CTX_set_ec_param_enc(ctx, OPENSSL_EC_NAMED_CURVE);
#endif
    }

    if (EVP_PKEY_generate(ctx, &key) <= 0)
    {
        status = cg_fail_openssl(CG_BAD_UNEXPECTED_ERROR, "Key generation");
        goto cleanup;
    }

    *result = key;
    key = NULL;

cleanup:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return status;
}

/* Selects the signature digest.
 *
 * DEVIATION (security fix): the legacy switch accepted only 224, 256 and 384
 * and silently fell back to SHA-1 for everything else - including 512, which
 * its own usage text advertises, and 160.  Here 512 means SHA-512 and 160 means
 * SHA-1 explicitly.  See README.md. */
static const EVP_MD *cg_select_digest(unsigned short hash_size)
{
    switch (hash_size)
    {
        case 160: return EVP_sha1();
        case 224: return EVP_sha224();
        case 256: return EVP_sha256();
        case 384: return EVP_sha384();
        case 512: return EVP_sha512();
        default:  return EVP_sha256();
    }
}

/* ---------------------------------------------------------------------------
 * Certificate identity helpers
 * ------------------------------------------------------------------------ */

/* SHA-1 of the DER encoding, uppercase hex - the OPC UA thumbprint. */
static unsigned int cg_get_thumbprint(X509 *certificate, char **result)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  length = 0;

    *result = NULL;

    if (X509_digest(certificate, EVP_sha1(), digest, &length) != 1)
    {
        return cg_fail_openssl(CG_BAD_CERTIFICATE_INVALID, "Thumbprint computation");
    }

    *result = cg_to_hex(digest, length);

    if (*result == NULL)
    {
        return cg_fail(CG_BAD_OUT_OF_MEMORY, "Memory allocation failed.");
    }

    return CG_GOOD;
}

static unsigned int cg_get_common_name(X509 *certificate, char **result)
{
    X509_NAME *subject = X509_get_subject_name(certificate);
    char       buffer[512];
    int        length;

    *result = NULL;

    length = X509_NAME_get_text_by_NID(subject, NID_commonName, buffer, sizeof(buffer));

    if (length <= 0)
    {
        /* No CN: the legacy tool failed here rather than inventing a name. */
        return cg_fail(CG_BAD_CERTIFICATE_INVALID,
                       "The certificate has no common name.");
    }

    *result = cg_to_hex((const unsigned char *)"", 0);   /* allocate, then fill */
    cg_free(*result);

    *result = (char *)cg_alloc((size_t)length + 1);

    if (*result == NULL)
    {
        return cg_fail(CG_BAD_OUT_OF_MEMORY, "Memory allocation failed.");
    }

    memcpy(*result, buffer, (size_t)length + 1);
    return CG_GOOD;
}

/* Replaces characters Windows forbids in a file name with '+'. */
static void cg_sanitize_file_name(char *text)
{
    static const char forbidden[] = "<>:\"/\\|?*";
    char *pos;

    for (pos = text; *pos != 0; pos++)
    {
        if (strchr(forbidden, *pos) != NULL)
        {
            *pos = '+';
        }
    }
}

/* Creates every directory along a path, skipping drive roots. */
static unsigned int cg_create_directories(const char *path)
{
    size_t length = strlen(path);
    size_t ii;

    for (ii = 0; ii < length; ii++)
    {
        char   ch = path[ii];
        char  *parent;
        unsigned int status;

        if (ch != '/' && ch != '\\')
        {
            continue;
        }

        if (ii == 0 || path[ii - 1] == ':')
        {
            continue;
        }

        parent = (char *)cg_alloc(ii + 1);

        if (parent == NULL)
        {
            return cg_fail(CG_BAD_OUT_OF_MEMORY, "Memory allocation failed.");
        }

        memcpy(parent, path, ii);
        parent[ii] = 0;

        status = cg_make_directory(parent);
        cg_free(parent);

        if (CG_IS_BAD(status))
        {
            return status;
        }
    }

    return CG_GOOD;
}

typedef enum { CG_FORMAT_DER, CG_FORMAT_PEM, CG_FORMAT_PKCS12 } cg_format;

/* Builds "<store>\certs\<CN> [<THUMBPRINT>].der" (or private\....pfx|.pem) and
 * creates the intervening directories.  Caller frees the result. */
static unsigned int cg_get_file_path(const char *store_path, X509 *certificate,
                                     cg_format format, char **result)
{
    char        *common_name = NULL;
    char        *thumbprint = NULL;
    unsigned int status;
    cg_str       path;

    *result = NULL;

    status = cg_get_common_name(certificate, &common_name);
    if (CG_IS_BAD(status)) return status;

    status = cg_get_thumbprint(certificate, &thumbprint);
    if (CG_IS_BAD(status))
    {
        cg_free(common_name);
        return status;
    }

    cg_sanitize_file_name(common_name);

    cg_str_init(&path);
    cg_str_append(&path, store_path);
    cg_str_append(&path, (format == CG_FORMAT_DER) ? "\\certs\\" : "\\private\\");

    status = cg_create_directories(path.data);

    if (CG_IS_BAD(status))
    {
        cg_str_free(&path);
        cg_free(common_name);
        cg_free(thumbprint);
        return status;
    }

    cg_str_append(&path, common_name);
    cg_str_append(&path, " [");
    cg_str_append(&path, thumbprint);
    cg_str_append(&path, "]");

    switch (format)
    {
        case CG_FORMAT_DER:    cg_str_append(&path, ".der"); break;
        case CG_FORMAT_PEM:    cg_str_append(&path, ".pem"); break;
        case CG_FORMAT_PKCS12: cg_str_append(&path, ".pfx"); break;
    }

    cg_free(common_name);
    cg_free(thumbprint);

    *result = path.data;   /* ownership transfers to the caller */
    return CG_GOOD;
}

/* ---------------------------------------------------------------------------
 * Store I/O
 * ------------------------------------------------------------------------ */
static unsigned int cg_save_public_key(const char *store_path, X509 *certificate,
                                       char **file_path)
{
    unsigned char *der = NULL;
    int            length;
    unsigned int   status;

    status = cg_get_file_path(store_path, certificate, CG_FORMAT_DER, file_path);
    if (CG_IS_BAD(status)) return status;

    length = i2d_X509(certificate, &der);

    if (length <= 0)
    {
        cg_free(*file_path);
        *file_path = NULL;
        return cg_fail_openssl(CG_BAD_ENCODING_ERROR, "Certificate encoding");
    }

    status = cg_write_file(*file_path, der, (size_t)length);
    OPENSSL_free(der);

    if (CG_IS_BAD(status))
    {
        cg_free(*file_path);
        *file_path = NULL;
    }

    return status;
}

static unsigned int cg_save_private_key(const char *store_path, X509 *certificate,
                                        EVP_PKEY *key, const char *password,
                                        int output_is_pem, char **file_path)
{
    unsigned int status;
    BIO         *bio = NULL;
    cg_format    format = output_is_pem ? CG_FORMAT_PEM : CG_FORMAT_PKCS12;
    char        *common_name = NULL;
    PKCS12      *p12 = NULL;
    unsigned char *buffer = NULL;
    int          length = 0;

    status = cg_get_file_path(store_path, certificate, format, file_path);
    if (CG_IS_BAD(status)) return status;

    if (output_is_pem)
    {
        /* PEM: private key followed by the certificate, as the legacy tool
         * wrote it.  An empty password means no encryption. */
        bio = BIO_new(BIO_s_mem());

        if (bio == NULL)
        {
            status = cg_fail(CG_BAD_OUT_OF_MEMORY, "Memory allocation failed.");
            goto cleanup;
        }

        if (password != NULL && *password != 0)
        {
            if (PEM_write_bio_PrivateKey(bio, key, EVP_aes_256_cbc(),
                                         (const unsigned char *)password,
                                         (int)strlen(password), NULL, NULL) != 1)
            {
                status = cg_fail_openssl(CG_BAD_ENCODING_ERROR, "PEM private key encoding");
                goto cleanup;
            }
        }
        else
        {
            if (PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL) != 1)
            {
                status = cg_fail_openssl(CG_BAD_ENCODING_ERROR, "PEM private key encoding");
                goto cleanup;
            }
        }

        if (PEM_write_bio_X509(bio, certificate) != 1)
        {
            status = cg_fail_openssl(CG_BAD_ENCODING_ERROR, "PEM certificate encoding");
            goto cleanup;
        }
    }
    else
    {
        status = cg_get_common_name(certificate, &common_name);
        if (CG_IS_BAD(status)) goto cleanup;

        /* NULL password and "" are different things to PKCS12_create; the
         * legacy tool always passed the string, so an empty password produces
         * an unencrypted-but-password-marked PFX. Preserved. */
        p12 = PKCS12_create(password, common_name, key, certificate, NULL, 0, 0, 0, 0, 0);

        if (p12 == NULL)
        {
            status = cg_fail_openssl(CG_BAD_ENCODING_ERROR, "PKCS#12 creation");
            goto cleanup;
        }

        bio = BIO_new(BIO_s_mem());

        if (bio == NULL)
        {
            status = cg_fail(CG_BAD_OUT_OF_MEMORY, "Memory allocation failed.");
            goto cleanup;
        }

        if (i2d_PKCS12_bio(bio, p12) != 1)
        {
            status = cg_fail_openssl(CG_BAD_ENCODING_ERROR, "PKCS#12 encoding");
            goto cleanup;
        }
    }

    length = BIO_get_mem_data(bio, (char **)&buffer);

    if (length <= 0)
    {
        status = cg_fail(CG_BAD_ENCODING_ERROR, "Encoded private key is empty.");
        goto cleanup;
    }

    status = cg_write_file(*file_path, buffer, (size_t)length);

cleanup:
    PKCS12_free(p12);
    BIO_free(bio);
    cg_free(common_name);

    if (CG_IS_BAD(status))
    {
        cg_free(*file_path);
        *file_path = NULL;
    }

    return status;
}

/* Loads a private key (and its certificate, when present) from a PFX or PEM
 * blob.  Accepts either a file path or an inline hex string, as the legacy tool
 * did for every input path argument. */
static unsigned int cg_load_private_key(const char *input, int input_is_pem,
                                        const char *password,
                                        EVP_PKEY **key, X509 **certificate)
{
    unsigned char *data = NULL;
    size_t         size = 0;
    unsigned int   status = CG_GOOD;
    BIO           *bio = NULL;
    PKCS12        *p12 = NULL;

    *key = NULL;
    *certificate = NULL;

    if (cg_is_hex_string(input))
    {
        data = cg_from_hex(input, &size);

        if (data == NULL)
        {
            return cg_fail(CG_BAD_INVALID_ARGUMENT, "Could not decode hexadecimal input.");
        }
    }
    else
    {
        status = cg_read_file(input, &data, &size);
        if (CG_IS_BAD(status)) return status;
    }

    bio = BIO_new_mem_buf(data, (int)size);

    if (bio == NULL)
    {
        status = cg_fail(CG_BAD_OUT_OF_MEMORY, "Memory allocation failed.");
        goto cleanup;
    }

    if (input_is_pem)
    {
        *key = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void *)password);

        if (*key == NULL)
        {
            status = cg_fail_openssl(CG_BAD_DECODING_ERROR, "PEM private key decoding");
            goto cleanup;
        }

        /* A certificate may follow the key in the same file; absence is fine. */
        *certificate = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        ERR_clear_error();
    }
    else
    {
        p12 = d2i_PKCS12_bio(bio, NULL);

        if (p12 == NULL)
        {
            status = cg_fail_openssl(CG_BAD_DECODING_ERROR, "PKCS#12 decoding");
            goto cleanup;
        }

        if (PKCS12_parse(p12, password, key, certificate, NULL) != 1)
        {
            status = cg_fail_openssl(CG_BAD_USER_ACCESS_DENIED, "PKCS#12 parse");
            goto cleanup;
        }
    }

cleanup:
    PKCS12_free(p12);
    BIO_free(bio);
    cg_free(data);

    if (CG_IS_BAD(status))
    {
        EVP_PKEY_free(*key);
        X509_free(*certificate);
        *key = NULL;
        *certificate = NULL;
    }

    return status;
}

/* ---------------------------------------------------------------------------
 * Certificate construction
 * ------------------------------------------------------------------------ */

/* Escapes characters not permitted in an application URI.
 *
 * DEVIATION (bug fix): the legacy format string was "%%%2X", which space-pads
 * instead of zero-padding, so byte 0x0A became "% A" - a malformed escape.
 * This uses %02X. */
static unsigned int cg_sanitize_uri(const char *uri, cg_str *result)
{
    const char *pos;

    cg_str_clear(result);

    for (pos = uri; *pos != 0; pos++)
    {
        unsigned char ch = (unsigned char)*pos;

        if (!isprint(ch) || ch == '%' || ch == ',')
        {
            char buffer[8];
            snprintf(buffer, sizeof(buffer), "%%%02X", ch);
            cg_str_append(result, buffer);
        }
        else if (isspace(ch))
        {
            cg_str_append_char(result, ' ');
        }
        else
        {
            cg_str_append_char(result, (char)ch);
        }
    }

    return CG_GOOD;
}

/* True when text is an IPv4 or IPv6 address literal. */
static int cg_is_address_literal(const char *text)
{
    unsigned char v4[4];
    unsigned char v6[16];

    if (inet_pton(AF_INET, text, v4) == 1)  return 1;
    if (inet_pton(AF_INET6, text, v6) == 1) return 1;

    return 0;
}

static int cg_add_extension(X509 *certificate, X509 *issuer, int nid, const char *value)
{
    X509V3_CTX     ctx;
    X509_EXTENSION *extension;

    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, (issuer != NULL) ? issuer : certificate, certificate, NULL, NULL, 0);

    extension = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);

    if (extension == NULL)
    {
        return -1;
    }

    if (X509_add_ext(certificate, extension, -1) != 1)
    {
        X509_EXTENSION_free(extension);
        return -1;
    }

    X509_EXTENSION_free(extension);
    return 0;
}

/* Assigns a random 20-byte positive serial number.
 *
 * DEVIATION (security fix): the legacy tool derived serial numbers from a GUID
 * in some paths and from a counter in others. A CSPRNG serial of at least 64
 * bits is required by CA/Browser Forum baseline requirements and by every
 * modern validator. */
static unsigned int cg_set_serial_number(X509 *certificate)
{
    unsigned char bytes[20];
    BIGNUM       *bn = NULL;
    ASN1_INTEGER *serial;

    if (RAND_bytes(bytes, sizeof(bytes)) != 1)
    {
        return cg_fail_openssl(CG_BAD_UNEXPECTED_ERROR, "Serial number generation");
    }

    bytes[0] &= 0x7F;   /* keep it positive */

    bn = BN_bin2bn(bytes, sizeof(bytes), NULL);

    if (bn == NULL)
    {
        return cg_fail(CG_BAD_OUT_OF_MEMORY, "Memory allocation failed.");
    }

    serial = X509_get_serialNumber(certificate);

    if (BN_to_ASN1_INTEGER(bn, serial) == NULL)
    {
        BN_free(bn);
        return cg_fail_openssl(CG_BAD_UNEXPECTED_ERROR, "Serial number encoding");
    }

    BN_free(bn);
    return CG_GOOD;
}

/* Sets notBefore/notAfter.
 *
 * LEGACY: a "month" is 30 days, exactly as the legacy arithmetic computed it
 * (30*24*3600*months seconds), so -lm 12 yields 360 days rather than a year.
 * Reproduced so renewal windows do not shift. */
static unsigned int cg_set_validity(X509 *certificate, long long start_time,
                                    short lifetime_in_months)
{
    time_t not_before;

    if (start_time != 0)
    {
        /* start_time is a raw FILETIME: 100ns ticks since 1601-01-01.
         * 11644473600 is the offset in seconds to the Unix epoch. */
        not_before = (time_t)((start_time / 10000000LL) - 11644473600LL);
    }
    else
    {
        not_before = time(NULL);
    }

    if (X509_time_adj_ex(X509_getm_notBefore(certificate), 0, 0, &not_before) == NULL)
    {
        return cg_fail_openssl(CG_BAD_UNEXPECTED_ERROR, "notBefore encoding");
    }

    {
        long long seconds = 30LL * 24 * 3600 * (long long)lifetime_in_months;
        time_t    not_after = (time_t)(not_before + seconds);

        if (X509_time_adj_ex(X509_getm_notAfter(certificate), 0, 0, &not_after) == NULL)
        {
            return cg_fail_openssl(CG_BAD_UNEXPECTED_ERROR, "notAfter encoding");
        }
    }

    return CG_GOOD;
}

/* Adds authorityKeyIdentifier, built explicitly rather than through
 * X509V3_EXT_conf_nid's "keyid" keyword.
 *
 * That keyword resolves the issuer's key id through OpenSSL's *cached*
 * extension table, which is only populated when a certificate is decoded - not
 * when one is assembled in memory with X509_add_ext.  For a self-signed
 * certificate the lookup therefore finds nothing and OpenSSL emits an empty
 * AUTHORITY_KEYID (an empty SEQUENCE, printed as "0."), which some validators
 * reject.  X509_check_purpose does not reliably help, because it skips
 * recomputation when it believes the cache is already built.
 *
 * Deriving the value directly removes the dependency on that cache. */
static unsigned int cg_add_authority_key_id(X509 *certificate, X509 *issuer)
{
    X509              *authority = (issuer != NULL) ? issuer : certificate;
    ASN1_OCTET_STRING *key_id;
    AUTHORITY_KEYID   *akid;
    int                added;

    key_id = (ASN1_OCTET_STRING *)X509_get_ext_d2i(authority,
                                                   NID_subject_key_identifier,
                                                   NULL, NULL);

    if (key_id == NULL)
    {
        /* The issuer carries no subjectKeyIdentifier, so derive the same value
         * the "hash" keyword would: SHA-1 over the subjectPublicKey bits. */
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int  length = 0;

        ERR_clear_error();

        if (X509_pubkey_digest(authority, EVP_sha1(), digest, &length) != 1)
        {
            return cg_fail_openssl(CG_BAD_UNEXPECTED_ERROR, "Authority key identifier digest");
        }

        key_id = ASN1_OCTET_STRING_new();

        if (key_id == NULL ||
            ASN1_OCTET_STRING_set(key_id, digest, (int)length) != 1)
        {
            ASN1_OCTET_STRING_free(key_id);
            return cg_fail(CG_BAD_OUT_OF_MEMORY, "Memory allocation failed.");
        }
    }

    akid = AUTHORITY_KEYID_new();

    if (akid == NULL)
    {
        ASN1_OCTET_STRING_free(key_id);
        return cg_fail(CG_BAD_OUT_OF_MEMORY, "Memory allocation failed.");
    }

    akid->keyid = key_id;   /* ownership transfers to akid */

    /* Non-critical, as RFC 5280 requires for authorityKeyIdentifier. */
    added = X509_add1_ext_i2d(certificate, NID_authority_key_identifier, akid, 0,
                              X509V3_ADD_DEFAULT);

    AUTHORITY_KEYID_free(akid);

    if (added != 1)
    {
        return cg_fail_openssl(CG_BAD_UNEXPECTED_ERROR, "authorityKeyIdentifier");
    }

    return CG_GOOD;
}

/* Adds the OPC UA extension set.
 *
 * LEGACY, and deliberately preserved: application (non-CA) certificates are
 * given basicConstraints "critical, CA:TRUE, pathlen:0" and a keyUsage that
 * includes keyCertSign.  That is what the legacy tool emitted, and OPC UA
 * deployments have validated against it for years.  It is wrong by modern PKI
 * standards - an end-entity certificate should not be a CA - but correcting it
 * here would alter the trust semantics of every certificate this tool issues.
 * See README.md; change it only as a deliberate, announced break. */
static unsigned int cg_add_extensions(X509 *certificate, X509 *issuer, int is_ca,
                                      int is_ec, const char *application_uri,
                                      const cg_list *domain_names)
{
    /* A certificate is self-signed when no separate issuer was supplied. */
    const int self_signed = (issuer == NULL);

    if (cg_add_extension(certificate, issuer, NID_subject_key_identifier, "hash") != 0)
    {
        return cg_fail_openssl(CG_BAD_UNEXPECTED_ERROR, "subjectKeyIdentifier");
    }

    if (is_ca)
    {
        /* Same for RSA and ECC: a CA signs certificates and CRLs, and neither
         * role needs an encipherment bit. */
        if (cg_add_extension(certificate, issuer, NID_basic_constraints,
                             "critical, CA:TRUE") != 0 ||
            cg_add_extension(certificate, issuer, NID_key_usage,
                             "critical, digitalSignature, keyCertSign, cRLSign") != 0)
        {
            return cg_fail_openssl(CG_BAD_UNEXPECTED_ERROR, "CA extensions");
        }
    }
    else
    {
        cg_str subject_alt_name;
        size_t ii;
        int    failed;

        /* keyUsage differs by key algorithm - OPC UA Part 6 section 6.2.2:
         *
         *   "For RSA keys, the keyUsage shall include digitalSignature,
         *    nonRepudiation, keyEncipherment and dataEncipherment. For ECC
         *    keys, the keyUsage shall include digitalSignature."
         *   "Self-signed Certificates shall also include keyCertSign."
         *
         * ECC keys sign only; they cannot encipher, so keyEncipherment and
         * dataEncipherment are meaningless on them (the ECC handshake agrees
         * keys with ephemeral pairs, not with the certificate key).  The spec
         * also says other keyUsage bits are "allowed but not recommended", so
         * the ECC set is kept to the minimum the spec requires rather than
         * mirroring the RSA list.
         *
         * The RSA branch reproduces the legacy tool's extensions verbatim,
         * including the CA:TRUE that modern PKI practice would not use - see
         * README.md for why that is deliberately preserved. */
        const char *basic_constraints;
        const char *key_usage;

        if (is_ec)
        {
            /* Part 6: the CA flag "must be FALSE" for an Application Instance
             * Certificate; TRUE is only a backward-compatibility tolerance for
             * self-signed ones.  ECC support is new here, with no installed
             * base to stay compatible with, so it follows the spec. */
            basic_constraints = self_signed
                ? "critical, CA:TRUE, pathlen:0"
                : "critical, CA:FALSE";

            key_usage = self_signed
                ? "critical, digitalSignature, keyCertSign"
                : "critical, digitalSignature";
        }
        else
        {
            basic_constraints = "critical, CA:TRUE, pathlen:0";
            key_usage = "critical, nonRepudiation, digitalSignature, "
                        "keyEncipherment, dataEncipherment, keyCertSign";
        }

        if (cg_add_extension(certificate, issuer, NID_basic_constraints,
                             basic_constraints) != 0 ||
            cg_add_extension(certificate, issuer, NID_key_usage, key_usage) != 0)
        {
            return cg_fail_openssl(CG_BAD_UNEXPECTED_ERROR, "application extensions");
        }

        /* extendedKeyUsage: mandatory for RSA profiles, optional for ECC ones.
         * It is emitted for both, because it is harmless and real deployments
         * expect serverAuth/clientAuth on a server certificate.  Not marked
         * critical for ECC: making an optional extension critical invites
         * rejection by a conformant validator that chooses not to parse it. */
        if (cg_add_extension(certificate, issuer, NID_ext_key_usage,
                             is_ec ? "serverAuth, clientAuth"
                                   : "critical, serverAuth, clientAuth") != 0)
        {
            return cg_fail_openssl(CG_BAD_UNEXPECTED_ERROR, "extendedKeyUsage");
        }

        cg_str_init(&subject_alt_name);
        cg_str_append(&subject_alt_name, "URI:");
        cg_str_append(&subject_alt_name, application_uri);

        for (ii = 0; ii < domain_names->count; ii++)
        {
            const char *domain = domain_names->items[ii];

            if (domain == NULL || *domain == 0)
            {
                continue;
            }

            /* An address literal becomes IP:, anything else DNS:.
             *
             * DEVIATION: the legacy code used inet_addr, which recognises IPv4
             * only, so an IPv6 literal was emitted as DNS:<literal> - which is
             * not a valid DNS SAN and would be rejected downstream.  inet_pton
             * is checked for both families here; IPv4 behaviour is unchanged. */
            cg_str_append(&subject_alt_name, cg_is_address_literal(domain) ? ",IP:" : ",DNS:");
            cg_str_append(&subject_alt_name, domain);
        }

        failed = cg_add_extension(certificate, issuer, NID_subject_alt_name,
                                  subject_alt_name.data) != 0;
        cg_str_free(&subject_alt_name);

        if (failed)
        {
            return cg_fail_openssl(CG_BAD_UNEXPECTED_ERROR, "subjectAltName");
        }
    }

    /* authorityKeyIdentifier last, because it depends on the issuer's
     * subjectKeyIdentifier - which for a self-signed certificate is the one
     * added at the top of this function. */
    return cg_add_authority_key_id(certificate, issuer);
}

/* ---------------------------------------------------------------------------
 * issue
 * ------------------------------------------------------------------------ */
unsigned int cg_cmd_issue(cg_args *args)
{
    unsigned int   status = CG_GOOD;
    EVP_PKEY      *key = NULL;
    EVP_PKEY      *issuer_key = NULL;
    X509          *issuer_certificate = NULL;
    X509          *certificate = NULL;
    X509_NAME     *subject = NULL;
    cg_name_fields fields;
    cg_str         application_uri;
    char          *public_key_path = NULL;
    char          *private_key_path = NULL;
    char          *thumbprint = NULL;

    cg_name_fields_init(&fields);
    cg_str_init(&application_uri);

    /* ---- issuer, when signing with a CA ---- */
    if (!cg_str_is_empty(&args->issuer_key_file_path))
    {
        status = cg_load_private_key(args->issuer_key_file_path.data,
                                     args->input_is_pem,
                                     args->issuer_key_password.data,
                                     &issuer_key, &issuer_certificate);

        if (CG_IS_BAD(status))
        {
            cg_fail(status, "Could not load private key. "
                            "The key may be bad or the password is invalid.");
            goto cleanup;
        }

        if (issuer_certificate == NULL)
        {
            if (cg_str_is_empty(&args->issuer_certificate))
            {
                status = cg_fail(CG_BAD_INVALID_ARGUMENT,
                                 "The private key has no public key information. "
                                 "The -icf <certifcate> argument must be specified.");
                goto cleanup;
            }

            {
                unsigned char *data = NULL;
                size_t         size = 0;
                const unsigned char *pos;

                if (cg_is_hex_string(args->issuer_certificate.data))
                {
                    data = cg_from_hex(args->issuer_certificate.data, &size);
                }
                else
                {
                    status = cg_read_file(args->issuer_certificate.data, &data, &size);
                    if (CG_IS_BAD(status)) goto cleanup;
                }

                pos = data;
                issuer_certificate = d2i_X509(NULL, &pos, (long)size);
                cg_free(data);

                if (issuer_certificate == NULL)
                {
                    status = cg_fail_openssl(CG_BAD_CERTIFICATE_INVALID,
                                             "Issuer certificate decoding");
                    goto cleanup;
                }
            }
        }
    }

    /* ---- application URI ---- */
    if (cg_str_is_empty(&args->application_uri))
    {
        cg_str_append(&application_uri, "urn:");

        if (args->domain_names.count > 0 && args->domain_names.items[0][0] != 0)
        {
            cg_str_append(&application_uri, args->domain_names.items[0]);
            cg_str_append(&application_uri, ":");
        }

        cg_str_append(&application_uri, args->application_name.data);
    }
    else
    {
        cg_str_set(&application_uri, args->application_uri.data);
    }

    {
        cg_str sanitized;
        cg_str_init(&sanitized);
        cg_sanitize_uri(application_uri.data, &sanitized);
        cg_str_free(&application_uri);
        application_uri = sanitized;
    }

    /* ---- subject name ---- */
    if (!cg_str_is_empty(&args->subject_name))
    {
        status = cg_parse_subject_name(args->subject_name.data, &fields);
        if (CG_IS_BAD(status)) goto cleanup;
    }

    if (fields.names.count == 0)
    {
        if (cg_str_is_empty(&args->application_name))
        {
            status = cg_fail(CG_BAD_INVALID_ARGUMENT,
                             "An -applicationName or -subjectName must be specified.");
            goto cleanup;
        }

        cg_name_fields_add(&fields, "CN", args->application_name.data);

        if (!cg_str_is_empty(&args->organization))
        {
            cg_name_fields_add(&fields, "O", args->organization.data);
        }

        /* LEGACY: the domain component is only added for non-CA certificates. */
        if (!args->is_ca && args->domain_names.count > 0 &&
            args->domain_names.items[0][0] != 0)
        {
            cg_name_fields_add(&fields, "DC", args->domain_names.items[0]);
        }
    }

    status = cg_build_x509_name(&fields, &subject);
    if (CG_IS_BAD(status)) goto cleanup;

    /* ---- key ---- */
    if (args->reuse_key)
    {
        if (cg_str_is_empty(&args->private_key_file_path))
        {
            status = cg_fail(CG_BAD_INVALID_ARGUMENT,
                             "Need a path to the existing certificate.");
            goto cleanup;
        }

        {
            X509 *existing = NULL;

            status = cg_load_private_key(args->private_key_file_path.data,
                                         args->input_is_pem,
                                         args->private_key_password.data,
                                         &key, &existing);
            X509_free(existing);

            if (CG_IS_BAD(status))
            {
                cg_fail(status, "Could not load private key. "
                                "The key may be bad or the password is invalid.");
                goto cleanup;
            }
        }
    }
    else
    {
        status = cg_generate_key(args->key_type, args->key_size, &key);
        if (CG_IS_BAD(status)) goto cleanup;
    }

    /* ---- build ---- */
    certificate = X509_new();

    if (certificate == NULL)
    {
        status = cg_fail(CG_BAD_OUT_OF_MEMORY, "Memory allocation failed.");
        goto cleanup;
    }

    /* X.509 v3 */
    if (X509_set_version(certificate, 2) != 1 ||
        X509_set_subject_name(certificate, subject) != 1 ||
        X509_set_pubkey(certificate, key) != 1)
    {
        status = cg_fail_openssl(CG_BAD_UNEXPECTED_ERROR, "Certificate setup");
        goto cleanup;
    }

    status = cg_set_serial_number(certificate);
    if (CG_IS_BAD(status)) goto cleanup;

    status = cg_set_validity(certificate, args->start_time, args->lifetime_in_months);
    if (CG_IS_BAD(status)) goto cleanup;

    if (issuer_certificate != NULL)
    {
        if (X509_set_issuer_name(certificate,
                                 X509_get_subject_name(issuer_certificate)) != 1)
        {
            status = cg_fail_openssl(CG_BAD_UNEXPECTED_ERROR, "Issuer name");
            goto cleanup;
        }
    }
    else
    {
        /* Self-signed. */
        if (X509_set_issuer_name(certificate, subject) != 1)
        {
            status = cg_fail_openssl(CG_BAD_UNEXPECTED_ERROR, "Issuer name");
            goto cleanup;
        }
    }

    status = cg_add_extensions(certificate, issuer_certificate, args->is_ca,
                               cg_is_ec_key_type(args->key_type),
                               application_uri.data, &args->domain_names);
    if (CG_IS_BAD(status)) goto cleanup;

    /* ---- sign ----
     *
     * The digest has to match the signing key, which for a CA-issued
     * certificate is the issuer's key, not the one just generated.  Choosing it
     * from -keyType alone would pair an RSA CA's signature with an ECC default,
     * so it is derived from the actual key about to sign.
     *
     * When -hashSize was given explicitly it wins, preserving the legacy
     * contract.  Otherwise an ECC key gets the hash its OPC UA SecurityPolicy
     * specifies (SHA-256 for the 256-bit curves, SHA-384 for the 384-bit ones)
     * rather than inheriting the RSA default of 256. */
    {
        EVP_PKEY *signing_key = (issuer_key != NULL) ? issuer_key : key;
        int       signing_id  = EVP_PKEY_get_base_id(signing_key);
        const EVP_MD *signing_digest;

        if (signing_id == EVP_PKEY_ED25519 || signing_id == EVP_PKEY_ED448)
        {
            /* PureEdDSA: the algorithm hashes internally and OpenSSL requires
             * a NULL digest here.  -hashSize is not applicable. */
            signing_digest = NULL;
        }
        else if (args->hash_size_specified)
        {
            signing_digest = cg_select_digest(args->hash_size);
        }
        else if (signing_id == EVP_PKEY_EC)
        {
            signing_digest = cg_select_digest(cg_signing_key_hash_size(signing_key));
        }
        else
        {
            signing_digest = cg_select_digest(args->hash_size);
        }

        if (X509_sign(certificate, signing_key, signing_digest) == 0)
        {
            status = cg_fail_openssl(CG_BAD_UNEXPECTED_ERROR, "Certificate signing");
            goto cleanup;
        }
    }

    /* ---- store ---- */
    if (cg_str_is_empty(&args->store_path))
    {
        status = cg_fail(CG_BAD_INVALID_ARGUMENT,
                         "A -storePath must be specified.");
        goto cleanup;
    }

    status = cg_save_private_key(args->store_path.data, certificate, key,
                                 args->password.data, args->output_is_pem,
                                 &private_key_path);
    if (CG_IS_BAD(status)) goto cleanup;

    status = cg_save_public_key(args->store_path.data, certificate, &public_key_path);
    if (CG_IS_BAD(status)) goto cleanup;

    status = cg_get_thumbprint(certificate, &thumbprint);
    if (CG_IS_BAD(status)) goto cleanup;

    cg_map_set(&args->output, "-thumbprint", thumbprint);
    cg_map_set(&args->output, "-publicKeyFilePath", public_key_path);
    cg_map_set(&args->output, "-privateKeyFilePath", private_key_path);

cleanup:
    cg_free(thumbprint);
    cg_free(public_key_path);
    cg_free(private_key_path);
    X509_NAME_free(subject);
    X509_free(certificate);
    X509_free(issuer_certificate);
    EVP_PKEY_free(issuer_key);
    EVP_PKEY_free(key);
    cg_str_free(&application_uri);
    cg_name_fields_free(&fields);

    return status;
}

/* ---------------------------------------------------------------------------
 * Commands not yet ported
 *
 * These are deliberately explicit rather than silently wrong.  Each has a
 * working legacy implementation in CertificateGenerator/opcua_certficates.cpp;
 * see CertGen/README.md for the porting status and order of work.
 * ------------------------------------------------------------------------ */
static unsigned int cg_not_yet_ported(const char *command)
{
    return cg_fail(CG_BAD_NOT_SUPPORTED,
                   "The '%s' command is not yet implemented in this OpenSSL 3.x port. "
                   "Use the legacy Opc.Ua.CertificateGenerator.exe for this command. "
                   "See CertGen/README.md.",
                   command);
}

unsigned int cg_cmd_revoke(cg_args *args)
{
    (void)args;
    return cg_not_yet_ported("revoke");
}

unsigned int cg_cmd_convert(cg_args *args)
{
    (void)args;
    return cg_not_yet_ported("convert");
}

unsigned int cg_cmd_replace(cg_args *args)
{
    (void)args;
    return cg_not_yet_ported("replace");
}

unsigned int cg_cmd_create_request(cg_args *args)
{
    (void)args;
    return cg_not_yet_ported("request");
}

unsigned int cg_cmd_process_request(cg_args *args)
{
    (void)args;
    return cg_not_yet_ported("process");
}
