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

#include "cmdline.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/opensslv.h>

#define CG_LINE_BUFFER_CHARS 65535

/* ---------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------ */
void cg_args_init(cg_args *args)
{
    memset(args, 0, sizeof(*args));

    cg_str_init(&args->parameter_file_path);
    cg_map_init(&args->output);

    cg_str_init(&args->command);
    cg_str_init(&args->store_path);
    cg_str_init(&args->application_name);
    cg_str_init(&args->application_uri);
    cg_str_init(&args->subject_name);
    cg_str_init(&args->organization);
    cg_list_init(&args->domain_names);
    cg_str_init(&args->password);
    cg_str_init(&args->issuer_certificate);
    cg_str_init(&args->issuer_key_file_path);
    cg_str_init(&args->issuer_key_password);
    cg_str_init(&args->public_key_file_path);
    cg_str_init(&args->private_key_file_path);
    cg_str_init(&args->private_key_password);
    cg_str_init(&args->request_file_path);

    /* Defaults, matching the legacy CommandLineArgs constructor.
     *
     * Note these differ from what the usage text claims: the usage says
     * keySize defaults to 1024 and lifetimeInMonths to 60, but the constructor
     * used 2048 and 12.  The constructor is the real behaviour, so it is what
     * is reproduced here; the usage text is reproduced verbatim as well, which
     * means the discrepancy is preserved too.  See README.md. */
    args->key_type = CG_KEY_RSA;
    args->key_size = 2048;
    args->start_time = 0;
    args->hash_size = 256;
    args->lifetime_in_months = 12;
    args->hash_size_specified = 0;
    args->is_ca = 0;
    args->input_is_pem = 0;
    args->output_is_pem = 0;
    args->reuse_key = 0;
}

void cg_args_free(cg_args *args)
{
    cg_str_free(&args->parameter_file_path);
    cg_map_free(&args->output);

    cg_str_free(&args->command);
    cg_str_free(&args->store_path);
    cg_str_free(&args->application_name);
    cg_str_free(&args->application_uri);
    cg_str_free(&args->subject_name);
    cg_str_free(&args->organization);
    cg_list_free(&args->domain_names);
    cg_str_free(&args->password);
    cg_str_free(&args->issuer_certificate);
    cg_str_free(&args->issuer_key_file_path);
    cg_str_free(&args->issuer_key_password);
    cg_str_free(&args->public_key_file_path);
    cg_str_free(&args->private_key_file_path);
    cg_str_free(&args->private_key_password);
    cg_str_free(&args->request_file_path);
}

void cg_args_set_error(cg_args *args, unsigned int code, const char *message)
{
    char buffer[32];

    /* DEVIATION (bug fix): the legacy code assigned the integer status code
     * straight into a std::string, which selected the char overload and emitted
     * a single stray byte - the low octet of the status code - as the value of
     * `-code`.  A hex status code is what the field was plainly meant to carry.
     * See README.md. */
    snprintf(buffer, sizeof(buffer), "0x%08X", code);
    cg_map_set(&args->output, "-code", buffer);
    cg_map_set(&args->output, "-error", message);
}

/* ---------------------------------------------------------------------------
 * Argument sources
 * ------------------------------------------------------------------------ */

/* Reads "flag value" pairs, one per line, terminated by a blank line.
 *
 * DEVIATION (bug fix): the legacy version passed sizeof(buffer) to fgetws
 * where a character count was required, allowing a write of twice the buffer
 * size.  This passes the element count. */
static void cg_read_arguments_from_file(FILE *file, cg_map *arguments)
{
    static wchar_t wide_buffer[CG_LINE_BUFFER_CHARS];

    cg_str flag;
    cg_str value;
    int    reading_value = 0;

    cg_str_init(&flag);
    cg_str_init(&value);

    while (fgetws(wide_buffer, CG_LINE_BUFFER_CHARS, file) != NULL)
    {
        char *line = cg_utf16_to_utf8(wide_buffer);
        char *pos;

        if (line == NULL)
        {
            break;
        }

        for (pos = line; *pos != 0; pos++)
        {
            if (*pos == '\r')
            {
                continue;
            }

            if (*pos == '\n')
            {
                /* A blank line ends the command block. */
                if (cg_str_is_empty(&flag))
                {
                    cg_free(line);
                    cg_str_free(&flag);
                    cg_str_free(&value);
                    return;
                }

                cg_map_set(arguments, flag.data, value.data);
                cg_str_clear(&flag);
                cg_str_clear(&value);
                reading_value = 0;
                continue;
            }

            if (!reading_value)
            {
                if (isspace((unsigned char)*pos))
                {
                    if (!cg_str_is_empty(&flag))
                    {
                        reading_value = 1;
                    }

                    continue;
                }

                cg_str_append_char(&flag, *pos);
                continue;
            }

            /* Leading whitespace in the value is skipped; once the value has
             * started, interior and trailing whitespace is kept and trimmed
             * later by cg_is_arg_specified. */
            if (isspace((unsigned char)*pos) && cg_str_is_empty(&value))
            {
                continue;
            }

            cg_str_append_char(&value, *pos);
        }

        cg_free(line);
    }

    /* Note: as in the legacy implementation, a pending flag/value pair at
     * end-of-file without a terminating newline is discarded. */
    cg_str_free(&flag);
    cg_str_free(&value);
}

/* Returns CG_GOOD, or an error when a bare (non-flag) token is found. */
static unsigned int cg_read_arguments_from_command_line(int argc, wchar_t *argv[],
                                                        cg_map *arguments)
{
    cg_str flag;
    int    reading_value = 0;
    int    ii;

    cg_str_init(&flag);

    for (ii = 1; ii < argc; ii++)
    {
        char *text = cg_utf16_to_utf8(argv[ii]);

        if (text == NULL)
        {
            cg_str_free(&flag);
            return cg_fail(CG_BAD_OUT_OF_MEMORY, "Memory allocation failed.");
        }

        if (!reading_value)
        {
            cg_str_set(&flag, text);
            reading_value = 1;

            if (strcmp(text, "-?") == 0 || strcmp(text, "/?") == 0 ||
                strcmp(text, "-help") == 0 || strcmp(text, "/help") == 0)
            {
                cg_map_set(arguments, "-?", "");
                cg_free(text);
                cg_str_free(&flag);
                return CG_GOOD;
            }

            if (text[0] != '-')
            {
                unsigned int status =
                    cg_fail(CG_BAD_INVALID_ARGUMENT, "Unrecognized Parameter: %s", text);
                cg_free(text);
                cg_str_free(&flag);
                return status;
            }
        }
        else
        {
            cg_map_set(arguments, flag.data, text);
            cg_str_clear(&flag);
            reading_value = 0;
        }

        cg_free(text);
    }

    /* Note: as in the legacy implementation, a trailing flag with no value is
     * silently discarded. */
    cg_str_free(&flag);
    return CG_GOOD;
}

/* ---------------------------------------------------------------------------
 * Argument extraction
 * ------------------------------------------------------------------------ */

/* Looks up the long form then the short form, removes both, and returns the
 * trimmed value.  Returns NULL when absent or empty - the legacy code only
 * applied a value when it was non-empty, so `-ca ""` is a no-op.
 *
 * Caller frees the result with cg_free.
 *
 * DEVIATION (bug fix): the legacy trim loop ran a size_t index down with an
 * `ii >= 0` condition, which is always true; an all-whitespace value underflowed
 * the index and read out of bounds.  cg_str_trim handles that case. */
static char *cg_is_arg_specified(cg_map *arguments, const char *long_form,
                                 const char *short_form)
{
    const char *found = cg_map_get(arguments, long_form);
    cg_str      value;
    char       *result;

    if (found == NULL)
    {
        found = cg_map_get(arguments, short_form);
    }

    cg_str_init(&value);

    if (found != NULL)
    {
        cg_str_set(&value, found);
    }

    cg_map_erase(arguments, long_form);
    cg_map_erase(arguments, short_form);

    cg_str_trim(&value);

    if (cg_str_is_empty(&value))
    {
        cg_str_free(&value);
        return NULL;
    }

    result = value.data;   /* hand the buffer over to the caller */
    return result;
}

static int cg_is_true(const char *text)
{
    return (_stricmp(text, "true") == 0) ? 1 : 0;
}

/* The legacy tool rejected non-ASCII in path arguments. */
static int cg_has_non_ascii(const char *text)
{
    const char *pos;

    if (text == NULL)
    {
        return 0;
    }

    for (pos = text; *pos != 0; pos++)
    {
        if ((unsigned char)*pos > 127)
        {
            return 1;
        }
    }

    return 0;
}

/* Assigns a path argument, rejecting non-ASCII. Returns 0 when rejected. */
static int cg_set_path_arg(cg_args *args, cg_str *target, char *value,
                           const char *description)
{
    if (cg_has_non_ascii(value))
    {
        char message[256];
        snprintf(message, sizeof(message),
                 "Non-ASCII file paths not supported at this time (%s)", description);

        cg_map_set(&args->output, "-error", message);
        cg_map_set(&args->output, "-storePath", value);
        return 0;
    }

    cg_str_set(target, value);
    return 1;
}

static int cg_valid_args(cg_args *args, cg_map *arguments)
{
    char *value;
    int   accepted = 1;

    if ((value = cg_is_arg_specified(arguments, "-command", "-cmd")) != NULL)
    {
        cg_str_set(&args->command, value);
        cg_free(value);
    }

    if ((value = cg_is_arg_specified(arguments, "-storePath", "-sp")) != NULL)
    {
        /* The legacy message for storePath has no trailing period, unlike the
         * other two; reproduced as-is. */
        accepted = cg_set_path_arg(args, &args->store_path, value, "storePath");
        cg_free(value);
        if (!accepted) return 0;
    }

    if ((value = cg_is_arg_specified(arguments, "-applicationName", "-an")) != NULL)
    {
        cg_str_set(&args->application_name, value);
        cg_free(value);
    }

    if ((value = cg_is_arg_specified(arguments, "-applicationUri", "-au")) != NULL)
    {
        cg_str_set(&args->application_uri, value);
        cg_free(value);
    }

    if ((value = cg_is_arg_specified(arguments, "-subjectName", "-sn")) != NULL)
    {
        cg_str_set(&args->subject_name, value);
        cg_free(value);
    }

    if ((value = cg_is_arg_specified(arguments, "-organization", "-o")) != NULL)
    {
        cg_str_set(&args->organization, value);
        cg_free(value);
    }

    if ((value = cg_is_arg_specified(arguments, "-domainNames", "-dn")) != NULL)
    {
        cg_list_add_split(&args->domain_names, value, ',');
        cg_free(value);
    }

    if ((value = cg_is_arg_specified(arguments, "-password", "-pw")) != NULL)
    {
        cg_str_set(&args->password, value);
        cg_free(value);
    }

    if ((value = cg_is_arg_specified(arguments, "-issuerCertificate", "-icf")) != NULL)
    {
        cg_str_set(&args->issuer_certificate, value);
        cg_free(value);
    }

    if ((value = cg_is_arg_specified(arguments, "-requestFilePath", "-rfp")) != NULL)
    {
        cg_str_set(&args->request_file_path, value);
        cg_free(value);
    }

    if ((value = cg_is_arg_specified(arguments, "-issuerKeyFilePath", "-ikf")) != NULL)
    {
        accepted = cg_set_path_arg(args, &args->issuer_key_file_path, value,
                                   "issuerKeyFilePath.");
        cg_free(value);
        if (!accepted) return 0;
    }

    if ((value = cg_is_arg_specified(arguments, "-issuerKeyPassword", "-ikp")) != NULL)
    {
        cg_str_set(&args->issuer_key_password, value);
        cg_free(value);
    }

    if ((value = cg_is_arg_specified(arguments, "-keyType", "-kt")) != NULL)
    {
        if (strcmp(value, "rsa") == 0)                   args->key_type = CG_KEY_RSA;
        else if (strcmp(value, "nistP256") == 0)         args->key_type = CG_KEY_EC_NIST_P256;
        else if (strcmp(value, "nistP384") == 0)         args->key_type = CG_KEY_EC_NIST_P384;
        else if (strcmp(value, "brainpoolP256r1") == 0)  args->key_type = CG_KEY_EC_BRAINPOOL_P256R1;
        else if (strcmp(value, "brainpoolP384r1") == 0)  args->key_type = CG_KEY_EC_BRAINPOOL_P384R1;
        else if (strcmp(value, "curve25519") == 0)       args->key_type = CG_KEY_EC_CURVE25519;
        else if (strcmp(value, "curve448") == 0)         args->key_type = CG_KEY_EC_CURVE448;
        else
        {
            cg_map_set(&args->output, "-error", "Unsupported keytype.");
            cg_map_set(&args->output, "-keyType", value);
            cg_free(value);
            return 0;
        }

        cg_free(value);
    }

    if ((value = cg_is_arg_specified(arguments, "-keySize", "-ks")) != NULL)
    {
        args->key_size = (unsigned short)atoi(value);
        cg_free(value);
    }

    if ((value = cg_is_arg_specified(arguments, "-startTime", "-st")) != NULL)
    {
        args->start_time = _atoi64(value);
        cg_free(value);
    }

    if ((value = cg_is_arg_specified(arguments, "-lifetimeInMonths", "-lm")) != NULL)
    {
        args->lifetime_in_months = (short)atoi(value);
        cg_free(value);
    }

    if ((value = cg_is_arg_specified(arguments, "-publicKeyFilePath", "-pbf")) != NULL)
    {
        accepted = cg_set_path_arg(args, &args->public_key_file_path, value,
                                   "publicKeyFilePath.");
        cg_free(value);
        if (!accepted) return 0;
    }

    if ((value = cg_is_arg_specified(arguments, "-privateKeyFilePath", "-pvf")) != NULL)
    {
        accepted = cg_set_path_arg(args, &args->private_key_file_path, value,
                                   "privateKeyFilePath.");
        cg_free(value);
        if (!accepted) return 0;
    }

    if ((value = cg_is_arg_specified(arguments, "-privateKeyPassword", "-pvp")) != NULL)
    {
        cg_str_set(&args->private_key_password, value);
        cg_free(value);
    }

    if ((value = cg_is_arg_specified(arguments, "-ca", "-ca")) != NULL)
    {
        args->is_ca = cg_is_true(value);
        cg_free(value);
    }

    if ((value = cg_is_arg_specified(arguments, "-hashSize", "-hs")) != NULL)
    {
        args->hash_size = (unsigned short)atoi(value);

        if (args->hash_size == 0)
        {
            args->hash_size = 256;
        }

        args->hash_size_specified = 1;
        cg_free(value);
    }

    if ((value = cg_is_arg_specified(arguments, "-pem", "-pem")) != NULL)
    {
        args->output_is_pem = cg_is_true(value);
        cg_free(value);
    }

    if ((value = cg_is_arg_specified(arguments, "-pemInput", "-pemInput")) != NULL)
    {
        args->input_is_pem = cg_is_true(value);
        cg_free(value);
    }

    if ((value = cg_is_arg_specified(arguments, "-reuseKey", "-rk")) != NULL)
    {
        args->reuse_key = cg_is_true(value);
        cg_free(value);
    }

    /* Anything left over is a syntax error.  Note that -inlineOutput / -io is
     * documented in the usage text but was never consumed here, so passing it
     * lands in this branch.  Reproduced: see README.md. */
    if (cg_map_count(arguments) > 0)
    {
        size_t ii;

        cg_map_set(&args->output, "-error",
                   "Unprocessed arguments exist possible syntax error.");

        for (ii = 0; ii < arguments->count; ii++)
        {
            cg_map_set(&args->output, arguments->items[ii].key,
                       arguments->items[ii].value);
        }

        return 0;
    }

    return 1;
}

/* ---------------------------------------------------------------------------
 * Output
 * ------------------------------------------------------------------------ */

/* Opens the parameter file for writing, or returns stdout. */
static FILE *cg_open_output(cg_args *args, int *using_stdout)
{
    wchar_t *wide;
    FILE    *file = NULL;

    *using_stdout = 1;

    if (cg_str_is_empty(&args->parameter_file_path))
    {
        return stdout;
    }

    wide = cg_utf8_to_utf16(args->parameter_file_path.data);
    if (wide == NULL)
    {
        return stdout;
    }

    file = _wfopen(wide, L"w,ccs=UTF-8");
    cg_free(wide);

    if (file == NULL)
    {
        /* The legacy code threw here.  At this point we are already on the way
         * out, so falling back to stdout is strictly more useful than losing
         * the output entirely. */
        return stdout;
    }

    *using_stdout = 0;
    return file;
}

static void cg_write_response(FILE *file, const char *text, const char *parameter)
{
    wchar_t *wide;

    if (text != NULL)
    {
        wide = cg_utf8_to_utf16(text);

        if (wide != NULL)
        {
            fputws(wide, file);
            cg_free(wide);
        }
    }

    /* The legacy code always emitted the separating space, even for an empty
     * value, so a bare flag echoes back as "-? " with a trailing space. */
    fputws(L" ", file);

    if (parameter != NULL)
    {
        wide = cg_utf8_to_utf16(parameter);

        if (wide != NULL)
        {
            fputws(wide, file);
            cg_free(wide);
        }
    }

    fputws(L"\r\n", file);
}

void cg_args_write_output(cg_args *args)
{
    int   using_stdout;
    FILE *file = cg_open_output(args, &using_stdout);
    size_t ii;

    cg_map_sort(&args->output);

    for (ii = 0; ii < args->output.count; ii++)
    {
        cg_write_response(file, args->output.items[ii].key,
                          args->output.items[ii].value);
    }

    if (!using_stdout)
    {
        fclose(file);
    }
}

void cg_args_write_usage(cg_args *args)
{
    int   using_stdout;
    FILE *f = cg_open_output(args, &using_stdout);

    /* Verbatim from the legacy tool.  If you change a line here you have
     * changed the documented interface - update README.md too. */
    fputs("-command or -cmd <issue | revoke | unrevoke | convert | replace | request | process | password> The action to perform (default = issue).\r\n", f);
    fputs("\r\n", f);
    fputs("    issue: create a new certificate.\r\n", f);
    fputs("    revoke: revoke a certificate.\r\n", f);
    fputs("    unrevoke: unrevoke a certificate.\r\n", f);
    fputs("    convert: convert a private key file.\r\n", f);
    fputs("    replace: update the certificates in a PFX file.\r\n", f);
    fputs("    request: create a new certificate signing request.\r\n", f);
    fputs("    process: create a new certificate from a new certificate signing request.\r\n", f);
    fputs("    password: change the password on a private key.\r\n", f);
    fputs("\r\n", f);
    fputs("-storePath or -sp <filepath>                The directory of the certificate store (must be writeable).\r\n", f);
    fputs("-applicationName or -an <name>              The name of the application.\r\n", f);
    fputs("-applicationUri or -au <uri>                The URI for the appplication.\r\n", f);
    fputs("-subjectName or -sn <DN>                    The distinguished subject name, fields seperated by a / (i.e. CN=Hello/O=World).\r\n", f);
    fputs("-organization or -o <name>                  The organization.\r\n", f);
    fputs("-domainNames or -dn <name>,<name>           A list of domain names seperated by commas\r\n", f);
    fputs("-password or -pw <password>                 The password for the new private key file.\r\n", f);
    fputs("-issuerCertificate or -icf <filepath>       The path to the issuer certificate file.\r\n", f);
    fputs("-issuerKeyFilePath or -ikf <filepath>       The path to the issuer private key file.\r\n", f);
    fputs("-issuerKeyPassword or -ikp <password>       The password for the issuer private key file.\r\n", f);
    fputs("-keyType or -kt <keytype>                   One of rsa, nistP256, nistP384, brainpoolP256r1, brainpoolP384r1, curve25519 or curve448 (default = rsa).\r\n", f);
    fputs("-keySize or -ks <bits>                      The size of key as a multiple of 1024 (default = 1024).\r\n", f);
    fputs("-hashSize or -hs <bits>                     The size of hash <160 | 256 | 512> (default = 256).\r\n", f);
    fputs("-startTime or -st <nanoseconds>             The start time for the validity period (nanoseconds from 1600-01-01).\r\n", f);
    fputs("-lifetimeInMonths or -lm <months>           The lifetime in months (default = 60).\r\n", f);
    fputs("-publicKeyFilePath or -pbf <filepath>       The path to the certificate to renew or revoke (a DER file).\r\n", f);
    fputs("-privateKeyFilePath or -pvf <filepath>      The path to an existing private key to reuse or convert.\r\n", f);
    fputs("-privateKeyPassword or -pvp <password>      The password for the existing private key.\r\n", f);
    fputs("-reuseKey or -rk <true | false>             Whether to reuse an existing public key (default = false).\r\n", f);
    fputs("-ca <true | false>                          Whether to create a CA certificate (default = false).\r\n", f);
    fputs("-pemInput <true | false>                    Whether the privateKeyFilePath is in PEM format (default = PFX).\r\n", f);
    fputs("-pem <true | false>                         Whether to output in the PEM format (default = PFX).\r\n", f);
    fputs("-requestFilePath or -rfp <filepath>         The path to certificate signing request.\r\n", f);
    fputs("-inlineOutput or -io <filepath>             Write all output as a hexadecimal string instead of saving to a file.\r\n", f);
    fputs("\r\n", f);
    fputs("\r\n", f);
    fputs("All input file arguments can be a valid directory path or a hexadecimal string.\r\n", f);
    fputs("All output files are written to output as hexadecimal strings if -inlineOutput true is specified.\r\n", f);
    fputs("\r\n", f);
    fputs("Create a self-signed Application Certificate: -cmd issue -sp . -an MyApp -au urn:MyHostMyCompany:MyApp -o MyCompany -dn MyHost -pw MyCertFilePassword\r\n", f);
    fputs("Create a CA Certificate: -cmd issue -sp . -sn CN=MyCA/O=Acme -ca true\r\n", f);
    fputs("Issue an Application Certificate: -cmd issue -sp . -an MyApp -ikf CaKeyFile -ikp CaPassword\r\n", f);
    fputs("Renew a Certificate: -cmd issue -sp . -pbf MyCertFile -ikf CaKeyFile -ikp CaPassword\r\n", f);
    fputs("Revoke a Certificate: -cmd revoke -sp . -pbf MyCertFile -ikf CaKeyFile -ikp CaPassword -hs 256\r\n", f);
    fputs("Unrevoke a Certificate: -cmd unrevoke -sp . -pbf MyCertFile -ikf CaKeyFile -ikp CaPassword\r\n", f);
    fputs("Convert key format: -cmd convert -pvf MyKeyFile -pvp oldpassword -pem true -pw newpassword\r\n", f);
    fputs("Create a certificate request: -cmd request -pbf MyCertFile.der -pvf MyCertFile.pfx -pvp MyCertFilePassword -rfp MyRequest.csr\r\n", f);
    fputs("Process a certificate request: -cmd process -rfp MyRequest.csr -ikf CaKeyFile -ikp CaPassword -pbf MyCertFile.der\r\n", f);
    fputs("Change a password: -cmd password -pvf MyCertFile.pfx -pvp MyCertFilePassword -password NewPassword\r\n", f);
    fputs("\r\nUsing ", f);
    fputs(OPENSSL_VERSION_TEXT, f);
    fputs("\r\n", f);

    if (!using_stdout)
    {
        fclose(f);
    }
}

/* ---------------------------------------------------------------------------
 * Entry point
 * ------------------------------------------------------------------------ */
int cg_args_process(cg_args *args, int argc, wchar_t *argv[])
{
    cg_map       arguments;
    unsigned int status = CG_GOOD;
    int          result;

    cg_map_init(&arguments);

    if (argc <= 1)
    {
        /* No arguments: the legacy tool read them from stdin. */
        cg_read_arguments_from_file(stdin, &arguments);
    }
    else
    {
        status = cg_read_arguments_from_command_line(argc, argv, &arguments);

        if (CG_IS_GOOD(status))
        {
            char *file_path = cg_is_arg_specified(&arguments, "-file", "-f");

            if (file_path != NULL)
            {
                wchar_t *wide;
                FILE    *file = NULL;

                /* Arguments from the command line are discarded in favour of
                 * the file's contents, as in the legacy implementation. */
                cg_map_free(&arguments);
                cg_map_init(&arguments);

                cg_str_set(&args->parameter_file_path, file_path);

                wide = cg_utf8_to_utf16(file_path);

                if (wide != NULL)
                {
                    file = _wfopen(wide, L"r, ccs=UTF-8");
                    cg_free(wide);
                }

                if (file == NULL)
                {
                    status = cg_fail(CG_BAD_INVALID_ARGUMENT,
                                     "Could not open input file: %s", file_path);
                }
                else
                {
                    cg_read_arguments_from_file(file, &arguments);
                    fclose(file);
                }

                cg_free(file_path);
            }
        }
    }

    if (CG_IS_BAD(status))
    {
        cg_args_set_error(args, status, cg_last_error_message());
        cg_map_free(&arguments);
        return 0;
    }

    /* Help: the usage text is written, then validation continues.  Because
     * "-?" is not one of the recognised arguments it remains in the map, so
     * cg_valid_args reports it as an unprocessed argument and the caller also
     * prints the syntax error.  That is what the legacy tool did. */
    if (cg_map_has(&arguments, "-?"))
    {
        cg_args_write_usage(args);
    }

    result = cg_valid_args(args, &arguments);

    cg_map_free(&arguments);
    return result;
}
