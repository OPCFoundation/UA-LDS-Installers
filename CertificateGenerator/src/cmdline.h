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

/* Command line handling.
 *
 * This file is the compatibility contract with the legacy
 * Opc.Ua.CertificateGenerator: same flags, same long/short forms, same
 * defaults, same usage text, same output parameter names and ordering.
 * Deviations are listed in CertGen/README.md and marked DEVIATION below.
 *
 * Do not "tidy" the behaviour here.  Several oddities (the trailing-flag drop,
 * the help-plus-error output) are reproduced deliberately because scripts may
 * depend on them. */

#ifndef CERTGEN_CMDLINE_H
#define CERTGEN_CMDLINE_H

#include "util.h"

/* Key types accepted by -keyType.  Values are internal only; the legacy tool
 * never exposed them through the command line or its output. */
typedef enum {
    CG_KEY_RSA = 0,
    CG_KEY_EC_NIST_P256,
    CG_KEY_EC_NIST_P384,
    CG_KEY_EC_BRAINPOOL_P256R1,
    CG_KEY_EC_BRAINPOOL_P384R1,
    CG_KEY_EC_CURVE25519,
    CG_KEY_EC_CURVE448
} cg_key_type;

typedef struct {
    /* -file / -f.  When set, output goes here instead of stdout - matching the
     * legacy behaviour, where the parameter file is both input and output. */
    cg_str  parameter_file_path;

    /* Output parameters, written by cg_args_write_output in sorted key order. */
    cg_map  output;

    cg_str  command;
    cg_str  store_path;
    cg_str  application_name;
    cg_str  application_uri;
    cg_str  subject_name;
    cg_str  organization;
    cg_list domain_names;
    cg_str  password;
    cg_str  issuer_certificate;
    cg_str  issuer_key_file_path;
    cg_str  issuer_key_password;
    cg_str  public_key_file_path;
    cg_str  private_key_file_path;
    cg_str  private_key_password;
    cg_str  request_file_path;

    cg_key_type    key_type;
    unsigned short key_size;
    long long      start_time;        /* raw FILETIME (100ns ticks from 1601) */
    unsigned short hash_size;
    short          lifetime_in_months;

    /* Set when -hashSize/-hs was given on the command line.  Needed because an
     * ECC key defaults to the hash its OPC UA SecurityPolicy pairs with, not to
     * the RSA default of 256 - so "256 because the user asked" and "256 because
     * nobody said" have to be distinguishable. */
    int hash_size_specified;

    int is_ca;
    int input_is_pem;
    int output_is_pem;
    int reuse_key;
} cg_args;

void cg_args_init(cg_args *args);
void cg_args_free(cg_args *args);

/* Parses the command line, stdin, or a parameter file, exactly as the legacy
 * tool did.  Returns 1 when the arguments are usable, 0 when the caller should
 * write the output parameters and exit (help requested, or a parse error). */
int cg_args_process(cg_args *args, int argc, wchar_t *argv[]);

/* Writes the usage text. */
void cg_args_write_usage(cg_args *args);

/* Writes the output parameters, sorted by key. */
void cg_args_write_output(cg_args *args);

/* Convenience for recording a failure into the output parameters. */
void cg_args_set_error(cg_args *args, unsigned int code, const char *message);

#endif /* CERTGEN_CMDLINE_H */
