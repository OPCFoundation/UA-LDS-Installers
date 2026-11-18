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

/* Certificate operations, implemented against the OpenSSL 3.x EVP_PKEY
 * interfaces.  The legacy implementation used the OpenSSL 1.1.1 low-level
 * RSA_* / EC_KEY_* APIs, which are deprecated in 3.x.
 *
 * Certificate content - subject name construction, the extension set, validity
 * arithmetic, the store layout and file naming - is reproduced exactly from the
 * legacy tool, because anything else would break deployed trust chains.  That
 * includes choices we would not make today; they are marked LEGACY and
 * explained in CertGen/README.md. */

#ifndef CERTGEN_CERTOPS_H
#define CERTGEN_CERTOPS_H

#include "cmdline.h"

/* Initializes / tears down process-wide OpenSSL state. */
void cg_certops_startup(void);
void cg_certops_shutdown(void);

/* -command issue (also the default when no command is given). */
unsigned int cg_cmd_issue(cg_args *args);

/* -command revoke | unrevoke */
unsigned int cg_cmd_revoke(cg_args *args);

/* -command convert | install | password */
unsigned int cg_cmd_convert(cg_args *args);

/* -command replace */
unsigned int cg_cmd_replace(cg_args *args);

/* -command request */
unsigned int cg_cmd_create_request(cg_args *args);

/* -command process */
unsigned int cg_cmd_process_request(cg_args *args);

#endif /* CERTGEN_CERTOPS_H */
