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

/* Product identity and version - the single source of truth for both the
 * Win32 VERSIONINFO resource (Resource.rc) and any code that needs it.
 *
 * The legacy tool split this across three files that disagreed with each
 * other: Version.h declared 1.01.333.0, BuildVersion.h declared build 123, and
 * Resource.rc hard-coded 1,1,342,10 - which, being the one the resource
 * compiler actually read, is what shipped.  One header, used by both, removes
 * the possibility. */

#ifndef CERTGEN_VERSION_H
#define CERTGEN_VERSION_H

/* MAJOR bumped 1 -> 2 for the OpenSSL 3.x rewrite.  The remaining components
 * carry the legacy lineage forward from the shipped 1.1.342.10. */
#define CERTGEN_VERSION_MAJOR     2
#define CERTGEN_VERSION_MINOR     1
#define CERTGEN_VERSION_BUILD     342
#define CERTGEN_VERSION_REVISION  10

#define CERTGEN_STRINGIFY_(x) #x
#define CERTGEN_STRINGIFY(x)  CERTGEN_STRINGIFY_(x)

#define CERTGEN_VERSION \
    CERTGEN_VERSION_MAJOR, CERTGEN_VERSION_MINOR, \
    CERTGEN_VERSION_BUILD, CERTGEN_VERSION_REVISION

#define CERTGEN_VERSION_STR                        \
    CERTGEN_STRINGIFY(CERTGEN_VERSION_MAJOR) "."   \
    CERTGEN_STRINGIFY(CERTGEN_VERSION_MINOR) "."   \
    CERTGEN_STRINGIFY(CERTGEN_VERSION_BUILD) "."   \
    CERTGEN_STRINGIFY(CERTGEN_VERSION_REVISION)

/* Identity strings, carried over from the legacy VERSIONINFO block. */
#define CERTGEN_COMPANY_NAME      "OPC Foundation"
#define CERTGEN_PRODUCT_NAME      "UA Certificate Generator"
#define CERTGEN_FILE_DESCRIPTION  "A tool to generate UA application instance certificates."
#define CERTGEN_INTERNAL_NAME     "Opc.Ua.CertificateGenerator.exe"
#define CERTGEN_ORIGINAL_FILENAME "Opc.Ua.CertificateGenerator.exe"
#define CERTGEN_LEGAL_COPYRIGHT   "Copyright (c) 2004-2026 OPC Foundation, Inc"
#define CERTGEN_LEGAL_TRADEMARKS \
    "This product includes software developed by the OpenSSL Project " \
    "for use in the OpenSSL Toolkit (http://www.openssl.org/)"

#endif /* CERTGEN_VERSION_H */
