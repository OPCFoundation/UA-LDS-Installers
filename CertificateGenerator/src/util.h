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

/* Small C replacements for the std::string / std::map / OpcUa_* helpers the
 * legacy C++ implementation relied on.  Nothing here is general purpose; it
 * exists to keep cmdline.c and certops.c readable. */

#ifndef CERTGEN_UTIL_H
#define CERTGEN_UTIL_H

#include <stddef.h>
#include <stdio.h>
#include <wchar.h>

/* ---------------------------------------------------------------------------
 * Status codes
 *
 * These are the OPC UA status codes the legacy tool reported through the
 * `-code` output parameter.  The numeric values are part of the output
 * contract, so they are reproduced verbatim rather than re-derived.
 * ------------------------------------------------------------------------ */
#define CG_GOOD                       0x00000000u
#define CG_BAD                        0x80000000u
#define CG_BAD_UNEXPECTED_ERROR       0x80010000u
#define CG_BAD_OUT_OF_MEMORY          0x80030000u
#define CG_BAD_COMMUNICATION_ERROR    0x80050000u
#define CG_BAD_ENCODING_ERROR         0x80060000u
#define CG_BAD_DECODING_ERROR         0x80070000u
#define CG_BAD_CERTIFICATE_INVALID    0x80120000u
#define CG_BAD_USER_ACCESS_DENIED     0x801F0000u
#define CG_BAD_NOT_SUPPORTED          0x803D0000u
#define CG_BAD_NOT_FOUND              0x803E0000u
#define CG_BAD_INVALID_ARGUMENT       0x80AB0000u
#define CG_BAD_SYNTAX_ERROR           0x80B60000u

#define CG_IS_BAD(x)  (((x) & 0x80000000u) != 0)
#define CG_IS_GOOD(x) (((x) & 0x80000000u) == 0)

/* ---------------------------------------------------------------------------
 * Error reporting
 *
 * The legacy code used a StatusCodeException thrown from deep inside the
 * certificate routines and caught in wmain.  C has no exceptions, so failing
 * functions return a status code and set a thread-wide "last error" that the
 * top level turns into the `-error` output parameter.  This keeps call sites
 * as terse as the ThrowIfBad macro did without losing the message.
 * ------------------------------------------------------------------------ */

/* Records the failure and returns code, so callers can `return cg_fail(...)`. */
unsigned int cg_fail(unsigned int code, const char *format, ...);

/* Last recorded failure. Message is "" when nothing has failed. */
const char  *cg_last_error_message(void);
unsigned int cg_last_error_code(void);
void         cg_clear_error(void);

/* Formats the most recent OpenSSL error as a message and records it. */
unsigned int cg_fail_openssl(unsigned int code, const char *context);

/* ---------------------------------------------------------------------------
 * Growable string
 * ------------------------------------------------------------------------ */
typedef struct {
    char  *data;      /* always NUL terminated, never NULL after cg_str_init */
    size_t length;
    size_t capacity;
} cg_str;

void  cg_str_init(cg_str *s);
void  cg_str_free(cg_str *s);
int   cg_str_set(cg_str *s, const char *text);
int   cg_str_append(cg_str *s, const char *text);
int   cg_str_append_char(cg_str *s, char c);
void  cg_str_clear(cg_str *s);
int   cg_str_is_empty(const cg_str *s);

/* Trims leading and trailing whitespace in place. */
void  cg_str_trim(cg_str *s);

/* ---------------------------------------------------------------------------
 * Ordered key/value map
 *
 * Replaces std::map<std::string,std::string>.  Iteration is sorted by key,
 * because the legacy output order was std::map's and scripts may parse it.
 * ------------------------------------------------------------------------ */
typedef struct {
    char *key;
    char *value;
} cg_kv;

typedef struct {
    cg_kv *items;
    size_t count;
    size_t capacity;
} cg_map;

void        cg_map_init(cg_map *m);
void        cg_map_free(cg_map *m);
/* Inserts or replaces. Returns 0 on success, -1 on allocation failure. */
int         cg_map_set(cg_map *m, const char *key, const char *value);
const char *cg_map_get(const cg_map *m, const char *key);
int         cg_map_has(const cg_map *m, const char *key);
void        cg_map_erase(cg_map *m, const char *key);
size_t      cg_map_count(const cg_map *m);
/* Sorts by key ascending (byte comparison, matching std::string operator<). */
void        cg_map_sort(cg_map *m);

/* ---------------------------------------------------------------------------
 * String list (replaces std::vector<std::string>)
 * ------------------------------------------------------------------------ */
typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} cg_list;

void   cg_list_init(cg_list *l);
void   cg_list_free(cg_list *l);
int    cg_list_add(cg_list *l, const char *value);
/* Splits text on `sep` and appends each field, including empty ones. */
int    cg_list_add_split(cg_list *l, const char *text, char sep);

/* ---------------------------------------------------------------------------
 * Encoding
 *
 * OPC UA strings are UTF-8; the Windows command line is UTF-16.  These mirror
 * OpcUa_UnicodeToString / OpcUa_StringToUnicode.  Both return heap blocks the
 * caller frees with cg_free.
 * ------------------------------------------------------------------------ */
char    *cg_utf16_to_utf8(const wchar_t *source);
wchar_t *cg_utf8_to_utf16(const char *source);

void *cg_alloc(size_t size);
void *cg_realloc(void *block, size_t size);
void  cg_free(void *block);

/* ---------------------------------------------------------------------------
 * Files and hex
 * ------------------------------------------------------------------------ */

/* Reads a whole file. Caller frees *data with cg_free. */
unsigned int cg_read_file(const char *path, unsigned char **data, size_t *size);
unsigned int cg_write_file(const char *path, const unsigned char *data, size_t size);
int          cg_file_exists(const char *path);

/* Creates a directory, succeeding if it already exists. */
unsigned int cg_make_directory(const char *path);

/* Joins two path fragments with a backslash. Caller frees the result. */
char *cg_path_join(const char *left, const char *right);

/* Uppercase hex, no separators - the format the legacy tool used for
 * thumbprints and for inline input/output. */
char          *cg_to_hex(const unsigned char *data, size_t size);
unsigned char *cg_from_hex(const char *hex, size_t *size);
/* True when text looks like an even-length run of hex digits, which is how the
 * legacy tool distinguished an inline blob from a file path. */
int            cg_is_hex_string(const char *text);

#endif /* CERTGEN_UTIL_H */
