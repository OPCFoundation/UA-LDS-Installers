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

#include "util.h"

#include <windows.h>
#include <ctype.h>
#include <direct.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>

/* ---------------------------------------------------------------------------
 * Memory
 * ------------------------------------------------------------------------ */
void *cg_alloc(size_t size)          { return malloc(size ? size : 1); }
void *cg_realloc(void *b, size_t s)  { return realloc(b, s ? s : 1); }
void  cg_free(void *block)           { free(block); }

/* ---------------------------------------------------------------------------
 * Error reporting
 * ------------------------------------------------------------------------ */
static char         g_error_message[1024] = { 0 };
static unsigned int g_error_code = CG_GOOD;

unsigned int cg_fail(unsigned int code, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(g_error_message, sizeof(g_error_message), format, args);
    va_end(args);

    g_error_code = code;
    return code;
}

unsigned int cg_fail_openssl(unsigned int code, const char *context)
{
    unsigned long err = ERR_get_error();

    if (err == 0)
    {
        return cg_fail(code, "%s failed.", context);
    }

    /* Drain the rest of the queue so a later unrelated call does not report a
     * stale error - OpenSSL's error queue is per-thread and cumulative. */
    {
        char reason[256];
        ERR_error_string_n(err, reason, sizeof(reason));
        while (ERR_get_error() != 0) { /* discard */ }
        return cg_fail(code, "%s failed: %s", context, reason);
    }
}

const char  *cg_last_error_message(void) { return g_error_message; }
unsigned int cg_last_error_code(void)    { return g_error_code; }

void cg_clear_error(void)
{
    g_error_message[0] = 0;
    g_error_code = CG_GOOD;
}

/* ---------------------------------------------------------------------------
 * Growable string
 * ------------------------------------------------------------------------ */
static int cg_str_reserve(cg_str *s, size_t needed)
{
    size_t capacity;
    char  *data;

    if (s->capacity > needed)
    {
        return 0;
    }

    capacity = s->capacity ? s->capacity : 32;
    while (capacity <= needed)
    {
        capacity *= 2;
    }

    data = (char *)cg_realloc(s->data, capacity);
    if (data == NULL)
    {
        return -1;
    }

    s->data = data;
    s->capacity = capacity;
    return 0;
}

void cg_str_init(cg_str *s)
{
    s->data = NULL;
    s->length = 0;
    s->capacity = 0;

    if (cg_str_reserve(s, 0) == 0)
    {
        s->data[0] = 0;
    }
}

void cg_str_free(cg_str *s)
{
    cg_free(s->data);
    s->data = NULL;
    s->length = 0;
    s->capacity = 0;
}

void cg_str_clear(cg_str *s)
{
    s->length = 0;
    if (s->data != NULL)
    {
        s->data[0] = 0;
    }
}

int cg_str_is_empty(const cg_str *s)
{
    return (s->data == NULL || s->length == 0);
}

int cg_str_set(cg_str *s, const char *text)
{
    cg_str_clear(s);
    return cg_str_append(s, text);
}

int cg_str_append(cg_str *s, const char *text)
{
    size_t extra;

    if (text == NULL)
    {
        return 0;
    }

    extra = strlen(text);
    if (extra == 0)
    {
        return 0;
    }

    if (cg_str_reserve(s, s->length + extra) != 0)
    {
        return -1;
    }

    memcpy(s->data + s->length, text, extra);
    s->length += extra;
    s->data[s->length] = 0;
    return 0;
}

int cg_str_append_char(cg_str *s, char c)
{
    if (cg_str_reserve(s, s->length + 1) != 0)
    {
        return -1;
    }

    s->data[s->length++] = c;
    s->data[s->length] = 0;
    return 0;
}

void cg_str_trim(cg_str *s)
{
    size_t first = 0;
    size_t last;

    if (cg_str_is_empty(s))
    {
        return;
    }

    while (first < s->length && isspace((unsigned char)s->data[first]))
    {
        first++;
    }

    if (first == s->length)
    {
        cg_str_clear(s);
        return;
    }

    last = s->length - 1;
    while (last > first && isspace((unsigned char)s->data[last]))
    {
        last--;
    }

    s->length = last - first + 1;
    memmove(s->data, s->data + first, s->length);
    s->data[s->length] = 0;
}

/* ---------------------------------------------------------------------------
 * Ordered key/value map
 * ------------------------------------------------------------------------ */
void cg_map_init(cg_map *m)
{
    m->items = NULL;
    m->count = 0;
    m->capacity = 0;
}

void cg_map_free(cg_map *m)
{
    size_t ii;

    for (ii = 0; ii < m->count; ii++)
    {
        cg_free(m->items[ii].key);
        cg_free(m->items[ii].value);
    }

    cg_free(m->items);
    cg_map_init(m);
}

static char *cg_strdup(const char *text)
{
    size_t size;
    char  *copy;

    if (text == NULL)
    {
        text = "";
    }

    size = strlen(text) + 1;
    copy = (char *)cg_alloc(size);

    if (copy != NULL)
    {
        memcpy(copy, text, size);
    }

    return copy;
}

static size_t cg_map_find(const cg_map *m, const char *key)
{
    size_t ii;

    for (ii = 0; ii < m->count; ii++)
    {
        if (strcmp(m->items[ii].key, key) == 0)
        {
            return ii;
        }
    }

    return (size_t)-1;
}

int cg_map_set(cg_map *m, const char *key, const char *value)
{
    size_t index = cg_map_find(m, key);
    char  *copy;

    if (index != (size_t)-1)
    {
        copy = cg_strdup(value);
        if (copy == NULL)
        {
            return -1;
        }

        cg_free(m->items[index].value);
        m->items[index].value = copy;
        return 0;
    }

    if (m->count == m->capacity)
    {
        size_t capacity = m->capacity ? m->capacity * 2 : 8;
        cg_kv *items = (cg_kv *)cg_realloc(m->items, capacity * sizeof(cg_kv));

        if (items == NULL)
        {
            return -1;
        }

        m->items = items;
        m->capacity = capacity;
    }

    m->items[m->count].key = cg_strdup(key);
    m->items[m->count].value = cg_strdup(value);

    if (m->items[m->count].key == NULL || m->items[m->count].value == NULL)
    {
        cg_free(m->items[m->count].key);
        cg_free(m->items[m->count].value);
        return -1;
    }

    m->count++;
    return 0;
}

const char *cg_map_get(const cg_map *m, const char *key)
{
    size_t index = cg_map_find(m, key);
    return (index == (size_t)-1) ? NULL : m->items[index].value;
}

int cg_map_has(const cg_map *m, const char *key)
{
    return cg_map_find(m, key) != (size_t)-1;
}

void cg_map_erase(cg_map *m, const char *key)
{
    size_t index = cg_map_find(m, key);

    if (index == (size_t)-1)
    {
        return;
    }

    cg_free(m->items[index].key);
    cg_free(m->items[index].value);

    if (index + 1 < m->count)
    {
        memmove(&m->items[index], &m->items[index + 1],
                (m->count - index - 1) * sizeof(cg_kv));
    }

    m->count--;
}

size_t cg_map_count(const cg_map *m)
{
    return m->count;
}

static int cg_kv_compare(const void *left, const void *right)
{
    return strcmp(((const cg_kv *)left)->key, ((const cg_kv *)right)->key);
}

void cg_map_sort(cg_map *m)
{
    if (m->count > 1)
    {
        qsort(m->items, m->count, sizeof(cg_kv), cg_kv_compare);
    }
}

/* ---------------------------------------------------------------------------
 * String list
 * ------------------------------------------------------------------------ */
void cg_list_init(cg_list *l)
{
    l->items = NULL;
    l->count = 0;
    l->capacity = 0;
}

void cg_list_free(cg_list *l)
{
    size_t ii;

    for (ii = 0; ii < l->count; ii++)
    {
        cg_free(l->items[ii]);
    }

    cg_free(l->items);
    cg_list_init(l);
}

int cg_list_add(cg_list *l, const char *value)
{
    char *copy;

    if (l->count == l->capacity)
    {
        size_t capacity = l->capacity ? l->capacity * 2 : 8;
        char **items = (char **)cg_realloc(l->items, capacity * sizeof(char *));

        if (items == NULL)
        {
            return -1;
        }

        l->items = items;
        l->capacity = capacity;
    }

    copy = cg_strdup(value);
    if (copy == NULL)
    {
        return -1;
    }

    l->items[l->count++] = copy;
    return 0;
}

int cg_list_add_split(cg_list *l, const char *text, char sep)
{
    const char *start = text;
    const char *found;

    if (text == NULL)
    {
        return 0;
    }

    /* Mirrors the legacy loop, which pushed every field including empties and
     * always pushed a final field even when the input ended with a separator. */
    while ((found = strchr(start, sep)) != NULL)
    {
        size_t length = (size_t)(found - start);
        char  *field = (char *)cg_alloc(length + 1);

        if (field == NULL)
        {
            return -1;
        }

        memcpy(field, start, length);
        field[length] = 0;

        if (cg_list_add(l, field) != 0)
        {
            cg_free(field);
            return -1;
        }

        cg_free(field);
        start = found + 1;
    }

    return cg_list_add(l, start);
}

/* ---------------------------------------------------------------------------
 * Encoding
 * ------------------------------------------------------------------------ */
char *cg_utf16_to_utf8(const wchar_t *source)
{
    int   needed;
    char *result;

    if (source == NULL)
    {
        return cg_strdup("");
    }

    needed = WideCharToMultiByte(CP_UTF8, 0, source, -1, NULL, 0, NULL, NULL);
    if (needed <= 0)
    {
        return NULL;
    }

    result = (char *)cg_alloc((size_t)needed);
    if (result == NULL)
    {
        return NULL;
    }

    if (WideCharToMultiByte(CP_UTF8, 0, source, -1, result, needed, NULL, NULL) <= 0)
    {
        cg_free(result);
        return NULL;
    }

    return result;
}

wchar_t *cg_utf8_to_utf16(const char *source)
{
    int      needed;
    wchar_t *result;

    if (source == NULL)
    {
        source = "";
    }

    needed = MultiByteToWideChar(CP_UTF8, 0, source, -1, NULL, 0);
    if (needed <= 0)
    {
        return NULL;
    }

    result = (wchar_t *)cg_alloc((size_t)needed * sizeof(wchar_t));
    if (result == NULL)
    {
        return NULL;
    }

    if (MultiByteToWideChar(CP_UTF8, 0, source, -1, result, needed) <= 0)
    {
        cg_free(result);
        return NULL;
    }

    return result;
}

/* ---------------------------------------------------------------------------
 * Files
 * ------------------------------------------------------------------------ */
int cg_file_exists(const char *path)
{
    wchar_t *wide = cg_utf8_to_utf16(path);
    DWORD    attributes;

    if (wide == NULL)
    {
        return 0;
    }

    attributes = GetFileAttributesW(wide);
    cg_free(wide);

    return (attributes != INVALID_FILE_ATTRIBUTES &&
            (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0);
}

unsigned int cg_read_file(const char *path, unsigned char **data, size_t *size)
{
    wchar_t      *wide;
    FILE         *file = NULL;
    long          length;
    unsigned char *buffer;

    *data = NULL;
    *size = 0;

    wide = cg_utf8_to_utf16(path);
    if (wide == NULL)
    {
        return cg_fail(CG_BAD_OUT_OF_MEMORY, "Memory allocation failed.");
    }

    file = _wfopen(wide, L"rb");
    cg_free(wide);

    if (file == NULL)
    {
        return cg_fail(CG_BAD_NOT_FOUND, "Could not open file: %s", path);
    }

    if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0)
    {
        fclose(file);
        return cg_fail(CG_BAD_UNEXPECTED_ERROR, "Could not determine size of file: %s", path);
    }

    rewind(file);

    buffer = (unsigned char *)cg_alloc((size_t)length + 1);
    if (buffer == NULL)
    {
        fclose(file);
        return cg_fail(CG_BAD_OUT_OF_MEMORY, "Memory allocation failed.");
    }

    if (length > 0 && fread(buffer, 1, (size_t)length, file) != (size_t)length)
    {
        cg_free(buffer);
        fclose(file);
        return cg_fail(CG_BAD_UNEXPECTED_ERROR, "Could not read file: %s", path);
    }

    fclose(file);

    buffer[length] = 0;   /* convenience for callers treating content as text */
    *data = buffer;
    *size = (size_t)length;
    return CG_GOOD;
}

unsigned int cg_write_file(const char *path, const unsigned char *data, size_t size)
{
    wchar_t *wide = cg_utf8_to_utf16(path);
    FILE    *file;

    if (wide == NULL)
    {
        return cg_fail(CG_BAD_OUT_OF_MEMORY, "Memory allocation failed.");
    }

    file = _wfopen(wide, L"wb");
    cg_free(wide);

    if (file == NULL)
    {
        return cg_fail(CG_BAD_USER_ACCESS_DENIED, "Could not create file: %s", path);
    }

    if (size > 0 && fwrite(data, 1, size, file) != size)
    {
        fclose(file);
        return cg_fail(CG_BAD_UNEXPECTED_ERROR, "Could not write file: %s", path);
    }

    fclose(file);
    return CG_GOOD;
}

unsigned int cg_make_directory(const char *path)
{
    wchar_t *wide = cg_utf8_to_utf16(path);
    int      result;

    if (wide == NULL)
    {
        return cg_fail(CG_BAD_OUT_OF_MEMORY, "Memory allocation failed.");
    }

    result = _wmkdir(wide);
    cg_free(wide);

    if (result != 0 && errno != EEXIST)
    {
        return cg_fail(CG_BAD_USER_ACCESS_DENIED, "Could not create directory: %s", path);
    }

    return CG_GOOD;
}

char *cg_path_join(const char *left, const char *right)
{
    size_t left_length;
    size_t right_length;
    int    needs_separator;
    char  *result;

    if (left == NULL || *left == 0)
    {
        return cg_strdup(right);
    }

    if (right == NULL || *right == 0)
    {
        return cg_strdup(left);
    }

    left_length = strlen(left);
    right_length = strlen(right);
    needs_separator = (left[left_length - 1] != '\\' && left[left_length - 1] != '/');

    result = (char *)cg_alloc(left_length + right_length + 2);
    if (result == NULL)
    {
        return NULL;
    }

    memcpy(result, left, left_length);
    if (needs_separator)
    {
        result[left_length++] = '\\';
    }
    memcpy(result + left_length, right, right_length + 1);

    return result;
}

/* ---------------------------------------------------------------------------
 * Hex
 * ------------------------------------------------------------------------ */
static const char g_hex_digits[] = "0123456789ABCDEF";

char *cg_to_hex(const unsigned char *data, size_t size)
{
    char  *result = (char *)cg_alloc(size * 2 + 1);
    size_t ii;

    if (result == NULL)
    {
        return NULL;
    }

    for (ii = 0; ii < size; ii++)
    {
        result[ii * 2]     = g_hex_digits[(data[ii] >> 4) & 0x0F];
        result[ii * 2 + 1] = g_hex_digits[data[ii] & 0x0F];
    }

    result[size * 2] = 0;
    return result;
}

static int cg_hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int cg_is_hex_string(const char *text)
{
    size_t length;
    size_t ii;

    if (text == NULL)
    {
        return 0;
    }

    length = strlen(text);

    /* An odd number of digits cannot be a byte string, and a 2-character path
     * like "C:" must not be mistaken for one - require something substantial. */
    if (length < 8 || (length % 2) != 0)
    {
        return 0;
    }

    for (ii = 0; ii < length; ii++)
    {
        if (cg_hex_value(text[ii]) < 0)
        {
            return 0;
        }
    }

    return 1;
}

unsigned char *cg_from_hex(const char *hex, size_t *size)
{
    size_t         length;
    size_t         ii;
    unsigned char *result;

    *size = 0;

    if (hex == NULL)
    {
        return NULL;
    }

    length = strlen(hex);
    if ((length % 2) != 0)
    {
        return NULL;
    }

    result = (unsigned char *)cg_alloc(length / 2 + 1);
    if (result == NULL)
    {
        return NULL;
    }

    for (ii = 0; ii < length; ii += 2)
    {
        int high = cg_hex_value(hex[ii]);
        int low  = cg_hex_value(hex[ii + 1]);

        if (high < 0 || low < 0)
        {
            cg_free(result);
            return NULL;
        }

        result[ii / 2] = (unsigned char)((high << 4) | low);
    }

    *size = length / 2;
    return result;
}
