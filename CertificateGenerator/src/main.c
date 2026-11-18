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
#include "cmdline.h"
#include "util.h"

#include <string.h>

/* Mirrors the legacy Main.cpp, including its exit code behaviour: the tool
 * always exits 0 and reports success or failure through the output parameters.
 * Callers parse `-error`; they do not check %ERRORLEVEL%. */
int wmain(int argc, wchar_t *argv[])
{
    cg_args      args;
    unsigned int status = CG_GOOD;
    const char  *command;

    cg_args_init(&args);
    cg_certops_startup();

    if (!cg_args_process(&args, argc, argv))
    {
        cg_args_write_output(&args);
        goto done;
    }

    /* The store directory is created up front, exactly as the legacy tool did.
     * "LocalMachine" and "CurrentUser" name Windows certificate stores rather
     * than directories, so a failure to create them is not an error. */
    if (!cg_str_is_empty(&args.store_path))
    {
        if (CG_IS_BAD(cg_make_directory(args.store_path.data)))
        {
            if (_strnicmp(args.store_path.data, "LocalMachine", strlen("LocalMachine")) != 0 &&
                _strnicmp(args.store_path.data, "CurrentUser", strlen("CurrentUser")) != 0)
            {
                cg_map_set(&args.output, "-error", "Could not access certificate store.");
                cg_map_set(&args.output, "-storePath", args.store_path.data);
                cg_args_write_output(&args);
                goto done;
            }
        }
    }

    command = args.command.data;

    if (cg_str_is_empty(&args.command) || strcmp(command, "issue") == 0)
    {
        status = cg_cmd_issue(&args);
    }
    else if (strcmp(command, "revoke") == 0 || strcmp(command, "unrevoke") == 0)
    {
        status = cg_cmd_revoke(&args);
    }
    else if (strcmp(command, "convert") == 0 || strcmp(command, "install") == 0)
    {
        status = cg_cmd_convert(&args);
    }
    else if (strcmp(command, "password") == 0)
    {
        /* The legacy tool routed `password` to Convert, not to its unused
         * ChangePassword method.  Preserved. */
        status = cg_cmd_convert(&args);
    }
    else if (strcmp(command, "replace") == 0)
    {
        status = cg_cmd_replace(&args);
    }
    else if (strcmp(command, "request") == 0)
    {
        status = cg_cmd_create_request(&args);
    }
    else if (strcmp(command, "process") == 0)
    {
        status = cg_cmd_process_request(&args);
    }
    else
    {
        cg_map_set(&args.output, "-error", "Unsupported command.");
        cg_map_set(&args.output, "-command", command);
        cg_args_write_output(&args);
        goto done;
    }

    if (CG_IS_BAD(status))
    {
        cg_args_set_error(&args, status, cg_last_error_message());
    }

    cg_args_write_output(&args);

done:
    cg_certops_shutdown();
    cg_args_free(&args);
    return 0;
}
