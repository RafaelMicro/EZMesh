
#include <sys/stat.h>

#include "utility/utils.h"
#include "utility/logs.h"

int recursive_mkdir(const char *dir, size_t len, const mode_t mode)
{
    char *tmp = NULL;
    char *p = NULL;
    struct stat sb;
    int ret;

    tmp = (char *)calloc_port(len + 1);
    ERROR_ON(tmp == NULL);

    /* copy path */
    ret = snprintf(tmp, len + 1, "%s", dir);
    ERROR_ON(ret < 0 || (size_t)ret >= (len + 1));

    /* remove trailing slash */
    if (tmp[len - 1] == '/')
    {
        tmp[len - 1] = '\0';
    }

    /* check if path exists and is a directory */
    if (stat(tmp, &sb) == 0)
    {
        if (S_ISDIR(sb.st_mode))
        {
            goto return_ok;
        }
    }

    /* recursive mkdir */
    for (p = tmp + 1; *p; p++)
    {
        if (*p == '/')
        {
            *p = 0;
            /* test path */
            if (stat(tmp, &sb) != 0)
            {
                /* path does not exist - create directory */
                if (mkdir(tmp, mode) < 0)
                {
                    goto return_err;
                }
            } else if (!S_ISDIR(sb.st_mode))
            {
                /* not a directory */
                goto return_err;
            }
            *p = '/';
        }
    }

    /* test path */
    if (stat(tmp, &sb) != 0)
    {
        /* path does not exist - create directory */
        if (mkdir(tmp, mode) < 0)
        {
            goto return_err;
        }
    } else if (!S_ISDIR(sb.st_mode))
    {
        /* not a directory */
        goto return_err;
    }

    /* Fall through to return_ok */

 return_ok:
    free(tmp);
    return 0;

 return_err:
    free(tmp);
    return -1;
}
