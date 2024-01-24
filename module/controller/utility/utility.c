
#include <sys/stat.h>

#include "log.h"
#include "utility.h"

#define SYS_ERROR(cond, tmp)  {if(cond){ free(tmp); return 0; }}

int recursive_mkdir(const char *dir, size_t len, const mode_t mode) {
  char *tmp = NULL;
  char *p = NULL;
  struct stat sb;
  int ret;

  tmp = (char *)calloc(1, len + 1);
  CHECK_ERROR(tmp == NULL);
  ret = snprintf(tmp, len + 1, "%s", dir);
  CHECK_ERROR(ret < 0 || (size_t)ret >= (len + 1));

  /* remove trailing slash */
  if (tmp[len - 1] == '/') tmp[len - 1] = '\0'; 

  /* check if path exists and is a directory */
  if (stat(tmp, &sb) == 0) {SYS_ERROR(S_ISDIR(sb.st_mode), tmp); }

  /* recursive mkdir */
  for (p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = 0;
      /* test path */
      if (stat(tmp, &sb) != 0) {SYS_ERROR(mkdir(tmp, mode) < 0, tmp);} /* path does not exist - create directory */
      else {SYS_ERROR(!S_ISDIR(sb.st_mode), tmp);} 
      *p = '/';
    }
  }

  /* test path */
  if (stat(tmp, &sb) != 0)  {SYS_ERROR(mkdir(tmp, mode) < 0, tmp);} /* path does not exist - create directory */
  else {SYS_ERROR(!S_ISDIR(sb.st_mode), tmp);}
  return 0;
}