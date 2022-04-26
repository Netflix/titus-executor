#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

void mkdir_p(const char *dir)
{
	char tmp[PATH_MAX];
	char *p = NULL;
	size_t len;
	struct stat st = { 0 };
	snprintf(tmp, sizeof(tmp), "%s", dir);
	len = strlen(tmp);
	if (tmp[len - 1] == '/')
		tmp[len - 1] = 0;
	for (p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = 0;
			if (stat(tmp, &st) == -1) {
				if (mkdir(tmp, 0777) == -1) {
					printf("mkdir error on %s: %s\n", tmp,
					       strerror(errno));
				}
			}
			*p = '/';
		}
	}
	if (stat(tmp, &st) == -1) {
		if (mkdir(tmp, 0777) == -1) {
			printf("mkdir error on %s: %s\n", tmp, strerror(errno));
		}
	}
}
