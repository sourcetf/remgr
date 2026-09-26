/* Which access sets AUNVEIL in the accounting flags? The daemon's own record
 * carries "U" while dmesg shows no violations, so this pins it down. */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

int main(void) {
	setvbuf(stdout, NULL, _IONBF, 0);

	/* 1: access something outside a locked unveil set (the interesting case) */
	if (unveil("/etc/hosts", "r") == -1) { perror("unveil"); return 1; }
	unveil(NULL, NULL);
	int fd = open("/etc/resolv.conf", O_RDONLY);
	printf("probe: open of an un-unveiled path -> fd=%d errno-ish=%d\n", fd, fd < 0 ? 1 : 0);
	if (fd >= 0) close(fd);
	return 0;
}
