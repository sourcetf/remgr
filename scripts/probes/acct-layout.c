/* Accounting-record layout and the last few records, as the C library sees it.
 * This is the reference the Rust mirror in remgr/src/acct.rs is written against:
 * the record size plus the offsets of the fields the log line needs. */
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/acct.h>
#include <sys/types.h>

int main(int argc, char **argv) {
	const char *path = argc > 1 ? argv[1] : "/var/account/acct";
	int fd, i, n = 6;
	off_t size;
	struct acct a[6];
	char comm[sizeof a->ac_comm + 1];

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("sizeof(struct acct)=%zu\n", sizeof(struct acct));
	printf("offsets: comm=%zu utime=%zu btime=%zu uid=%zu gid=%zu mem=%zu tty=%zu pid=%zu flag=%zu\n",
	    offsetof(struct acct, ac_comm), offsetof(struct acct, ac_utime),
	    offsetof(struct acct, ac_btime), offsetof(struct acct, ac_uid),
	    offsetof(struct acct, ac_gid), offsetof(struct acct, ac_mem),
	    offsetof(struct acct, ac_tty), offsetof(struct acct, ac_pid),
	    offsetof(struct acct, ac_flag));

	fd = open(path, O_RDONLY);
	if (fd < 0) { perror("open"); return 1; }
	size = lseek(fd, 0, SEEK_END);
	printf("file size=%lld records=%lld remainder=%lld\n",
	    (long long)size, (long long)(size / (off_t)sizeof(struct acct)),
	    (long long)(size % (off_t)sizeof(struct acct)));
	if (size < (off_t)sizeof a) { printf("file too small\n"); return 1; }
	if (lseek(fd, size - (off_t)sizeof a, SEEK_SET) < 0) { perror("lseek"); return 1; }
	if (read(fd, a, sizeof a) != (ssize_t)sizeof a) { printf("short read\n"); return 1; }

	for (i = 0; i < n; i++) {
		memcpy(comm, a[i].ac_comm, sizeof a->ac_comm);
		comm[sizeof a->ac_comm] = 0;
		printf("  [%d] comm=%-16s uid=%-4u pid=%-6d btime=%lld flag=0x%08x\n",
		    i, comm, a[i].ac_uid, (int)a[i].ac_pid, (long long)a[i].ac_btime,
		    a[i].ac_flag);
	}
	close(fd);
	return 0;
}
