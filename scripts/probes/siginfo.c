/* Ground truth for OpenBSD's siginfo_t: what the kernel fills in for a kill(2),
 * and where the fields live. The libc crate's si_pid() accessor reads at offset
 * 128 (3 ints + SI_PAD[29]); that returned 0 for a signal from a real process. */
#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

static void handler(int sig, siginfo_t *si, void *ctx) {
	printf("child: sig=%d si_code=%d si_pid=%d si_uid=%d\n",
	    sig, si->si_code, (int)si->si_pid, (int)si->si_uid);
	printf("offsets: size=%zu signo=%zu code=%zu errno=%zu pid=%zu uid=%zu\n",
	    sizeof(siginfo_t), offsetof(siginfo_t, si_signo), offsetof(siginfo_t, si_code),
	    offsetof(siginfo_t, si_errno), offsetof(siginfo_t, si_pid), offsetof(siginfo_t, si_uid));
	_exit(0);
}

int main(void) {
	struct sigaction sa;
	pid_t child;
	setvbuf(stdout, NULL, _IONBF, 0);
	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGUSR1, &sa, NULL);

	child = fork();
	if (child == 0) { pause(); _exit(0); }
	usleep(200000);
	printf("parent: pid=%d sending SIGUSR1 to child=%d\n", (int)getpid(), (int)child);
	kill(child, SIGUSR1);
	waitpid(child, NULL, 0);
	return 0;
}
