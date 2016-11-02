#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/wait.h>

#define bail(fmt, ...)							\
	do {								\
		fprintf(stderr, fmt ": %m\n", ##__VA_ARGS__); \
		exit(__COUNTER__ + 1);					\
	} while(0)

typedef struct process_t {
	char **args;
	sigset_t set;
	pid_t pid;
} process_t;

typedef struct reaper_t {
	int fd;
	sigset_t parent_set;
	sigset_t child_set;
	process_t *child;
} reaper_t;

// reaper_new initializes the reaper with the provided process.
// it also sets up the signal handlers and child handlers for restore
// when the child is execed
int reaper_new(reaper_t * reaper, process_t * process)
{
	int i;
	int sync_signals[] =
	    { SIGSYS, SIGFPE, SIGBUS, SIGABRT, SIGTRAP, SIGILL, SIGSEGV, };
	if (sigfillset(&reaper->parent_set) != 0) {
		return -1;
	}
	for (i = 0; i < (sizeof(sync_signals) / sizeof(int)); i++) {
		if (sigdelset(&reaper->parent_set, sync_signals[i]) != 0) {
			return -1;
		}
	}
	if (sigprocmask(SIG_SETMASK, &reaper->parent_set, &reaper->child_set) !=
	    0) {
		return -1;
	}
	reaper->fd = signalfd(-1, &reaper->parent_set, SFD_CLOEXEC);
	if (reaper->fd == -1) {
		return -1;
	}
	reaper->child = process;
	process->set = reaper->child_set;
	return 0;
}

// reaper_exit closes the reaper's signalfd and exits with the
// child's exit status
void reaper_exit(reaper_t * reaper, int status)
{
	close(reaper->fd);
	if (WIFSIGNALED(status)) {
		exit(WTERMSIG(status) + 128);
	}
	exit(WEXITSTATUS(status));
}

// reaper_reap reaps any dead processes.  If the process that is reaped
// is the child process that we spawned get its exit status and exit this program
int reaper_reap(reaper_t * reaper)
{
	int status = 0, child_exited = 0, child_status = 0;
	for (;;) {
		pid_t pid = waitpid(-1, &status, WNOHANG);
		switch (pid) {
		case 0:
			// exiting here means that our direct child has exited but they are other processes
			// still running in the conatiner.  we can just exit here as we are pid1 and everything
			// else left will be SIGKILL'd by the kernel
			if (child_exited) {
				reaper_exit(reaper, child_status);
			}
			return 0;
		case -1:
			if (errno != ECHILD) {
				return -1;
			}
			if (child_exited) {
				reaper_exit(reaper, child_status);
			}
			return 0;
		default:
			// the process has already been reaped but check if it was our child process
			// and save the child processes state until our existing loop has completed
			// and all child processses have been reaped before exiting
			if (reaper->child->pid == pid) {
				child_exited = 1;
				child_status = status;
			}
		}
	}
	return 0;
}

// process_exec executes the new child process under supervision of the init
int process_exec(process_t * process)
{
	pid_t pid = fork();
	if (pid < 0) {
		return pid;
	}
	if (pid == 0) {
		// restore the child's signal handlers after fork
		if (sigprocmask(SIG_SETMASK, &process->set, NULL) != 0) {
			bail("set sigprocmask %s", strerror(errno));
		}
		execvp(process->args[0], process->args);
		// execvp will only return on an error so make sure that we check the errno
		// and exit with the correct return status for the error that we encountered
		int status = EXIT_FAILURE;
		switch errno {
		case ENOENT:
			status = 127;
			break;
		case EACCES:
			status = 126;
			break;
		}
		fprintf(stderr, "%s\n", strerror(errno));
		exit(status);
	}
	process->pid = pid;
	return 0;
}

int main(int argc, char **argv)
{
	process_t process;
	reaper_t reaper;

	if (argc == 2 && !strcmp(argv[1], "--version")) {
		printf("grimes version %s\n", VERSION);
		exit(0);
	}

	if (reaper_new(&reaper, &process) != 0) {
		bail("initialize reaper %s", strerror(errno));
	}
	// setup the process
	process.args = &argv[1];
	if (process_exec(&process) != 0) {
		bail("exec process %s", strerror(errno));
	}
	for (;;) {
		struct signalfd_siginfo info;
		if (read(reaper.fd, &info, sizeof(info)) != sizeof(info)) {
			bail("invalid size of siginfo");
		}
		// handle the signal received by either reaping all processes on a SIGCHLD
		// or forwarding the signal to our child processes if it is anything else
		uint32_t sig = info.ssi_signo;
		switch (sig) {
		case SIGCHLD:
			if (reaper_reap(&reaper) != 0) {
				bail("reap processes %s", strerror(errno));
			}
			break;
		default:
			kill(process.pid, sig);
			break;
		}
	}
}
