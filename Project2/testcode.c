#include <sys/syscall.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>

struct processinfo {
	long state;
	pid_t pid;
	pid_t parent_pid;
	pid_t youngest_child;
	pid_t younger_sibling;
	pid_t older_sibling;
	uid_t uid;
	long long start_time;
	long user_time;
	long sys_time;
	long cutime;
	long cstime;
}; 

// These values MUST match the unistd_32.h modifications:
#define __NR_cs3013_syscall1 349
#define __NR_cs3013_syscall2 350
#define __NR_cs3013_syscall3 351

long testCall1 ( void) {
	return (long) syscall(__NR_cs3013_syscall1);
}
long testCall2 (struct processinfo *info) {		
	return (long) syscall(__NR_cs3013_syscall2,info);
}
long testCall3 ( void) {
	return (long) syscall(__NR_cs3013_syscall3);
}
int main () {
	int pid = fork();
	if (pid == 0) {
		sleep(20);
		exit(0);	
	}
	struct processinfo* info = NULL;
	info = (struct processinfo*) malloc(sizeof(struct processinfo));
	printf("The return values of the system calls are: \n");
	printf("\tcs3013_syscall1: %ld\n", testCall1());
	printf("\tcs3013_syscall2: %ld\n", testCall2(info));
	printf("\tcs3013_syscall3: %ld\n", testCall3());
	printf("\tPid: %d\n",info->pid);
	printf("\tParent pid: %d\n",info->parent_pid);
	printf("\tState: %ld\n",info->state);
	printf("\tUid: %d\n", info->uid);
	printf("\tStart Time: %lld nanoseconds\n", info->start_time);
	printf("\tUser Time: %ld microseconds\n", info->user_time);
	printf("\tSystem time: %ld microseconds\n", info->sys_time);
	printf("\tChildren user time: %ld microseconds\n",info->cutime);
	printf("\tChildren system time: %ld microseconds\n",info->cstime);
	printf("\tYoungest Child: %d\n", info->youngest_child);
	printf("\tYounger Sibling: %d\n", info->younger_sibling);
	printf("\tOlder Sibling: %d\n", info->older_sibling);
	//printf("Pid: %d, Parent pid: %d, State: %ld, Uid: %d, Start Time: %lld nanoseconds\n", info->pid, info->parent_pid, info->state, info->uid, info->start_time);
	//printf("User time: %ld microseconds, System time: %ld microseconds, Children user time: %ld microseconds, Children system time: %ld microseconds\n",info->user_time, info->sys_time, info->cutime, info->cstime);
	//printf("Youngest Child: %d, Younger Sibling: %d, Older Sibling: %d\n",info->youngest_child,info->younger_sibling,info->older_sibling);
	return 0;
}
