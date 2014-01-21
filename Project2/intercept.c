#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>
#include <asm/fcntl.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <asm/current.h>
#include <asm/cputime.h>
#include <linux/time.h>
#include <asm/uaccess.h>

int getyoungestchild(struct task_struct *process);

int getyoungersibling(struct task_struct *process);

long long timespectons(struct task_struct *);

int getoldersibling(struct task_struct *process);

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
}; //struct processinfo


static unsigned long **find_sys_call_table(void);
unsigned long **sys_call_table;

asmlinkage long (*ref_sys_cs3013_syscall1)(void);
asmlinkage long (*ref_sys_open)(const char __user *path, int flags, mode_t modes);
asmlinkage long (*ref_sys_close)(int fd);
asmlinkage long (*ref_sys_cs3013_syscall2)(struct processinfo *info);

asmlinkage long new_sys_cs3013_syscall1(void) {
	printk(KERN_INFO "\"’Hello world?!’ More like ’Goodbye, world!’ EXTERMINATE!\" -- Dalek");
	return 0;
}

asmlinkage long new_sys_close(int fd) {
	int uid = current_uid();
	printk(KERN_INFO "User %d is closing file descriptor: %d\n", uid, fd);
	return ref_sys_close(fd);
}

asmlinkage long new_sys_open(const char* path, int oflag, mode_t mode) {
	int uid = current_uid();
	printk(KERN_INFO "User %d is opening file: %s\n", uid, path);
	return ref_sys_open(path,oflag,mode);
}

asmlinkage long new_sys_cs3013_syscall2(struct processinfo *info) {
	long long starttime;
	struct processinfo infocopy;
	infocopy.state = current->state;	
	infocopy.pid = current->pid;
	infocopy.parent_pid = current->real_parent->pid;
	infocopy.youngest_child = getyoungestchild(current);
	infocopy.younger_sibling = getyoungersibling(current);
	infocopy.older_sibling = getoldersibling(current);
	infocopy.uid = current_uid();
	starttime = timespec_to_ns(&current->real_start_time);
//(current->real_start_time.tv_nsec) + (current->real_start_time.tv_sec * 1000000000);
	infocopy.start_time = starttime;
	infocopy.user_time = cputime_to_usecs(current->utime);
	infocopy.sys_time = cputime_to_usecs(current->stime);
	infocopy.cutime = cputime_to_usecs(current->signal->cutime);
	infocopy.cstime = cputime_to_usecs(current->signal->cstime);
	copy_to_user(info, &infocopy, sizeof(struct processinfo));
	//printk(KERN_INFO "Pid: %d, Parent pid: %d, State: %ld, Uid: %d, Start Time: %lld nanoseconds, User time: %ld microseconds, System time: %ld microseconds, Children user time: %ld microseconds, Children system time: %ld microseconds\n", info->pid, info->parent_pid, info->state, info->uid, info->start_time, info->user_time, info->sys_time, info->cutime, info->cstime);

//Youngest child pid: %d, Younger sibling pid: %d, Children user time: %lld microseconds, Children system time: %lld microseconds
	return 0;
}

int getyoungersibling(struct task_struct *process) {
	struct task_struct* sibling;
	long long ysiblingtime = -1;
	int ysiblingpid = -1;
	long long timediff = -1;
	long long processstart = timespec_to_ns(&process->real_start_time);
	long long temp;
	list_for_each_entry(sibling, &(process->sibling), sibling) {
		if (ysiblingtime == -1) {
			temp = timespec_to_ns(&sibling->real_start_time);
			timediff = (temp - processstart);
			if (timediff > 0) {
				ysiblingtime = temp;
				ysiblingpid = sibling->pid;
			}
		}
		temp = (timespec_to_ns(&sibling->real_start_time) - processstart);
		if (timediff > temp && temp > 0 ) {
			ysiblingtime = timespec_to_ns(&sibling->real_start_time);
			timediff = (ysiblingtime - processstart);
			ysiblingpid = sibling->pid;
		}
	}
	return ysiblingpid;
}

int getoldersibling(struct task_struct *process) {
	struct task_struct* sibling;
	long long osiblingtime = -1;
	int osiblingpid = -1;
	long long timediff = -1;
	long long temp;
	long long processstart = timespec_to_ns(&process->real_start_time);
	list_for_each_entry(sibling, &(process->sibling), sibling) {
		if (osiblingtime == -1) {
			temp = timespec_to_ns(&sibling->real_start_time);
			timediff = (processstart - temp);
			if (timediff > 0) {
				osiblingtime = temp;
				osiblingpid = sibling->pid;
			}
		}
		else {
			temp = (processstart - timespec_to_ns(&sibling->real_start_time));
			if (timediff > temp && temp > 0) {
				osiblingtime = timespec_to_ns(&sibling->real_start_time);
				timediff = (processstart - osiblingtime);
				osiblingpid = sibling->pid;
			}
		}
	}
	if (osiblingpid == 0)
		return -1;
	return osiblingpid;
}

int getyoungestchild(struct task_struct *process) {
	struct task_struct* child;
//list_for_each_entry(f, &fox_list, list) struct fox *f
	long long youngestprocesstime = -1; 
	int youngestpid = -1;
	list_for_each_entry(child, &(process->children), sibling) {
		if (youngestprocesstime == -1) {	
			youngestprocesstime = timespec_to_ns(&child->real_start_time);
			youngestpid = child->pid;
			continue;
		}
		if (youngestprocesstime < timespec_to_ns(&child->real_start_time)) {
			youngestprocesstime = timespec_to_ns(&child->real_start_time);
			youngestpid = child->pid;
		}
	}
	return youngestpid;
}

long long timespectons(struct task_struct *process) {
	long long timeinns = (process->real_start_time.tv_nsec) + (process->real_start_time.tv_sec * 1000000000);
	return timeinns;
}

static unsigned long **find_sys_call_table(void) {
	unsigned long int offset = PAGE_OFFSET;
	unsigned long **sct;

	while (offset < ULLONG_MAX) {
		sct = (unsigned long **)offset;
		if (sct[__NR_close] == (unsigned long *) sys_close) {
			printk(KERN_INFO "Interceptor: Found syscall table at address: 0x%02lX", (unsigned long) sct);
			return sct;
		}
		offset += sizeof(void *);
	}
	return NULL;
}
static void disable_page_protection(void) {
/*
Control Register 0 (cr0) governs how the CPU operates.
Bit #16, if set, prevents the CPU from writing to memory marked as
read only. Well, our system call table meets that description.
But, we can simply turn off this bit in cr0 to allow us to make
changes. We read in the current value of the register (32 or 64
bits wide), and AND that with a value where all bits are 0 except
the 16th bit (using a negation operation), causing the write_cr0
value to have the 16th bit cleared (with all other bits staying
the same. We will thus be able to write to the protected memory.
It’s good to be the kernel!
*/
	write_cr0 (read_cr0 () & (~ 0x10000));
}
static void enable_page_protection(void) {
/*
See the above description for cr0. Here, we use an OR to set the
16th bit to re-enable write protection on the CPU.
*/
	write_cr0 (read_cr0 () | 0x10000);
}
static int __init interceptor_start(void) {
/* Find the system call table */
	if(!(sys_call_table = find_sys_call_table())) {
/* Well, that didn’t work.
Cancel the module loading step. */
		return -1;
	}
/* Store a copy of all the existing functions */
	ref_sys_cs3013_syscall1 = (void *)sys_call_table[__NR_cs3013_syscall1];
	ref_sys_close = (void *)sys_call_table[__NR_close];
	ref_sys_open = (void *)sys_call_table[__NR_open];
	ref_sys_cs3013_syscall2 = (void *)sys_call_table[__NR_cs3013_syscall2];
/* Replace the existing system calls */
	disable_page_protection();
	sys_call_table[__NR_cs3013_syscall1] = (unsigned long *)new_sys_cs3013_syscall1;
	sys_call_table[__NR_close] = (unsigned long *)new_sys_close;
	sys_call_table[__NR_open] = (unsigned long *)new_sys_open;
	sys_call_table[__NR_cs3013_syscall2] = (unsigned long *)new_sys_cs3013_syscall2;
	enable_page_protection();
/* And indicate the load was successful */
	printk(KERN_INFO "Loaded interceptor!");
	return 0;
}
static void __exit interceptor_end(void) {
/* If we don’t know what the syscall table is, don’t bother. */
	if(!sys_call_table)
		return;
/* Revert all system calls to what they were before we began. */
	disable_page_protection();
	sys_call_table[__NR_cs3013_syscall1] = (unsigned long *)ref_sys_cs3013_syscall1;
	sys_call_table[__NR_open] = (unsigned long *)ref_sys_open;
	sys_call_table[__NR_close] = (unsigned long *)ref_sys_close;
	sys_call_table[__NR_cs3013_syscall2] = (unsigned long*)ref_sys_cs3013_syscall2;
	enable_page_protection();
	printk(KERN_INFO "Unloaded interceptor!");
}
MODULE_LICENSE("GPL");
module_init(interceptor_start);
module_exit(interceptor_end);

