#ifndef CGROUP_TEST_H
#define CGROUP_TEST_H

#define NR_ENTRY_MAX		10000
#define NR_CPU_MAX		512
#define NR_REASON_MAX		128

typedef unsigned long long u64;
typedef int pid_t;

struct user_info{
	pid_t selfpid;
	pid_t pid;
	unsigned int cg_idx;
	int cg_id;
	int cg_fid;
	int level;
	char name[20];
	int exit;
	int opened;
};

#endif
