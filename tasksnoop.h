// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Alibaba Cloud
#ifndef TASKSNOOP_H
#define TASKSNOOP_H

#define NR_ENTRY_MAX		10000
#define NR_CPU_MAX		50
#define TASK_COMM_LEN		16

enum {
	TYPE_MIGRATE,
	TYPE_ENQUEUE,
	TYPE_WAIT,
	TYPE_EXECUTE,
	TYPE_DEQUEUE,
	TYPE_SYSCALL_ENTER,
	TYPE_SYSCALL_EXIT,
};

enum {
	PREEMPTION,
	SYSCALL,
};

struct trace_info {
	int type;
	int cpu;
	int syscall;
	pid_t tid;
	__u64 ts;
	__u64 duration;
	char comm[TASK_COMM_LEN];
};

struct ti_key {
	int cpu;
	int syscall;
	pid_t tid;
	pid_t tgid;
	char comm[TASK_COMM_LEN];
};

struct stat_info {
	__u64 total;
	__u64 longest;
	int count;
	int padding;
};

struct stat_info_node {
	int cpu;
	pid_t tid;
	int count;
	__u64 avg;
	__u64 longest;
	char comm[4 * TASK_COMM_LEN];
};
#endif /* __TASKSNOOP_H */
