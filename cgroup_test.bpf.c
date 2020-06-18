#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "cgroup_test.h"

struct{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct user_info);
} user_info_maps SEC(".maps");

static inline void *get_user_info(void){
	int key = 0;
	return bpf_map_lookup_elem(&user_info_maps, &key);
}

SEC("tp_btf/sched_process_exit")
int handle__sched_process_exit(u64* ctx){
	struct task_struct *p = (void*) ctx[0];
	struct user_info *ui = get_user_info();
	if (ui && ui->pid == p->pid)
		ui->exit = 1;
	return 0;
}

#define _(P)					\
({						\
 	typeof(P) val;				\
	bpf_probe_read(&val, sizeof(val), &P);	\
	val;					\
})

SEC("kprobe/cgroup_pidlist_start")
int BPF_KPROBE(kprobe__cgroup_pidlist_start, struct seq_file *sf){
	int pid = bpf_get_current_pid_tgid();
	struct user_info *ui = get_user_info();
	
	if (ui) ui->opened = pid;

	if (!ui || ui->selfpid != pid)
		return 0;

	struct kernfs_open_file *of;
	struct kernfs_node *kn;
	struct kernfs_node *parent;
	struct cgroup *cgrp;
	int level;
	u64 *ids;
	
	of	= _(sf->private);
	kn	= _(of->kn);
	parent	= _(kn->parent);
	cgrp	= _(parent->priv);
	level	= _(cgrp->level);
	ids	= _(cgrp->ancestor_ids);

	ui->level = level;
	ui->cg_fid = _(parent->id);
	return 0;
}

SEC("tp_btf/sched_wakeup")
int handle__sched_wakeup(u64 *ctx){
	struct task_struct *p = (void*) ctx[0];
	struct user_info *ui = get_user_info();

	if(!ui || ui->pid != p->pid)
		return 0;
		
	//int index = 1;
	unsigned int index = ui->cg_idx;
	struct css_set* css;
	struct cgroup_subsys_state** subsys_ptr;
	struct cgroup_subsys_state* subsys_state;
	struct cgroup* cgrp;
	struct kernfs_node* kn;
	
	css = _(p->cgroups);
	subsys_ptr = _(css->subsys);
	subsys_state = _(subsys_ptr[index]);
	cgrp = _(subsys_state->cgroup);
	kn = _(cgrp->kn);

	//int cgid = bpf_get_current_cg_id();
	ui->cg_id = _(kn->id);
	return 0;
}
	


char _license[] SEC("license") = "GPL";
