#include <argp.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <bpf/bpf.h>
#include "errno_helpers.h"
#include "trace_helpers.h"
#include "syscall_helpers.h"
#include "cgroup_test.h"
#include "cgroup_test.skel.h"

#define ROOT_CG "/sys/fs/cgroup"
#define CG	"cpu"

const char *argp_program_version = "cgroup_test 0.1";
const char *argp_program_bug_address = "<xxxxxx>";
static const char argp_program_doc[] =
"Are you kidding?\n"
"It's a test tool\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process PID"},
	{ "cgroup", 'c', "CG_PATH", 0, "Cgroup path"},
	{ "hierarchy", 'h', "CG_HIERARCHY", 0, "Cgroup hierarchy"},
	{},
};

static struct env{
	int ui_map_fd;
	bool exiting;
	int target;
	char *cg_path;
	char *cg_h;
} env = {
	.exiting = false,
};

static error_t parse_arg(int key, char *arg, struct argp_state *state){
	int pid;
	switch(key){
		case 'p':
			if(arg == NULL){
				fprintf(stderr, "PID is required\n");
				argp_usage(state);
			}else{
				pid = strtol(arg, NULL, 10);
				if(pid <= 0){
					fprintf(stderr, "Invalid PID: %s\n", arg);
					argp_usage(state);
				}
				env.target = pid;
			}
			break;
		case 'c':
			env.cg_path = arg;
			break;
		case 'h':
			env.cg_h = arg;
			break;
		case ARGP_KEY_END:
			if(!env.target){
				fprintf(stderr, "No target PID\n");
				argp_usage(state);
			}
			if (!env.cg_h) 
				env.cg_h = CG;
			if (!env.cg_path)
				env.cg_path = "";
			break;
		default:
			return ARGP_ERR_UNKNOWN;

	}
	return 0;
}

static int get_target_cg_idx(){
	char buf[80];
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	int id = 0;

	fp = fopen("/proc/cgroups", "r");
	while (getline(&line, &len, fp) != -1){
		int f_i = 0;
		int s_i = 0;
		while (f_i < len && line[f_i] != '\t') {
			buf[f_i] = line[f_i];
			f_i++;
		}
		if (f_i == len)
			continue;
		buf[f_i] = '\0';
		//printf("%s\n", buf);
		if (strcmp(buf, env.cg_h) == 0) {
			s_i = f_i+1;
			while (s_i < len && line[s_i]!='\t'){
				id *= 10;
				id += line[s_i] - '0';
				s_i++;
			}
			if (s_i != len)
				return id;
		
		}
	}
	return 0;
}

static int get_cg_id(char *cg_h, char *path){
	char buf[512];
	struct stat stat_buf;
	int err;
	if (path)
		snprintf(buf, sizeof(buf), "%s/%s/%s", ROOT_CG, cg_h, path);
	else
		snprintf(buf, sizeof(buf), "%s/%s", ROOT_CG, cg_h);

	printf("CGroup Path %s\n",buf);
	err = lstat(buf, &stat_buf);
	if (err){
		printf("No such cgroup\n");
		return -1;
	}
	return stat_buf.st_ino;
}

static int setup_user_info(int pid){
	int key = 0;
	DIR *dir;
	char buf[256];
	int cg_idx;
	struct user_info ui = {
		.selfpid = getpid(),
		.pid = pid,
		.cg_fid = get_cg_id(env.cg_h, env.cg_path),
		.cg_id = -1,
	};
	snprintf(buf, sizeof(buf), "/proc/%d", pid);
	dir = opendir(buf);
	if (!dir) {
		printf("Open %s failed: %s\n",buf, strerror(errno));
		return -1;
	}
	
	cg_idx = get_target_cg_idx();
	if(cg_idx < 0)
		return -1;
	ui.cg_idx = cg_idx;
	printf("CGroup index: %d\n", cg_idx);
	bpf_map_update_elem(env.ui_map_fd, &key, &ui, BPF_ANY);
	closedir(dir);
	return 0;
}

static void int_exit(int sig){
	env.exiting = true;
}


int main(int argc, char **argv){
	struct cgroup_test_bpf *obj;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if(err)
		return err;

	err = bump_memlock_rlimit();
	if(err){
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		return err;
	}

	obj = cgroup_test_bpf__open();
	if(!obj){
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return -1;
	}

	err = cgroup_test_bpf__load(obj);
	if(err){
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = cgroup_test_bpf__attach(obj);
	if(err){
		fprintf(stderr, "failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	env.ui_map_fd = bpf_map__fd(obj->maps.user_info_maps);

	if(setup_user_info(env.target)){
		printf("Illegal target %d\n", env.target);
		goto cleanup;
	}

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	int count = 0;
	printf("Start\n");
	while(!env.exiting){
		int key = 0;
		struct user_info ui = {
			.exit = 0,
		};

		bpf_map_lookup_elem(env.ui_map_fd, &key, &ui);
		if(ui.exit){
			printf("Target \"%d\" Destroyed\n", env.target);
			goto cleanup;
		}

		int hid = bpf_get_hierarchy_id("cpu");
		int cgid = bpf_get_cgroup_id(hid,env.cg_path);	
		if (count > 0) printf("\033[3A");
		printf("\rHID %d, File CG id %d, BPF CG id %d,",hid, ui.cg_fid, ui.cg_id);
		printf(" User bpf call cgid %d, path %s\n", cgid, env.cg_path);
		printf("File name %s, count %d\n",ui.name, count);
		printf("Task pid %d, Task tgid %d\n",ui.task_pid, ui.task_tgid);
		count++;
		sleep(1);

	}
cleanup:
	cgroup_test_bpf__destroy(obj);
	return err != 0;

}

