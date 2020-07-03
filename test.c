#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <linux/fs.h>
#include <sys/stat.h>

struct file_handle {
	__u32 handle_bytes;
	int handle_type;
	unsigned char f_handle[0];
};

int main(){
	FILE *f;
	DIR *dir;
	char path[80];
	snprintf(path, sizeof(path),"/sys/fs/cgroup/cpu/test/tes_c");
	
	int dirfd = AT_FDCWD;
	int flags = 0;
	struct file_handle *fhp,*fhp2;
	int mount_id,err;
	fhp = calloc(1, sizeof(*fhp));
	struct stat buf;
	err = lstat(path, &buf);

	int id = bpf_get_current_cgid(3);
	printf("id %d\n" id);

	printf("err %d id %d\n", err, buf.st_ino);

	err = name_to_handle_at(dirfd, path, fhp, &mount_id, flags);
	if (err < 0 || fhp->handle_type != 8) {
		printf("err %d, handle_type %d\n", err, fhp->handle_type);
		goto free_mem;
	} 


	int fd = open(path, O_RDONLY);
	printf("fd %d\n",fd);	
	fd = open(path,O_RDONLY);
	printf("fd %d\n",fd);	

free_mem:
	free(fhp);

	return 0;
}
