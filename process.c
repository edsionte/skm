#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>

#include "process.h"

int user_ent_hashfn(unsigned int ino)
{
	int val = (ino >> 24) ^ (ino >> 16) ^ (ino >> 8) ^ ino;
	
	//keep the low 8 bits
	return val & (USER_ENT_HASH_SIZE - 1);
}

void user_ent_add(unsigned int ino, const char *process, int pid, int fd)
{
	struct user_ent *p, **pp;
	int str_len;

	//create the new user_ent node
	str_len = strlen(process) + 1;
	p = malloc(sizeof(struct user_ent) + str_len);
	if (!p)
		abort();
	p->next = NULL;
	p->ino = ino;
	p->pid = pid;
	p->fd = fd;
	strcpy(p->process, process);

	//resolve the key conflict
	pp = &user_ent_hash[user_ent_hashfn(ino)];
	p->next = *pp;
	*pp = p;
}

//build the process hash table
void user_ent_hash_build()
{
	const char *root = getenv("PROC_ROOT") ? : "/proc/";
	struct dirent *d;
	char name[1024];
	int nameoff;
	DIR *dir;

	strcpy(name, root);
	if (strlen(name) == 0 || name[strlen(name)-1] != '/')
		strcat(name, "/");

	nameoff = strlen(name);

	// name = "/proc/"
	dir = opendir(name);
	if (!dir)
		return;

	while ((d = readdir(dir)) != NULL) {
		struct dirent *d1;
		char process[16];
		int pid, pos;
		DIR *dir1;
		char crap;

		if (sscanf(d->d_name, "%d%c", &pid, &crap) != 1)
			continue;

		// "/proc/[pid]/fd/"
		sprintf(name + nameoff, "%d/fd/", pid);
		pos = strlen(name);
		if ((dir1 = opendir(name)) == NULL)
			continue;

		process[0] = '\0';

		//read every file from @dir1
		while ((d1 = readdir(dir1)) != NULL) {
			const char *pattern = "socket:[";
			unsigned int ino;
			char lnk[64];
			int fd;
			ssize_t link_len;

			if (sscanf(d1->d_name, "%d%c", &fd, &crap) != 1)
				continue;

			// "proc/[pid]/fd/[fd]/"
			sprintf(name+pos, "%d", fd);

			link_len = readlink(name, lnk, sizeof(lnk)-1);
			if (link_len == -1)
				continue;
			lnk[link_len] = '\0';

			//search the socket fd
			if (strncmp(lnk, pattern, strlen(pattern)))
				continue;

			sscanf(lnk, "socket:[%u]", &ino);

			if (process[0] == '\0') {
				char tmp[1024];
				FILE *fp;

				snprintf(tmp, sizeof(tmp), "%s/%d/stat", root, pid);
				if ((fp = fopen(tmp, "r")) != NULL) {
					fscanf(fp, "%*d (%[^)])", process);
					fclose(fp);
				}
			}

			user_ent_add(ino, process, pid, fd);
		}
		closedir(dir1);
	}
	closedir(dir);
}

int find_users(unsigned ino, char *buf, int buflen)
{
	struct user_ent *p;
	int cnt = 0;
	char *ptr;

	if (!ino)
		return 0;

	p = user_ent_hash[user_ent_hashfn(ino)];
	ptr = buf;
	while (p) {
		if (p->ino != ino)
			goto next;

		if (ptr - buf >= buflen - 1)
			break;

		snprintf(ptr, buflen - (ptr - buf),
			 "(\"%s\",%d,%d),",
			 p->process, p->pid, p->fd);
		ptr += strlen(ptr);
		cnt++;

	next:
		p = p->next;
	}

	if (ptr != buf)
		ptr[-1] = '\0';

	return cnt;
}

