#ifndef __MY_PROCESS_H

struct user_ent {
	struct user_ent	*next;
	unsigned int	ino;
	int		pid;
	int		fd;
	char		process[0];
};

#define USER_ENT_HASH_SIZE	256

struct user_ent *user_ent_hash[USER_ENT_HASH_SIZE];

void user_ent_hash_build(); 
int find_users(unsigned ino, char *buf, int buflen);
void user_ent_add(unsigned int ino, const char *process, int pid, int fd);
int user_ent_hashfn(unsigned int ino);
#endif 
