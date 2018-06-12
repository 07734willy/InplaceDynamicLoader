#include <stdio.h>
#include <hurd/trivfs.h>
#include <types.h>

#define FILENAME "tmp6.o"

int main() {
	char* const arg = calloc(1);
	char* const env = calloc(1);
	int fd = open(FILENAME);
	_hurd_exe(__mach_task_self(), fd, arg, env);
}
