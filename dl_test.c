#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main() {
	int (*f1ptr)();
	void* handle = NULL;

	const char* error_message = NULL;

	handle = dlopen("tmp4.so", RTLD_NOW);
	if (!handle) {
		printf("Couldn't find library\n");
		exit(1);
	}
	
	dlerror();

	f1ptr = (int (*)()) dlsym(handle, "main");

	error_message = dlerror();

	if (error_message) {
		printf("Couldn't resolve symbol\n");
		dlclose(handle);
		exit(1);
	}

	printf("opened\n");

	printf("%d\n", (*f1ptr)());

	dlclose(handle);
}
