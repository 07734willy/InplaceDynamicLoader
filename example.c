/*extern int main2(void);
asm("main2:\n\
mov %rax, %rax\n\
ret");*/
/*#include <stdio.h>

void fun() {
	char* str = "hello test\n";
	return;
}*/
#include <stdio.h>

#define USEGLOBAL

#ifdef USEGLOBAL
int globVar = 34;
#endif

int test() {
	printf("Does this work???\n");
	#ifdef USEGLOBAL
	return globVar;
	#else
	return 4;
	#endif
}

int main() {
	//char buf[200];
	//scanf("%s", buf);
	//asm(buf);
	//main2();
	//fun();
	int x = 2;
	//return 13;
	return test();
}
