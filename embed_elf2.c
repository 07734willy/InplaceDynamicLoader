#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <elf.h>
#include <unistd.h>
#include <errno.h>

#define FILENAME "tmp4.o"
#define OFFSET 0x71f
/*475*/

unsigned char *testfun;
int testvalue = 57;

int main ( void ) {
    unsigned int ra;
    unsigned int pagesize;
    unsigned char *ptr;
    unsigned int offset;



	char buf[20000];
	FILE* file;
	size_t fsize;

	file = fopen(FILENAME, "rb");
	if (file) {
		fsize = fread(buf, 1, sizeof(buf), file);
		printf("Size: %ld\n", fsize);
	}
	if (ferror(file)) {
		return 1;
	}		
			


    pagesize=getpagesize();
    testfun=malloc(sizeof(buf)+pagesize+1);
    if(testfun==NULL) return(1);
    //need to align the address on a page boundary
    //printf("%p\n",testfun);
    testfun = (unsigned char *)(((long)testfun + pagesize-1) & ~(pagesize-1));
    //printf("%p\n",testfun);

    if(mprotect(testfun, pagesize, PROT_READ|PROT_EXEC|PROT_WRITE))
    {
        printf("mprotect failed\n");
        return(1);
    }

    //400687: b8 0d 00 00 00          mov    $0xd,%eax
    //40068d: c3                      retq

    /*testfun[ 0]=0xb8;
    testfun[ 1]=0x0d;
    testfun[ 2]=0x00;
    testfun[ 3]=0x00;
    testfun[ 4]=0x00;
    testfun[ 5]=0xc3;
	*/

	memcpy(testfun, buf, sizeof(buf));


	/*
	char buf2[20000];
	ssize_t size = read(pipefd[0], buf2, sizeof(buf2));
	printf("%d\n", buf2[0x1030]);
	*/

	unsigned char* target = testfun + 0x200000;
	unsigned char* result;
	result = mmap(target, sizeof(buf), PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (target != result) {
		printf("Could not acquire the appropriate page\n");
		return 1;
	}
	
	memcpy(target, buf, sizeof(buf));

	printf("%d\n", buf[0x1030]);
	printf("%d\n", target[0x1030]);

	/*for (i = -40; i < 40; i++) {
		int offset3 = 0x1030;
		printf("%d\n", 34 == buf[offset+i]);
	}*/
	//memcpy(testfun+200000, buf, sizeof(buf));
//	int off = 0x4004da-0x400000+1;
//	int nval = (int)(testfun) + 0xb50;

	/*
	//int i;
	for (i = 0; i <= 8600; i++) {
		if (testfun[i] == 34) { 
			printf("%d\n", i);
			//printf("%d\n", testfun[i]);
		}
	}*/
//	printf("%d\n", testfun[0x4da+0xb50+6]);

	
	//*(int*)(testfun-0x400000+0x4004da+2) = (int)(long)&testvalue - 0x4da;
	
	//*(int*)(testfun-0x400000+0x4004da+2) &= 0xFFFF;

	/*testfun[off+0] = (nval >> 0) & 0xFF;
	testfun[off+1] = (nval >> 1) & 0xFF;
	testfun[off+2] = (nval >> 2) & 0xFF;
	testfun[off+3] = (nval >> 3) & 0xFF;
	*/
	
	//testfun += (0x4004d6-0x4003e0);
	//testfun += (0x4004d6-0x400000);
//	testfun += (0x4004e2-0x400000);
	

	testfun += OFFSET;

	printf("Starting execution-\n");

	unsigned int val = ((unsigned int (*)())testfun)();

	printf("Value: %d\n", val);



	fclose(file);
	return 0;
}
