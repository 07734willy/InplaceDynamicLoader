#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <elf.h>

#define FILENAME "tmp4.o"

typedef struct MemBlock {
	struct MemBlock* next;
	Elf64_Addr pageoff;
	uint32_t size;
	uint8_t mapped;
} MemBlock;


int sect_cmp(const void* a, const void* b) {
	return ((Elf64_Shdr*)a)->sh_addr - ((Elf64_Shdr*)b)->sh_addr;
}

/*void rw_mem(uint8_t* pagebase, Elf64_Shdr* sects, uint32_t size, FILE* ElfFile, Elf64_Ehdr elfHdr) {
	
}*/

uint8_t* map_mem(FILE* ElfFile, Elf64_Ehdr elfHdr, Elf64_Shdr* elfSect) {
    uint32_t pagesize = getpagesize();
	uint8_t* pagebase;
	uint8_t* raddr;
	uint32_t mapsize;
	
	printf("Pagesize: %u\n", pagesize);

	pagebase = (uint8_t*) malloc(1);
	free(pagebase);

	Elf64_Addr pageoff = 0;
	pagebase = (uint8_t *)(((uint64_t)pagebase + pagesize-1) & ~(pagesize-1));
	
	//uint8_t repeat = 1;
	//while (repeat) {
	//	repeat = 0;
	uint32_t i;
	//uint32_t start = 0;
	//Elf64_Addr mmAddr = 0;
	Elf64_Xword mmSize = 0;
	MemBlock* mblock = NULL;
	for (i = 0; i < elfHdr.e_shnum; i++) {
		if (!elfSect[i].sh_addr) { continue; }
		if (!elfSect[i].sh_size) { continue; }
		//if (!mmAddr) { mmAddr = elfSect[i].sh_addr; }

		if (pageoff + mmSize + pagesize < elfSect[i].sh_addr) {
			/*raddr = mmap(pagebase + pageoff, mmSize + mmAddr - pageoff, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (raddr != pagebase + pageoff) {
				repeat = 1;
				pagebase = pagebase + pageoff + pagesize;
				break;
			}
			rw_mem(pagebase, elfSect+start, i-start, ElfFile, elfHdr);
			start = i;*/
			MemBlock* mb = (MemBlock*) malloc(sizeof(MemBlock));
			mb->pageoff = pageoff;
			mb->size = mmSize;
			mb->next = mblock;
			mb->mapped = 0;
			if (pageoff + mmSize > 0) { mblock = mb; }
			pageoff = elfSect[i].sh_addr - (elfSect[i].sh_addr % pagesize);
		}
		mmSize = elfSect[i].sh_addr + elfSect[i].sh_size - pageoff;
	}
	//if (repeat) { continue; }
	
	/*raddr = mmap(pagebase + pageoff, mmSize + mmAddr - pageoff, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (raddr != pagebase + pageoff) {
		repeat = 1;
		pagebase = pagebase + pageoff + pagesize;
		continue;
	}*/

	MemBlock* mb = (MemBlock*) malloc(sizeof(MemBlock));
	mb->pageoff = pageoff;
	mb->size = mmSize;
	mb->next = mblock;
	mb->mapped = 0;
	mblock = mb;
	


	MemBlock* curr = mblock;
	while (curr) {
		printf("%lu %u\n", curr->pageoff, curr->size);
		curr = curr->next;
	}
	
	uint8_t repeat = 1;
	while (repeat) {
		curr = mblock;
		printf("===========\n");
		repeat = 0;
		while (curr) {
			printf("Pre-Alloc\n");
			raddr = mmap(pagebase + curr->pageoff, curr->size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			printf("Alloc 1\n");
			if (raddr != pagebase + curr->pageoff) {
				repeat = 1;
				pagebase += curr->pageoff + curr->size;
				pagebase = (uint8_t *)(((uint64_t)pagebase + pagesize-1) & ~(pagesize-1));
				printf("Failed mmap\n");
				break;
			}
			curr->mapped = 1;
			curr = curr->next;
		}
		if (!repeat) { break; }
		
		printf("Restoring\n");
		curr = mblock;
		while (curr && curr->mapped) {
			munmap(pagebase + curr->pageoff, curr->size);
			curr->mapped = 0;
			curr = curr->next;
			printf("Unmapped\n");
		}
	}

	printf("PAST\n");
	
	for (i = 0; i < elfHdr.e_shnum; i++) {
		fseek(ElfFile, elfSect[i].sh_offset, SEEK_SET);
		printf("%lu %lu\n", elfSect[i].sh_addr, elfSect[i].sh_size);
		fread(pagebase + elfSect[i].sh_addr, 1, elfSect[i].sh_size, ElfFile);
	}

	printf("Success\n");

	return pagebase;

	//rw_mem(pagebase, elfSect+start, elfHdr.e_shnum-start, ElfFile, elfHdr);
				
	/*
		pagebase = (uint8_t *)(((uint64_t)pagebase + pagesize-1) & ~(pagesize-1));
		raddr = mmap(pagebase, mapsize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		
		if (pagebase == raddr) {
			uint32_t i;
			for (i = start; i < end; i++) {
				fseek(ElfFile, elfSect[i].sh_offset, SEEK_SET);
				fread(resAddr, 1, elfSect[i].sh_size, ElfFile);
				resAddr += elfSect[i].sh_size;
			}
		}
	}
	return base + addr;
	*/
}



int main(int arc, char** argv) {
	FILE* ElfFile = NULL;
	char* SectNames = NULL;
	char* SymNames = NULL;
	char* DynSymNames = NULL;
	Elf64_Sym* SectSymbols = NULL;
	Elf64_Dyn* SectDynamic = NULL;
	Elf64_Ehdr elfHdr;
	Elf64_Shdr* elfSect;
	Elf64_Shdr sectHdr;

	if ((ElfFile = fopen(FILENAME, "r")) == NULL) {
		printf("Couldn't open file: %s\n", FILENAME);
		exit(1);
	}

	fread(&elfHdr, 1, sizeof(Elf64_Ehdr), ElfFile);

	fseek(ElfFile, elfHdr.e_shoff + elfHdr.e_shstrndx * sizeof(sectHdr), SEEK_SET);
	fread(&sectHdr, 1, sizeof(sectHdr), ElfFile);

	SectNames = malloc(sectHdr.sh_size);
	fseek(ElfFile, sectHdr.sh_offset, SEEK_SET);
	fread(SectNames, 1, sectHdr.sh_size, ElfFile);
	
	elfSect = (Elf64_Shdr*) malloc(sizeof(Elf64_Shdr) * elfHdr.e_shnum);

	uint32_t i;
	for (i = 0; i < elfHdr.e_shnum; i++) {
		fseek(ElfFile, elfHdr.e_shoff + i * sizeof(sectHdr), SEEK_SET);
		fread(elfSect + i, 1, sizeof(sectHdr), ElfFile);
		
		//printf("%2u %ld %ld %ld %s\n", i, sectHdr.sh_offset, sectHdr.sh_addr, sectHdr.sh_size, name);
	}

	qsort(elfSect, elfHdr.e_shnum, sizeof(sectHdr), sect_cmp);
	
	Elf64_Addr startAddr;

	uint8_t st_idx;

	for (i = 0; i < elfHdr.e_shnum; i++) {
		if (strcmp(SectNames + elfSect[i].sh_name, ".text") == 0) {
			startAddr = elfSect[i].sh_addr;
			printf("Found .text\n");
		}

		if (elfSect[i].sh_type == SHT_SYMTAB) {
			printf("Found SYMTAB\n");
			SectSymbols = (Elf64_Sym*) malloc(elfSect[i].sh_size);
			fseek(ElfFile, elfSect[i].sh_offset, SEEK_SET);
			fread(SectSymbols, 1, elfSect[i].sh_size, ElfFile);
			st_idx = i;
		}
		if (strcmp(SectNames + elfSect[i].sh_name, ".strtab") == 0) {
		//if (elfSect[i].sh_type == SHT_STRTAB) {
			printf("FOUND STRTAB\n");
			SymNames = malloc(elfSect[i].sh_size);
			fseek(ElfFile, elfSect[i].sh_offset, SEEK_SET);
			fread(SymNames, 1, elfSect[i].sh_size, ElfFile);
		}
			
		printf("%d %ld %ld %ld  %s\n", i, elfSect[i].sh_offset, elfSect[i].sh_size, elfSect[i].sh_addr, SectNames + elfSect[i].sh_name);
	}
			
	uint32_t j;
	for (j = 0; j < elfSect[st_idx].sh_size / sizeof(Elf64_Sym); j++) {
		if (strcmp(SymNames + SectSymbols[j].st_name, "main") == 0) {
			startAddr = SectSymbols[j].st_value;
			printf(" ++ main location: %lu\n", SectSymbols[j].st_value);
		}
		printf("%s\n", SymNames + SectSymbols[j].st_name);
	}

	
	uint8_t* pagebase = map_mem(ElfFile, elfHdr, elfSect);
	
	/*
	uint8_t repeat = 1;
	while (repeat) {
		repeat = 0;

		uint32_t start = 0;
		Elf64_Addr mmAddr = 0;
		Elf64_Xword mmSize = 0;
		for (i = 0; i < elfHdr.e_shnum; i++) {
			if (elfSect[i].sh_addr == 0) {
				start++;
				continue;
			}
			if (mmAddr == 0) {
				mmAddr = elfSect[i].sh_addr;
			}

			if ((mmAddr + mmSize != elfSect[i].sh_addr)) {
				if (map_mem(mmAddr, mmSize, mmBase, start, i) == NULL) {
					repeat = 1;
					mmBase += mmAddr + mmSize;
					printf("%lu %lu %p\n", mmAddr, mmSize, mmBase);
					break;
				}
				start = i;
			}
		}
		if (!repeat) {
			if (map_mem(mmAddr, mmSize, mmBase, start, elfHdr.e_shnum) == NULL) {
				repeat = 1;
				mmBase += mmAddr + mmSize;
				printf("Second\n");
				continue;
			}
		}
	}
	*/
	
	fclose(ElfFile);

	uint8_t* fptr = pagebase + startAddr;
	uint32_t val = ((uint32_t (*)())fptr)();
	printf("Value: %u\n", val);

	return 0;
}
