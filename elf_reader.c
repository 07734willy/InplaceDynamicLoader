#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <elf.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>

#define FILENAME "tmp4.o"
#define FORCE_BASE 1
#define FORCE_NONE 0

typedef uint8_t Elf64_Byte;

typedef struct MMap {
	Elf64_Addr	m_offset;
	Elf64_Word	m_size;
	Elf64_Byte 	m_mapped;
	struct MMap* m_next;
} MMap;

typedef struct MemBlock {
	Elf64_Addr	pageoff;
	Elf64_Word	size;
	uint8_t 	mapped;
	struct MemBlock* next;
} MemBlock;

typedef struct {
	Elf64_Byte* d_data;
	Elf64_Byte*	d_base;
	MMap*		d_mmap;
} Elf64_Data;

int sectCmp(const void* a, const void* b) {
	return ((Elf64_Shdr*)a)->sh_addr - ((Elf64_Shdr*)b)->sh_addr;
}

Elf64_Shdr* getSect(Elf64_Data elf, const char* name) {
	Elf64_Ehdr elfHdr = *(Elf64_Ehdr*)elf.d_data;
	Elf64_Shdr* elfSect = (Elf64_Shdr*)(elf.d_data + elfHdr.e_shoff);
	Elf64_Byte* strSect = (Elf64_Byte*)(elf.d_data + elfSect[elfHdr.e_shstrndx].sh_offset);
	uint32_t i;
	for (i = 0; i < elfHdr.e_shnum; i++) {
		if (strcmp(name, strSect + elfSect[i].sh_name) == 0) {
			return elfSect + i;
		}
	}
	return NULL;
}

Elf64_Sym* getSym(Elf64_Data elf, const char* name) {
	Elf64_Shdr* symtab = getSect(elf, ".symtab");
	Elf64_Shdr* strtab = getSect(elf, ".strtab");
	Elf64_Byte* strSym = elf.d_data + strtab->sh_offset;
	Elf64_Sym* elfSym = (Elf64_Sym*)(elf.d_data + symtab->sh_offset);
	uint32_t i;
	for (i = 0; i < symtab->sh_size / sizeof(Elf64_Sym); i++) {
		if (strcmp(name, strSym + elfSym[i].st_name) == 0) {
			return elfSym + i;
		}
	}
	return NULL;
}


Elf64_Data elfMakeMap(Elf64_Data elf) {
	Elf64_Ehdr elfHdr = *(Elf64_Ehdr*)elf.d_data;
	Elf64_Shdr* elfSect = (Elf64_Shdr*)malloc(elfHdr.e_shnum * sizeof(Elf64_Shdr));
	memcpy(elfSect, elf.d_data + elfHdr.e_shoff, elfHdr.e_shnum * sizeof(Elf64_Shdr));
	qsort(elfSect, elfHdr.e_shnum, sizeof(Elf64_Shdr), sectCmp);
	
	Elf64_Word pagesize = getpagesize();

	uint32_t i;
	Elf64_Addr pageoff = 0;
	Elf64_Xword msize = 0;
	MMap* mblock = NULL;
	for (i = 0; i < elfHdr.e_shnum; i++) {
		if (!elfSect[i].sh_addr || !elfSect[i].sh_size) { continue; }

		if ((pageoff + msize + pagesize) < (elfSect[i].sh_addr & ~(pagesize-1))) {
			MMap* map = (MMap*) malloc(sizeof(MMap));
			map->m_offset = pageoff;
			map->m_size = msize;
			map->m_next = mblock;
			map->m_mapped = 0;
			if (pageoff | msize) { mblock = map; }
			pageoff = elfSect[i].sh_addr & ~(pagesize-1);
		}
		msize = elfSect[i].sh_addr + elfSect[i].sh_size - pageoff;
	}

	MMap* map = (MMap*) malloc(sizeof(MMap));
	map->m_offset = pageoff;
	map->m_size = msize;
	map->m_next = mblock;
	map->m_mapped = 0;
	elf.d_mmap = map;
	free(elfSect);
	return elf;
}
	
Elf64_Data mapMem(Elf64_Data elf, Elf64_Byte* elfbase, Elf64_Byte force_base) {
	Elf64_Ehdr elfHdr = *(Elf64_Ehdr*)elf.d_data;
	Elf64_Shdr* elfSect = (Elf64_Shdr*)(elf.d_data + elfHdr.e_shoff);
	Elf64_Byte* maddr;
	uint8_t flag = force_base ? MAP_FIXED : 0;
	Elf64_Word pagesize = getpagesize();
	
	MMap* curr;
	curr = elf.d_mmap;
	while (curr) {
		printf("%lu %u\n", curr->m_offset, curr->m_size);
		curr = curr->m_next;
	}
	Elf64_Byte repeat = 1;
	while (repeat) {
		curr = elf.d_mmap;
		repeat = 0;
		while (curr) {
			maddr = mmap(elfbase + curr->m_offset, curr->m_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | flag, -1, 0);
			if (maddr != elfbase + curr->m_offset) {
				if (maddr == MAP_FAILED && flag == MAP_FIXED) {
					printf("Could not map program to base address: %p, of size: %u\n", elfbase, curr->m_size);
					exit(1);
					/*printf("memprot %d\n", mprotect(elfbase + curr->m_offset, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC));
					curr->m_offset += pagesize;
					curr->m_size -= pagesize;
					if (curr->m_size <= 0) {
						curr = curr->m_next;
					}
					continue;*/
				}
				repeat = 1;
				elfbase += curr->m_offset + curr->m_size;
				if (elfbase < maddr) { elfbase = maddr; }
				elfbase = (Elf64_Byte *)(((Elf64_Xword)elfbase + pagesize-1) & ~(pagesize-1));
				printf("Failed mmap\n");
				break;
			}
			curr->m_mapped = 1;
			curr = curr->m_next;
		}
		if (!repeat) { break; }
		
		curr = elf.d_mmap;
		while (curr && curr->m_mapped) {
			munmap(elfbase + curr->m_offset, curr->m_size);
			curr->m_mapped = 0;
			curr = curr->m_next;
		}
	}
	elf.d_base = elfbase;

	printf("PAST\n");
	
	uint32_t i;
	for (i = 0; i < elfHdr.e_shnum; i++) {
		if (!elfSect[i].sh_addr || !elfSect[i].sh_size) { continue; }
		memcpy(elfbase + elfSect[i].sh_addr, elf.d_data + elfSect[i].sh_offset, elfSect[i].sh_size);
	}
	printf("MMap Success\n");

	return elf;
}

void patchStatic(Elf64_Data elf) {
	Elf64_Ehdr elfHdr = *(Elf64_Ehdr*)elf.d_data;
	Elf64_Shdr* elfSect = (Elf64_Shdr*)(elf.d_data + elfHdr.e_shoff);
	Elf64_Shdr sectHdr;
	uint32_t j;

	printf("===== Dynamic =====\n");
	
	sectHdr = *getSect(elf, ".dynamic");
	Elf64_Dyn* SectDynamic = (Elf64_Dyn*)(elf.d_data + sectHdr.sh_offset);
	Elf64_Byte* DynSymNames = (Elf64_Byte*)(elf.d_data + getSect(elf, ".dynstr")->sh_offset);
	for (j = 0; j < sectHdr.sh_size / sizeof(Elf64_Dyn); j++) {
		if (SectDynamic[j].d_tag == DT_NEEDED) {
			printf("%s\n", DynSymNames + SectDynamic[j].d_un.d_val);
		}
		Elf64_Sxword tag = SectDynamic[j].d_tag;
		if (tag == DT_PLTGOT || tag == DT_HASH || tag == DT_STRTAB || tag == DT_SYMTAB || tag == DT_RELA || tag == DT_INIT || tag == DT_FINI || tag == DT_REL || tag == DT_DEBUG || tag == DT_JMPREL) {
			((Elf64_Dyn*)(elf.d_base + sectHdr.sh_addr))[j].d_un.d_ptr += (Elf64_Addr)elf.d_base;
		}
	}
	
	printf("===== Rela (plt) =====\n");
	
	sectHdr = *getSect(elf, ".rela.plt");
	Elf64_Rela* SectRelaPlt = (Elf64_Rela*)(elf.d_data + sectHdr.sh_offset);
	Elf64_Sym* SectDynSymbols = (Elf64_Sym*)(elf.d_data + getSect(elf, ".dynsym")->sh_offset);
	for (j = 0; j < sectHdr.sh_size / sizeof(Elf64_Rela); j++) {
		((Elf64_Rela*)(elf.d_base + sectHdr.sh_addr))[j].r_offset += (Elf64_Addr)elf.d_base;
		printf("%s\n", DynSymNames + SectDynSymbols[ELF64_R_SYM(SectRelaPlt[j].r_info)].st_name);
	}

	printf("===== Rela (dyn) =====\n");

	sectHdr = *getSect(elf, ".rela.dyn");
	Elf64_Rela* SectRelaDyn = (Elf64_Rela*)(elf.d_data + sectHdr.sh_offset);
	for (j = 0; j < sectHdr.sh_size / sizeof(Elf64_Rela); j++) {
		((Elf64_Rela*)(elf.d_base + sectHdr.sh_addr))[j].r_offset += (Elf64_Addr)elf.d_base;
	printf("%s\n", DynSymNames + SectDynSymbols[ELF64_R_SYM(SectRelaDyn[j].r_info)].st_name);
	}

	printf("===== Fixing GOT =====\n");

	sectHdr = *getSect(elf, ".got.plt");
	for (j = 3; j < sectHdr.sh_size / sizeof(Elf64_Addr); j++) {
		((Elf64_Addr*)(elf.d_base + sectHdr.sh_addr))[j] += (Elf64_Addr)elf.d_base;
		printf("GOT entry: %lu\n", ((Elf64_Addr*)(elf.d_base + sectHdr.sh_addr))[j]);
	}
	
	printf("===== Patching Init/Fini Array =====\n");
	
	
	sectHdr = *getSect(elf, ".init_array");
	for (j = 0; j < sectHdr.sh_size / sizeof(Elf64_Addr); j++) {
		*((Elf64_Addr*)(elf.d_base + sectHdr.sh_addr)) += (Elf64_Addr)elf.d_base;
		printf("patched init_array\n");
	}

	sectHdr = *getSect(elf, ".fini_array");
	for (j = 0; j < sectHdr.sh_size / sizeof(Elf64_Addr); j++) {
		*((Elf64_Addr*)(elf.d_base + sectHdr.sh_addr)) += (Elf64_Addr)elf.d_base;
		printf("patched fini_array\n");
	}
}

void patchDynLibs(Elf64_Data elf) {
	Elf64_Shdr dynamicHdr = *getSect(elf, ".dynamic");
	Elf64_Shdr relaDynHdr = *getSect(elf, ".rela.dyn");
	Elf64_Shdr relaPltHdr = *getSect(elf, ".rela.plt");
	Elf64_Sym* SectDynSymbols = (Elf64_Sym*)(elf.d_data + getSect(elf, ".dynsym")->sh_offset);
	Elf64_Dyn* SectDynamic = (Elf64_Dyn*)(elf.d_data + dynamicHdr.sh_offset);
	Elf64_Rela* SectRelaDyn = (Elf64_Rela*)(elf.d_data + relaDynHdr.sh_offset);
	Elf64_Rela* SectRelaPlt = (Elf64_Rela*)(elf.d_data + relaPltHdr.sh_offset);
	Elf64_Byte* DynSymNames = (Elf64_Byte*)(elf.d_data + getSect(elf, ".dynstr")->sh_offset);
	
	uint32_t i, j;
	for (i = 0; i < dynamicHdr.sh_size / sizeof(Elf64_Dyn); i++) {
		if (SectDynamic[i].d_tag == DT_NEEDED) {
			//printf("%s\n", DynSymNames + SectDynamic[i].d_un.d_val);
			void* handle = dlopen(DynSymNames + SectDynamic[i].d_un.d_val, RTLD_LAZY);
			for (j = 0; j < relaPltHdr.sh_size / sizeof(Elf64_Rela); j++) {
				dlerror();
				void* faddr = dlsym(handle, DynSymNames + SectDynSymbols[ELF64_R_SYM(SectRelaPlt[j].r_info)].st_name);
				if (dlerror() == NULL) {
					*((void**)(elf.d_base + SectRelaPlt[j].r_offset)) = faddr;
					printf("Symbol patched: %s\n", DynSymNames + SectDynSymbols[ELF64_R_SYM(SectRelaPlt[j].r_info)].st_name);
				}
			}
			for (j = 0; j < relaDynHdr.sh_size / sizeof(Elf64_Rela); j++) {
				dlerror();
				void* faddr = dlsym(handle, DynSymNames + SectDynSymbols[ELF64_R_SYM(SectRelaDyn[j].r_info)].st_name);
				if (dlerror() == NULL) {
					*((void**)(elf.d_base + SectRelaDyn[j].r_offset)) = faddr;
					printf("Symbol patched: %s\n", DynSymNames + SectDynSymbols[ELF64_R_SYM(SectRelaDyn[j].r_info)].st_name);
				}
			}
		}
	}
}

uint32_t execElf(Elf64_Data elf, const char* entry) {
	Elf64_Ehdr elfHdr = *(Elf64_Ehdr*)elf.d_data;
	
	Elf64_Byte* fptr = elf.d_base;
	if (entry) {
		fptr += getSym(elf, entry)->st_value;
	} else {
		fptr += elfHdr.e_entry;
	}
	return ((uint32_t (*)())fptr)();
}

#define FILESELF "elf_reader"

void clean_exit() {
	printf("Patching In Original Program\n");
	FILE* ElfFile;
	if ((ElfFile = fopen(FILESELF, "r")) == NULL) {
		printf("Couldn't open file: %s\n", FILESELF);
		exit(1);
	}
	
	fseek(ElfFile, 0L, SEEK_END);
	ssize_t filelen = ftell(ElfFile);
	fseek(ElfFile, 0L, SEEK_SET);

	Elf64_Byte* buffer = (Elf64_Byte*) malloc(filelen);
	fread(buffer, 1, filelen, ElfFile);
	fclose(ElfFile);

	Elf64_Data elf;
	elf.d_data = buffer;
	elf.d_base = 0;
	elf.d_mmap = NULL;

	printf("Calculating Memory Segments\n");
	elf = elfMakeMap(elf);
	printf("Making Memory Maps\n");
	elf = mapMem(elf, NULL, FORCE_BASE);
	printf("Patching Static Values\n");
	patchStatic(elf);
	printf("Patching Dynamic Libraries\n");
	patchDynLibs(elf);
	printf("Returning Down Call-Stack\n");
	return;
}

void hoisted_main() {
	printf("Inside of Hoisted Main\n");

	FILE* ElfFile;
	if ((ElfFile = fopen(FILENAME, "r")) == NULL) {
		printf("Couldn't open file: %s\n", FILENAME);
		exit(1);
	}
	
	fseek(ElfFile, 0L, SEEK_END);
	ssize_t filelen = ftell(ElfFile);
	fseek(ElfFile, 0L, SEEK_SET);

	Elf64_Byte* buffer = (Elf64_Byte*) malloc(filelen);
	fread(buffer, 1, filelen, ElfFile);
	fclose(ElfFile);

	Elf64_Data elf;
	elf.d_data = buffer;
	elf.d_base = 0;
	elf.d_mmap = NULL;
	
	
	Elf64_Word pagesize = getpagesize();
	
	printf("Calculating Memory Segments\n");
	elf = elfMakeMap(elf);
	printf("Making Memory Maps\n");
	elf = mapMem(elf, NULL, FORCE_BASE);
	printf("Patching Static Values\n");
	patchStatic(elf);
	printf("Patching Dynamic Libraries\n");
	patchDynLibs(elf);
	printf("Executing Program\n");
	execElf(elf, "main");
	printf("Terminating Process\n");

	printf("Leaving Hoisted Main\n");
	
	clean_exit();
	return;
}


int main(int arc, char** argv) {
	FILE* ElfFile;
	if ((ElfFile = fopen(FILESELF, "r")) == NULL) {
		printf("Couldn't open file: %s\n", FILESELF);
		exit(1);
	}
	/*if ((ElfFile = fopen(FILENAME, "r")) == NULL) {
		printf("Couldn't open file: %s\n", FILENAME);
		exit(1);
	}*/
	
	fseek(ElfFile, 0L, SEEK_END);
	ssize_t filelen = ftell(ElfFile);
	fseek(ElfFile, 0L, SEEK_SET);

	Elf64_Byte* buffer = (Elf64_Byte*) malloc(filelen);
	fread(buffer, 1, filelen, ElfFile);
	fclose(ElfFile);

	// TODO - make sure to shift hoisted_main far enough (check virt size of -other)

	Elf64_Data elf;
	elf.d_data = buffer;
	elf.d_base = 0;
	elf.d_mmap = NULL;

	//printf("munmap: %d\n", munmap(NULL, 0x220000));

	Elf64_Addr orig_base = ((Elf64_Addr)main) - getSym(elf, "main")->st_value;
	printf("orig: %lu\n", orig_base);
	printf("orig_base: %p %lu\n", main, getSym(elf, "main")->st_value);
	
	printf("Calculating Memory Segments\n");
	elf = elfMakeMap(elf);
	printf("Making Memory Maps\n");
	elf = mapMem(elf, NULL, FORCE_NONE);
	printf("Patching Static Values\n");
	patchStatic(elf);
	printf("Patching Dynamic Libraries\n");
	patchDynLibs(elf);
	printf("===== Executing Program =====\n");
	execElf(elf, "hoisted_main");
	//execElf(elf, "main");
	printf("===== Terminating Process =====\n");
	
	return 0;
}
