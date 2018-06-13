#ifndef ELF_LOADER_H
#define ELF_LOADER_H

#define FILENAME "example"
#define FILESELF "elf_loader"
#define FORCE_BASE 1
#define FORCE_NONE 0

uint8_t is_PIC = 0;

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

int sectCmp(const void* a, const void* b);

Elf64_Shdr* getSect(Elf64_Data elf, const char* name);
Elf64_Sym* getSym(Elf64_Data elf, const char* name);

Elf64_Data elfMakeMap(Elf64_Data elf);
Elf64_Data mapMem(Elf64_Data elf, Elf64_Byte* elfbase, Elf64_Byte force_base);

void patchStatic(Elf64_Data elf);
void patchDynLibs(Elf64_Data elf);

int32_t execElf(Elf64_Data elf, const char* entry);
Elf64_Data readFile(const char* name);
Elf64_Xword getVirtSize(Elf64_Data elf);

void unmapElf(Elf64_Data elf);
void closeLibs(Elf64_Data elf);
void freeElf(Elf64_Data elf);
void cleanExit();
int32_t hoisted_host();
int32_t host();

#endif
