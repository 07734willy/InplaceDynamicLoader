# Inplace Dynamic Loader

A C program that loads and executes an ELF object in memory along with its shared libraries without requiring the ELF object to ever be written to disk.

To compile the elf_loader, use the command: 

gcc elf_loader.c -o elf_loader -ldl -fPIC

Traditionally, linux will use execve() to open a program file from disk to then pass to the loader. This program serves to bypass that requirement, and allow an ELF object to be injected directly into a running host-process's memory, without writing the object to disk.

The example code does read an ELF object from disk to memory first for the sake of convenience, however fopen() does no linking/loading itself, and so the same effect could be accomplished by reading from a pipe, procedurally generating the binary object in memory, or any other means.

It is important to specify whether the ELF binary you plan to execute has been compiled as PIC (position independant code) or not- as this will tell the loader whether it needs to hoist the host "out of the way" in memory, or if it needs to be relocated in memory anways (to avoid the 0-4kb critical region).

Also be aware that the process being executed (and sometimes the host as well) will be executed in memory pages with all three permissions set-  read, write, and execute. This can be seen as a vulnerability, and is unsafe, but then again this program serves to inject a binary into an existing process directly in memory. If you're worried about pageframe permissions, I think you might be overlooking the bigger issue here...

You can specify the target ELF binary to execute in the elf_loader.h header file. Currently there is no support for passing command line arguments, however exit codes will propagate through the host program.
