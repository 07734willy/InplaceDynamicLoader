# InplaceDynamicLoader
A C program that loads and executes an ELF object in memory along with shared libraries without writing to disk

Traditionally, linux will use execvp() to open a program file from disk to them pass to the loader. This program serves to bypass that- and allow an ELF object to be injected directly into a process's memory, without writing the object to disk.
