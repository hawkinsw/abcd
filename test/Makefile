all: hello.out goodbye.out

hello.o: hello.asm
	nasm -felf64 -o hello.o hello.asm

hello.out: hello.o
	ld -dynamic-linker /lib64/ld-linux-x86-64.so.2 -o hello.out hello.o -lc

hello.obj: hello.out
	objdump -d hello.out > hello.obj

goodbye.o: goodbye.asm
	nasm -felf64 -o goodbye.o goodbye.asm

goodbye.out: goodbye.o
	ld -dynamic-linker /lib64/ld-linux-x86-64.so.2 -o goodbye.out goodbye.o -lc

goodbye.obj: goodbye.out
	objdump -d goodbye.out > goodbye.obj

clean:
	rm -rf goodbye.o goodbye.out goodbye.obj
	rm -rf hello.o hello.out hello.obj
