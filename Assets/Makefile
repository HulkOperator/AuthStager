make:
	nasm -f win64 alignstack.asm -o alignstack.o
	x86_64-w64-mingw32-gcc stager.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o stager.o -Wl,-Tlinker.ld,--no-seh
	x86_64-w64-mingw32-ld -s alignstack.o stager.o -o ../stager.exe
	rm alignstack.o stager.o