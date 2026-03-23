Makefile:

all:
	gcc -shared -o evil.so -fPIC evil-so.c -Wno-error=implicit-function-declaration
	gcc exploit.c -o exploit -Wno-error=implicit-function-declaration

clean:
	rm -r ./GCONV_PATH=. && rm -r ./evildir && rm exploit && rm evil.so
