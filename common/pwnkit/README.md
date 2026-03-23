# PWNKIT
## Requirements
1. `pkexec` with SUID
2. `gcc` available for local compilation  

## Known vulnerable versions
0.105  

## Compilation
Transfer `makefile`, `.so` and `.c` files to target machine  

	make all

## Usage
	./exploit

## Troubleshooting
If compilation error `collect2: fatal error: cannot find 'ld'`, the compiler could not find the binary from `PATH` variable  
Could be fixed with  

	export PATH=$PATH:/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin

## Sources
[Original exploit code from INE](https://ine.com/blog/exploiting-pwnkit-cve-2021-4034-techniques-and-defensive-measures)