#include <stdio.h>
#include <debug.h>


void
memdump(const void *p, size_t l)
{
	size_t i;
	const unsigned char *buf = p;
	for (i=0; i<l; i++) {
		printf("%02x ", buf[i]);
		if ((i+1)%16 == 0) {
			puts("");
		} else if ((i+1)%8 == 0) {
			printf(" ");
		}
	}
	puts("");
}
