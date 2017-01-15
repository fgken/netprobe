#include <stdio.h>
#include <stdarg.h>

#include <log.h>

void
log_debug(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	printf("\n");
	va_end(args);
}
