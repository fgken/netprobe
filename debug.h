#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <assert.h>

#define ASSERT(expr)	assert((expr))
#define MEMDUMP(p, l)	memdump((p), (l))

void
memdump(const void *p, size_t l);

#endif /* __DEBUG_H__ */
