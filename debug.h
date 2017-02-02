#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <assert.h>

#ifdef DEBUG
#define ASSERT(expr)	assert((expr))
#define MEMDUMP(p, l)	memdump((p), (l))

void
memdump(const void *p, size_t l);

#else
#define ASSERT(expr)
#define MEMDUMP(p, l)
#endif

#endif /* __DEBUG_H__ */
