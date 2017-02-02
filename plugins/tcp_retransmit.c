#include <stdint.h>
#include <assert.h>
#include <netprobe.h>
#include <log.h>
#include <debug.h>

void
plugin_tcp_retransmit(const struct base_tuple *tuple, const uint8_t *buf, size_t length)
{
	log_debug(__func__);
	ASSERT(tuple != NULL && buf != NULL);
}
