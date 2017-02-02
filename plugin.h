#ifndef __PLUGIN_H__
#define __PLUGIN_H__

#include <netprobe.h>


typedef enum {
	PLUGIN_L2 = 1,
	PLUGIN_L3,
	PLUGIN_L4,
	PLUGIN_L7,
	PLUGIN_UDP,
	PLUGIN_TCP,
	PLUGIN_DOMAIN,
	/* --- */
	PLUGIN_MAX,
} plugin_proto;

typedef void (*plugin_func)(const struct base_tuple *tuple, const uint8_t *buf, size_t length);

void
plugin_register(plugin_proto proto, plugin_func plugin);

void
plugin_call(plugin_proto proto, const struct base_tuple *tuple, const uint8_t *buf, size_t length);

#endif /* __PLUGIN_H__ */
