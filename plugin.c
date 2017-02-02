#include <plugin.h>

plugin_func plugins[PLUGIN_MAX];

void
plugin_register(plugin_proto proto, plugin_func plugin)
{
	plugins[proto] = plugin;
}

void
plugin_call(plugin_proto proto, const struct base_tuple *tuple, const uint8_t *buf, size_t length)
{
	if (plugins[proto] != NULL) {
		plugins[proto](tuple, buf, length);
	}
}
