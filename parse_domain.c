#include <stdint.h>
#include <assert.h>

#include <netprobe.h>
#include <log.h>
#include <debug.h>
#include <parse_domain.h>

struct domain_header {
	uint16_t id;
	uint8_t qr;
	uint8_t opcode;
	uint8_t aa;
	uint8_t tc;
	uint8_t rd;
	uint8_t ra;
	uint8_t rcode;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};

void
handle_domain(const struct base_tuple *tuple, const uint8_t *buf, size_t length)
{
	log_debug(__func__);
	ASSERT(tuple != NULL && buf != NULL);

	MEMDUMP(buf, length);

	/* Header */

	/* Question Section */

	/* Answer Section */

	/* Authority Section */

	/* Additional Section */

	/* EDNS0 */

	/* DNSSEC */

}

