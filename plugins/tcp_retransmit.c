#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netprobe.h>
#include <log.h>
#include <debug.h>
#include <netinet/tcp.h>
#include <murmur3.h>

#define TCP_SESSION_MAX	128

struct tcp_session {
	uint32_t hash;
	struct base_tuple tuple;
	uint32_t next_sequence;
	size_t transmit;
	size_t retransmit;
	uint32_t window;
};

static void
dump_tcp_session(struct tcp_session *session, size_t num)
{
	size_t i;
	char src_ip[INET6_ADDRSTRLEN];
	char dst_ip[INET6_ADDRSTRLEN];
	puts("-------------------------");
	for (i=0; i<num && session[i].hash != 0; i++) {
		inet_ntop(AF_INET, session[i].tuple.l3.src_ip, src_ip, sizeof(src_ip));
		inet_ntop(AF_INET, session[i].tuple.l3.dst_ip, dst_ip, sizeof(dst_ip));
		printf("%s : %u -->> %s : %u - retransmit %zu/%zu, window = %u\n",
			src_ip, session[i].tuple.l4.src_port,
			dst_ip, session[i].tuple.l4.dst_port,
			session[i].retransmit, session[i].transmit,
			session[i].window);
	}
	puts("-------------------------");
}

void
plugin_tcp_retransmit(const struct base_tuple *tuple, const uint8_t *buf, size_t length)
{
	static struct tcp_session session[TCP_SESSION_MAX];

	log_debug(__func__);
	ASSERT(tuple != NULL && buf != NULL);

	if (tuple->l2.type != ETHERTYPE_IP) {
		/* TODO: IPv6 */
		return;
	}

	if (tuple->l4.dst_port == 80 || tuple->l4.dst_port == 443) {
		const struct tcphdr *hdr = (const struct tcphdr *)buf;
		size_t hdrlen = hdr->th_off << 2;
		uint16_t window = ntohs(hdr->th_win);
		uint32_t hash;
		uint32_t seed = 42;
		uint8_t key[4+4+2];	/* src_ip, dst_ip, src_port */

		memcpy(&key[0], tuple->l3.src_ip, sizeof(struct in_addr));
		memcpy(&key[4], tuple->l3.dst_ip, sizeof(struct in_addr));
		memcpy(&key[8], &tuple->l4.src_port, sizeof(tuple->l4.src_port));

		MurmurHash3_x86_32(key, sizeof(key), seed, &hash);

		ASSERT(hash != 0);	/* ??? */

		size_t i;
		for (i=0; i<TCP_SESSION_MAX; i++) {
			if (session[i].hash == hash) {
				uint32_t sequence = ntohl(hdr->th_seq);
				session[i].transmit++;
				if (sequence < session[i].next_sequence) {
					session[i].retransmit++;
				}
				session[i].next_sequence = ntohl(hdr->th_seq) + tuple->l3.payload_length - hdrlen;
				session[i].window = window;
				break;
			} else if (session[i].hash == 0) {
				session[i].hash = hash;
				memcpy(&session[i].tuple, tuple, sizeof(struct base_tuple));
				session[i].next_sequence = ntohl(hdr->th_seq) + tuple->l3.payload_length - hdrlen;
				session[i].transmit++;
				session[i].window = window;
				break;
			}
		}
	}

	dump_tcp_session(session, TCP_SESSION_MAX);
}

