#ifndef __NETPROBE_H__
#define __NETPROBE_H__

#include <stdint.h>
#include <string.h>
#include <net/ethernet.h>
#include <net/bpf.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define PORT_DNS	53

struct meta_tuple {
	struct timespec timestamp;
	uint32_t ifindex;
	uint8_t direction;
};

struct l2_tuple {
	int32_t dlt;	/* data link type */
	uint8_t src_mac[ETHER_ADDR_LEN];
	uint8_t dst_mac[ETHER_ADDR_LEN];
	uint16_t type;
};

#define _INET6_ADDRLEN	16
struct l3_tuple {
	uint8_t fragmented;
	uint8_t src_ip[_INET6_ADDRLEN];
	uint8_t dst_ip[_INET6_ADDRLEN];
	uint8_t protocol;
};

struct l4_tuple {
	uint16_t src_port;
	uint16_t dst_port;
};

struct base_tuple {
	struct meta_tuple meta;
	struct l2_tuple l2;
	struct l3_tuple l3;
	struct l4_tuple l4;
};

#define UDP_PORT_DOMAIN		53
#define TCP_PORT_DOMAIN		53

#endif /* __NETPROBE_H__ */
