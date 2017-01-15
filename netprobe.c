#include <stdint.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <pcap.h>

#include <log.h>

#define PORT_DNS	53

struct meta_tuple {
	struct timespec timestamp;
	uint32_t ifindex;
	uint8_t direction;
};

struct l2_tuple {
	uint8_t src_mac[ETHER_ADDR_LEN];
	uint8_t dst_mac[ETHER_ADDR_LEN];
	uint16_t type;
};

#define _INET6_ADDRLEN	16
struct l3_tuple {
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

static void
handle_domain(const struct base_tuple *tuple, const uint8_t *buf, size_t length)
{
	log_debug(__func__);
}

static void
handle_udp(struct base_tuple *tuple, const uint8_t *buf, size_t length)
{
	log_debug(__func__);

	if (buf != NULL && sizeof(struct udphdr) < length) {
		const struct udphdr *hdr = (const struct udphdr *)buf;
		size_t hdrlen = 8;

		tuple->l4.dst_port = ntohs(hdr->uh_dport);

		switch (tuple->l4.dst_port) {
			case UDP_PORT_DOMAIN:
				handle_domain(tuple, buf + hdrlen, length - hdrlen);
				break;
			default:
				break;
		}
	}
}

static void
handle_ipv4_fragment(struct base_tuple *tuple, const uint8_t *packet, size_t length, size_t offset)
{
	log_debug(__func__);
}

static void
handle_ipv4(struct base_tuple *tuple, const uint8_t *packet, size_t length, size_t offset)
{
	log_debug(__func__);

	if (packet != NULL && sizeof(struct ip) < length - offset) {
		const struct ip *hdr = (const struct ip *)(packet + offset);
		size_t hdrlen = hdr->ip_hl * 4;

#define IS_IPFRAGMENTED(iphdr)	(((iphdr)->ip_off & (IP_RF | IP_DF)) != 0)
		if (IS_IPFRAGMENTED(hdr)) {
			handle_ipv4_fragment(tuple, packet, length, offset);
		} else {
			tuple->l3.protocol = hdr->ip_p;

			switch (tuple->l3.protocol) {
				case IPPROTO_UDP:
					handle_udp(tuple, (uint8_t *)hdr + hdrlen, length - hdrlen);
					break;
				default:
					break;
			}
		}
	}
}

static void
handle_ether(struct base_tuple *tuple, const uint8_t *packet, size_t length, size_t offset)
{
	log_debug(__func__);

	if (packet != NULL && sizeof(struct ether_header) < length - offset) {
		const struct ether_header *hdr = (const struct ether_header *)(packet + offset);
		size_t hdrlen = ETHER_HDR_LEN;

		tuple->l2.type = ntohs(hdr->ether_type);

		switch (tuple->l2.type) {
			case ETHERTYPE_IP:
				handle_ipv4(tuple, packet, length, offset + hdrlen);
				break;
			default:
				break;
		}
	}
}

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 53";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
 
	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("capture on %s\n", dev);
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, 5000, 1, 10, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	for(;;) {
		/* Grab a packet */
		packet = pcap_next(handle, &header);
		if (packet != NULL) {
			struct base_tuple tuple;
			memset(&tuple, 0x00, sizeof(tuple));
			handle_ether(&tuple, packet, header.len, 0);
		}
		/* Print its length */
	}

	/* And close the session */
	pcap_close(handle);
	return(0);
}
