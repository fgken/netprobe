#include <stdint.h>
#include <string.h>
#include <net/ethernet.h>
#include <net/bpf.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <pcap.h>

#include <netprobe.h>
#include <plugin.h>
#include <log.h>
#include <debug.h>
#include <parse_domain.h>

#include <plugins/tcp_retransmit.h>

static void
handle_l7(struct base_tuple *tuple, const uint8_t *buf, size_t length)
{
	log_debug(__func__);
	ASSERT(tuple != NULL && buf != NULL);

#define IS_SRC_OR_DST_PORT(tuple, port)	(tuple->l4.src_port == (port) || tuple->l4.dst_port == (port))
	if (IS_SRC_OR_DST_PORT(tuple, UDP_PORT_DOMAIN)) {
		handle_domain(tuple, buf, length);
	}
}

static size_t
parse_l4_tcp(struct base_tuple *tuple, const uint8_t *buf, size_t length)
{
	log_debug(__func__);
	ASSERT(tuple != NULL && buf != NULL);

	if (sizeof(struct tcphdr) < length) {
		const struct tcphdr *hdr = (const struct tcphdr *)buf;
		size_t hdrlen;

		hdrlen = hdr->th_off << 2;
		tuple->l4.src_port = ntohs(hdr->th_sport);
		tuple->l4.dst_port = ntohs(hdr->th_dport);

		plugin_call(PLUGIN_TCP, tuple, buf, length);
		return hdrlen;
	}

	return 0;
}

static size_t
parse_l4_udp(struct base_tuple *tuple, const uint8_t *buf, size_t length)
{
	log_debug(__func__);
	ASSERT(tuple != NULL && buf != NULL);
	MEMDUMP(buf, length);

	if (sizeof(struct udphdr) < length) {
		const struct udphdr *hdr = (const struct udphdr *)buf;
		size_t hdrlen = 8;

		tuple->l4.src_port = ntohs(hdr->uh_sport);
		tuple->l4.dst_port = ntohs(hdr->uh_dport);

		plugin_call(PLUGIN_UDP, tuple, buf, length);
		return hdrlen;
	}

	return 0;
}

static void
handle_l4(struct base_tuple *tuple, const uint8_t *buf, size_t length)
{
	log_debug(__func__);
	ASSERT(tuple != NULL && buf != NULL);

	size_t offset_l7 = 0;

	if (tuple->l3.protocol == IPPROTO_UDP) {
		offset_l7 = parse_l4_udp(tuple, buf, length);
		handle_l7(tuple, buf + offset_l7, length - offset_l7);
	} else if (tuple->l3.protocol == IPPROTO_TCP) {
		parse_l4_tcp(tuple, buf, length);
	}
}

static size_t
parse_l3_ipv4(struct base_tuple *tuple, const uint8_t *packet, size_t length)
{
	log_debug(__func__);
	ASSERT(tuple != NULL && packet != NULL);

	if (sizeof(struct ip) < length) {
		const struct ip *hdr = (const struct ip *)packet;
		size_t hdrlen = hdr->ip_hl * 4;

		memcpy(tuple->l3.src_ip, &hdr->ip_src, sizeof(struct in_addr));
		memcpy(tuple->l3.dst_ip, &hdr->ip_dst, sizeof(struct in_addr));
		tuple->l3.protocol = hdr->ip_p;
		tuple->l3.payload_length = ntohs(hdr->ip_len) - hdrlen;

#define IS_IPFRAGMENTED(iphdr)	(((iphdr)->ip_off & (IP_RF | IP_DF)) != 0)
		if (IS_IPFRAGMENTED(hdr)) {
			tuple->l3.fragmented = 1;
		}

		return hdrlen;
	}

	return 0;
}

static size_t
parse_l3_tuple(struct base_tuple *tuple, const uint8_t *packet, size_t length)
{
	log_debug(__func__);
	ASSERT(tuple != NULL && packet != NULL);
	MEMDUMP(packet, length);

	switch (tuple->l2.type) {
		case ETHERTYPE_IP:
			return parse_l3_ipv4(tuple, packet, length);
		case ETHERTYPE_IPV6:
			/* TODO */
			return 0;
		default:
			break;
	}

	return 0;
}

static size_t
parse_l2_ethernet(struct base_tuple *tuple, const uint8_t *packet, size_t length)
{
	log_debug(__func__);
	ASSERT(tuple != NULL && packet != NULL);

	if (sizeof(struct ether_header) < length) {
		const struct ether_header *hdr = (const struct ether_header *)packet;
		size_t hdrlen = ETHER_HDR_LEN;

		memcpy(tuple->l2.src_mac, hdr->ether_shost, ETHER_ADDR_LEN);
		memcpy(tuple->l2.dst_mac, hdr->ether_dhost, ETHER_ADDR_LEN);
		tuple->l2.type = ntohs(hdr->ether_type);

		return hdrlen;
	}

	return 0;
}

static size_t
parse_l2_tuple(struct base_tuple *tuple, const uint8_t *packet, size_t length, uint32_t dlt)
{
	log_debug(__func__);
	ASSERT(tuple != NULL && packet != NULL);
	MEMDUMP(packet, length);

	tuple->l2.dlt = dlt;

	switch (tuple->l2.dlt) {
		case DLT_EN10MB:
			return parse_l2_ethernet(tuple, packet, length);
		case DLT_PPP:
			/* TODO */
			return 0;
		default:
			break;
	}

	return 0;
}

static void
handle_packet(const uint8_t *packet, size_t length, int32_t dlt)
{
	log_debug(__func__);

	if (packet != NULL) {
		struct base_tuple tuple;
		size_t offset_l3 = 0;
		size_t offset_l4 = 0;

		MEMDUMP(packet, length);

		memset(&tuple, 0x00, sizeof(tuple));

		offset_l3 = parse_l2_tuple(&tuple, packet, length, dlt);
		if (offset_l3 == 0) {
			return;
		}

		offset_l4 = parse_l3_tuple(&tuple, packet + offset_l3, length - offset_l3);
		if (offset_l4 == 0) {
			return;
		}

		if (tuple.l3.fragmented != 0) {
			/* TODO */
			return;
		}

		handle_l4(&tuple, packet + offset_l3 + offset_l4, length - offset_l4);
	}
}

static void
init_plugins()
{
	plugin_register(PLUGIN_TCP, plugin_tcp_retransmit);
}

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 53 or port 80 or port 443";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	init_plugins();
 
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
			handle_packet(packet, header.len, DLT_EN10MB);
		}
		/* Print its length */
	}

	/* And close the session */
	pcap_close(handle);
	return(0);
}
