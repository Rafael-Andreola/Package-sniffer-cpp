#include "packet_dispatcher.hpp"

#include "ipv4_parser.hpp"
#include "ipv6_parser.hpp"
#include "protocol_utils.hpp"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>

namespace {
bool should_print_ipv4(Filter filter, int protocol)
{
	return filter == Filter::All ||
		(filter == Filter::Tcp && protocol == IPPROTO_TCP) ||
		(filter == Filter::Udp && protocol == IPPROTO_UDP) ||
		(filter == Filter::Icmp && protocol == IPPROTO_ICMP);
}

bool should_print_ipv6(Filter filter, int next_header)
{
	return filter == Filter::All || filter == Filter::Ipv6 ||
		(filter == Filter::Tcp && next_header == IPPROTO_TCP) ||
		(filter == Filter::Udp && next_header == IPPROTO_UDP) ||
		(filter == Filter::Icmp && next_header == IPPROTO_ICMPV6) ||
		(filter == Filter::Icmpv6 && next_header == IPPROTO_ICMPV6);
}
} // espaço de nomes interno

void process_packet(const unsigned char *buffer, int size, Filter filter)
{
	++stats.total;
	if (size < (int)sizeof(struct ethhdr)) {
		++stats.others;
		return;
	}

	const struct ethhdr *ethernet = (const struct ethhdr *)buffer;
	unsigned short ether_type = ntohs(ethernet->h_proto);

	if (ether_type == ETH_P_IPV6) {
		++stats.ipv6;
		int transport_offset = 0;
		uint8_t next_header = 0;
		if (!find_ipv6_transport(buffer, size, &transport_offset, &next_header)) {
			++stats.others;
			if (filter == Filter::All || filter == Filter::Ipv6) fprintf(logsniff, "\nTruncated or unsupported IPv6 packet\n");
			return;
		}

		if (next_header == IPPROTO_TCP) {
			++stats.tcp;
			if (should_print_ipv6(filter, next_header)) parse_tcp_ipv6_packet(buffer, size, transport_offset);
		} else if (next_header == IPPROTO_UDP) {
			++stats.udp;
			if (should_print_ipv6(filter, next_header)) parse_udp_ipv6_packet(buffer, size, transport_offset);
		} else if (next_header == IPPROTO_ICMPV6) {
			++stats.icmpv6;
			if (should_print_ipv6(filter, next_header)) parse_icmpv6_packet(buffer, size, transport_offset);
		} else {
			++stats.others;
			if (filter == Filter::All || filter == Filter::Ipv6) {
				fprintf(logsniff, "\nIPv6 packet with unsupported next header: %u (%s)\n", next_header, protocol_name(next_header));
			}
		}
		return;
	}

	if (ether_type != ETH_P_IP || size < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr))) {
		++stats.others;
		return;
	}

	const struct iphdr *ip = (const struct iphdr *)(buffer + sizeof(struct ethhdr));
	int protocol = ip->protocol;
	if (protocol == IPPROTO_ICMP) {
		++stats.icmpv4;
		if (should_print_ipv4(filter, protocol)) parse_icmpv4_packet(buffer, size);
	} else if (protocol == IPPROTO_IGMP) {
		++stats.igmp;
	} else if (protocol == IPPROTO_TCP) {
		++stats.tcp;
		if (should_print_ipv4(filter, protocol)) parse_tcp_ipv4_packet(buffer, size);
	} else if (protocol == IPPROTO_UDP) {
		++stats.udp;
		if (should_print_ipv4(filter, protocol)) parse_udp_ipv4_packet(buffer, size);
	} else {
		++stats.others;
	}
}
