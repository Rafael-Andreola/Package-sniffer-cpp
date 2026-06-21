#include "protocol_utils.hpp"

#include <netinet/in.h>

const char *protocol_name(unsigned int protocol)
{
	switch (protocol) {
		case IPPROTO_TCP: return "TCP";
		case IPPROTO_UDP: return "UDP";
		case IPPROTO_ICMP: return "ICMPv4";
		case IPPROTO_ICMPV6: return "ICMPv6";
		case IPPROTO_HOPOPTS: return "IPv6 Hop-by-Hop";
		case IPPROTO_ROUTING: return "IPv6 Routing";
		case IPPROTO_FRAGMENT: return "IPv6 Fragment";
		default: return "Unknown";
	}
}

const char *icmpv4_type_description(unsigned int type)
{
	switch (type) {
		case 0: return "Echo Reply";
		case 3: return "Destination Unreachable";
		case 5: return "Redirect";
		case 8: return "Echo Request";
		case 11: return "Time Exceeded";
		case 12: return "Parameter Problem";
		default: return "Unknown";
	}
}

const char *icmpv6_type_description(unsigned int type)
{
	switch (type) {
		case 1: return "Destination Unreachable";
		case 2: return "Packet Too Big";
		case 3: return "Time Exceeded";
		case 4: return "Parameter Problem";
		case 128: return "Echo Request";
		case 129: return "Echo Reply";
		case 133: return "Router Solicitation (NDP)";
		case 134: return "Router Advertisement (NDP)";
		case 135: return "Neighbor Solicitation (NDP)";
		case 136: return "Neighbor Advertisement (NDP)";
		default: return "Unknown";
	}
}

