#include "cli.hpp"

#include <stdio.h>
#include <string.h>

void print_usage(const char *program_name)
{
	printf("USAGE: sudo %s <required: network_card_name> <optional: packet-filter>\n", program_name);
	printf("USAGE: packet-filters can be: --proto tcp|udp|icmp|ipv6|icmpv6\n");
	printf("Legacy filters still accepted: --udp, --tcp, --icmp\n");
	printf("You can see your network cards by executing the command: ip link show\n");
}

bool parse_filter(int argc, char **argv, Filter *filter)
{
	*filter = Filter::All;
	if (argc == 2) return true;

	if (argc == 3) {
		if (strcmp("--udp", argv[2]) == 0) {
			*filter = Filter::Udp;
			return true;
		}
		if (strcmp("--tcp", argv[2]) == 0) {
			*filter = Filter::Tcp;
			return true;
		}
		if (strcmp("--icmp", argv[2]) == 0) {
			*filter = Filter::Icmp;
			return true;
		}
	}

	if (argc == 4 && strcmp("--proto", argv[2]) == 0) {
		if (strcmp("udp", argv[3]) == 0) *filter = Filter::Udp;
		else if (strcmp("tcp", argv[3]) == 0) *filter = Filter::Tcp;
		else if (strcmp("icmp", argv[3]) == 0) *filter = Filter::Icmp;
		else if (strcmp("ipv6", argv[3]) == 0) *filter = Filter::Ipv6;
		else if (strcmp("icmpv6", argv[3]) == 0) *filter = Filter::Icmpv6;
		else return false;
		return true;
	}

	return false;
}

