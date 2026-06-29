#include "cli.hpp"
#include "common.hpp"
#include "packet_dispatcher.hpp"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

FILE *logsniff = nullptr;
PacketStats stats;

namespace {
void print_summary()
{
	printf("TCP : %d   UDP : %d   ICMPv4 : %d   ICMPv6 : %d   IGMP : %d   IPv6 : %d   Others : %d   Total : %d\n",
		stats.tcp, stats.udp, stats.icmpv4, stats.icmpv6, stats.igmp, stats.ipv6, stats.others, stats.total);
}

void handle_interrupt(int signal_number)
{
	(void)signal_number;
	char answer;
	signal(SIGINT, SIG_IGN);
	printf("OUCH, did you hit Ctrl-C?\nDo you really want to quit? [y/n] ");
	answer = getchar();
	if (answer == 'y' || answer == 'Y') {
		print_summary();
		exit(0);
	}
	signal(SIGINT, handle_interrupt);
	getchar();
}
} // espaço de nomes interno

int main(int argc, char **argv)
{
	if (argc < 2) {
		print_usage(argv[0]);
		return 1;
	}

	Filter filter = Filter::All;
	if (!parse_filter(argc, argv, &filter)) {
		print_usage(argv[0]);
		return 1;
	}

	printf("Writing packets info in sniff_logger.txt\n");
	signal(SIGINT, handle_interrupt);
	unsigned char *buffer = (unsigned char *)malloc(65536);
	if (buffer == nullptr) {
		perror("malloc");
		return 1;
	}

	logsniff = fopen("sniff_logger.txt", "w");
	if (logsniff == nullptr) {
		printf("Unable to create sniff_logger.txt file.\n");
		free(buffer);
		return 1;
	}

	int socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (socket_fd < 0) {
		printf("run this program using 'sudo', required to open raw socket\n");
		perror("socket");
		fclose(logsniff);
		free(buffer);
		return 1;
	}

	struct ifreq interface_request = {};
	strncpy(interface_request.ifr_name, argv[1], IFNAMSIZ - 1);
	if (ioctl(socket_fd, SIOCGIFFLAGS, &interface_request) == -1) {
		perror("ioctl");
		close(socket_fd);
		fclose(logsniff);
		free(buffer);
		return 1;
	}

	interface_request.ifr_flags |= IFF_PROMISC;
	if (ioctl(socket_fd, SIOCSIFFLAGS, &interface_request) == -1) {
		perror("ioctl");
		close(socket_fd);
		fclose(logsniff);
		free(buffer);
		return 1;
	}

	while (true) {
		int received_bytes = recvfrom(socket_fd, buffer, 65536, 0, nullptr, nullptr);
		if (received_bytes < 0) {
			printf("Recvfrom error, failed to get packets\n");
			break;
		}
		process_packet(buffer, received_bytes, filter);
	}

	interface_request.ifr_flags ^= IFF_PROMISC;
	ioctl(socket_fd, SIOCSIFFLAGS, &interface_request);
	close(socket_fd);
	fclose(logsniff);
	free(buffer);
	return 0;
}
