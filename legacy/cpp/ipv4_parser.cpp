#include "ipv4_parser.hpp"

#include "common.hpp"
#include "protocol_utils.hpp"

#include <arpa/inet.h>
#include <assert.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <optional>
#include <string.h>
#include <unordered_map>

using Ip = unsigned long;
using ExpectedSeq = std::optional<uint32_t>;
using IpTable = std::unordered_map<Ip, std::unordered_map<Ip, ExpectedSeq>>;

namespace {
IpTable ip_table;

void print_tcp_header(const struct tcphdr *tcp)
{
	fprintf(logsniff, "\nTCP Header\n");
	fprintf(logsniff, "   |-Source Port      : %u\n", ntohs(tcp->source));
	fprintf(logsniff, "   |-Destination Port : %u\n", ntohs(tcp->dest));
	fprintf(logsniff, "   |-Sequence Number    : %u\n", ntohl(tcp->seq));
	fprintf(logsniff, "   |-Acknowledge Number : %u\n", ntohl(tcp->ack_seq));
	fprintf(logsniff, "   |-Header Length      : %d DWORDS or %d BYTES\n", (unsigned int)tcp->doff, (unsigned int)tcp->doff * 4);
	fprintf(logsniff, "   |-Urgent Flag          : %d\n", (unsigned int)tcp->urg);
	fprintf(logsniff, "   |-Acknowledgement Flag : %d\n", (unsigned int)tcp->ack);
	fprintf(logsniff, "   |-Push Flag            : %d\n", (unsigned int)tcp->psh);
	fprintf(logsniff, "   |-Reset Flag           : %d\n", (unsigned int)tcp->rst);
	fprintf(logsniff, "   |-Synchronise Flag     : %d\n", (unsigned int)tcp->syn);
	fprintf(logsniff, "   |-Finish Flag          : %d\n", (unsigned int)tcp->fin);
	fprintf(logsniff, "   |-Window         : %d\n", ntohs(tcp->window));
	fprintf(logsniff, "   |-Checksum       : %d\n", ntohs(tcp->check));
	fprintf(logsniff, "   |-Urgent Pointer : %d\n", tcp->urg_ptr);
}

void print_udp_header(const struct udphdr *udp)
{
	fprintf(logsniff, "\nUDP Header\n");
	fprintf(logsniff, "   |-Source Port      : %d\n", ntohs(udp->source));
	fprintf(logsniff, "   |-Destination Port : %d\n", ntohs(udp->dest));
	fprintf(logsniff, "   |-UDP Length       : %d\n", ntohs(udp->len));
	fprintf(logsniff, "   |-UDP Checksum     : %d\n", ntohs(udp->check));
}

void check_ack_sequence(const struct tcphdr *tcp, const struct iphdr *ip)
{
	Ip source_ip = ip->saddr;
	Ip destination_ip = ip->daddr;
	bool packet_error = false;
	ExpectedSeq expected_sequence;

	if (ip_table.find(destination_ip) != ip_table.end() && ip_table[destination_ip].find(source_ip) != ip_table[destination_ip].end()) {
		expected_sequence = ip_table[destination_ip][source_ip];
		uint32_t received_sequence = ntohl(tcp->seq);
		if (expected_sequence.has_value() && expected_sequence.value() != received_sequence) {
			packet_error = true;
		} else {
			ip_table[destination_ip][source_ip] = std::nullopt;
		}
	}

	ip_table[source_ip][destination_ip] = ntohl(tcp->ack_seq);

	if (packet_error) {
		printf("Pacote com erro\n");
		assert(expected_sequence.has_value());
		fprintf(logsniff, "\nERROR: expected seq: %u, received seq: %u\n\n", expected_sequence.value(), ntohl(tcp->seq));
	}
}
} // espaço de nomes interno

void print_ethernet_header(const unsigned char *buffer, int size)
{
	if (size < (int)sizeof(struct ethhdr)) {
		fprintf(logsniff, "\nTruncated Ethernet frame\n");
		return;
	}

	const struct ethhdr *ethernet = (const struct ethhdr *)buffer;
	fprintf(logsniff, "\nEthernet Header\n");
	fprintf(logsniff, "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", ethernet->h_dest[0], ethernet->h_dest[1], ethernet->h_dest[2], ethernet->h_dest[3], ethernet->h_dest[4], ethernet->h_dest[5]);
	fprintf(logsniff, "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", ethernet->h_source[0], ethernet->h_source[1], ethernet->h_source[2], ethernet->h_source[3], ethernet->h_source[4], ethernet->h_source[5]);
	fprintf(logsniff, "   |-Protocol            : 0x%04X \n", ntohs(ethernet->h_proto));
}

void print_ipv4_header(const unsigned char *buffer, int size)
{
	if (size < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr))) {
		fprintf(logsniff, "\nTruncated IPv4 packet\n");
		return;
	}

	print_ethernet_header(buffer, size);
	const struct iphdr *ip = (const struct iphdr *)(buffer + sizeof(struct ethhdr));
	unsigned short ip_header_length = ip->ihl * 4;
	if (size < (int)(sizeof(struct ethhdr) + ip_header_length)) {
		fprintf(logsniff, "\nTruncated IPv4 header\n");
		return;
	}

	struct in_addr source = {.s_addr = ip->saddr};
	struct in_addr destination = {.s_addr = ip->daddr};
	fprintf(logsniff, "\nIP Header\n");
	fprintf(logsniff, "   |-IP Version        : %d\n", (unsigned int)ip->version);
	fprintf(logsniff, "   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)ip->ihl, ((unsigned int)ip->ihl) * 4);
	fprintf(logsniff, "   |-Type Of Service   : %d\n", (unsigned int)ip->tos);
	fprintf(logsniff, "   |-IP Total Length   : %d  Bytes(Size of Packet)\n", ntohs(ip->tot_len));
	fprintf(logsniff, "   |-Identification    : %d\n", ntohs(ip->id));
	fprintf(logsniff, "   |-TTL               : %d\n", (unsigned int)ip->ttl);
	fprintf(logsniff, "   |-Protocol          : %d (%s)\n", (unsigned int)ip->protocol, protocol_name(ip->protocol));
	fprintf(logsniff, "   |-Checksum          : %d\n", ntohs(ip->check));
	fprintf(logsniff, "   |-Source IP         : %s\n", inet_ntoa(source));
	fprintf(logsniff, "   |-Destination IP    : %s\n", inet_ntoa(destination));
}

void parse_icmpv4_packet(const unsigned char *buffer, int size)
{
	fprintf(logsniff, "\n***********************ICMPv4 PACKET***********************\n");
	if (size < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr))) return;

	const struct iphdr *ip = (const struct iphdr *)(buffer + sizeof(struct ethhdr));
	unsigned short ip_header_length = ip->ihl * 4;
	if (size < (int)(sizeof(struct ethhdr) + ip_header_length + sizeof(struct icmphdr))) {
		fprintf(logsniff, "\nTruncated ICMPv4 packet\n");
		return;
	}

	const struct icmphdr *icmp = (const struct icmphdr *)(buffer + sizeof(struct ethhdr) + ip_header_length);
	print_ipv4_header(buffer, size);
	fprintf(logsniff, "\nICMPv4 Header\n");
	fprintf(logsniff, "   |-Type : %d (%s)\n", (unsigned int)icmp->type, icmpv4_type_description(icmp->type));
	fprintf(logsniff, "   |-Code : %d\n", (unsigned int)icmp->code);
	fprintf(logsniff, "   |-Checksum : %d\n", ntohs(icmp->checksum));
}

void parse_tcp_ipv4_packet(const unsigned char *buffer, int size)
{
	if (size < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr))) return;
	const struct iphdr *ip = (const struct iphdr *)(buffer + sizeof(struct ethhdr));
	unsigned short ip_header_length = ip->ihl * 4;
	if (size < (int)(sizeof(struct ethhdr) + ip_header_length + sizeof(struct tcphdr))) {
		fprintf(logsniff, "\nTruncated TCP/IPv4 packet\n");
		return;
	}

	const struct tcphdr *tcp = (const struct tcphdr *)(buffer + sizeof(struct ethhdr) + ip_header_length);
	if (size < (int)(sizeof(struct ethhdr) + ip_header_length + tcp->doff * 4)) {
		fprintf(logsniff, "\nTruncated TCP/IPv4 header\n");
		return;
	}

	fprintf(logsniff, "\n\n***********************TCP Packet*************************\n");
	print_ipv4_header(buffer, size);
	check_ack_sequence(tcp, ip);
	print_tcp_header(tcp);
	fprintf(logsniff, "\n");
}

void parse_udp_ipv4_packet(const unsigned char *buffer, int size)
{
	if (size < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr))) return;
	const struct iphdr *ip = (const struct iphdr *)(buffer + sizeof(struct ethhdr));
	unsigned short ip_header_length = ip->ihl * 4;
	if (size < (int)(sizeof(struct ethhdr) + ip_header_length + sizeof(struct udphdr))) {
		fprintf(logsniff, "\nTruncated UDP/IPv4 packet\n");
		return;
	}

	const struct udphdr *udp = (const struct udphdr *)(buffer + sizeof(struct ethhdr) + ip_header_length);
	fprintf(logsniff, "\n\n***********************UDP Packet*************************\n");
	print_ipv4_header(buffer, size);
	print_udp_header(udp);
}
