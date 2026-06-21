#include "ipv6_parser.hpp"

#include "common.hpp"
#include "ipv4_parser.hpp"
#include "protocol_utils.hpp"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>

namespace {
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
} // espaço de nomes interno

void print_ipv6_header(const unsigned char *buffer, int size)
{
	if (size < (int)(sizeof(struct ethhdr) + sizeof(struct ip6_hdr))) {
		fprintf(logsniff, "\nTruncated IPv6 packet\n");
		return;
	}

	print_ethernet_header(buffer, size);
	const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(buffer + sizeof(struct ethhdr));
	uint32_t flow = ntohl(ip6->ip6_flow);
	char source_ip[INET6_ADDRSTRLEN];
	char destination_ip[INET6_ADDRSTRLEN];

	// Endereços IPv6 possuem 128 bits; por isso, usamos inet_ntop com AF_INET6.
	// A função inet_ntoa, usada para IPv4, não consegue representá-los.
	inet_ntop(AF_INET6, &ip6->ip6_src, source_ip, sizeof(source_ip));
	inet_ntop(AF_INET6, &ip6->ip6_dst, destination_ip, sizeof(destination_ip));

	fprintf(logsniff, "\nIPv6 Header\n");
	fprintf(logsniff, "   |-IP Version        : %u\n", (flow >> 28) & 0x0F);
	fprintf(logsniff, "   |-Traffic Class     : %u\n", (flow >> 20) & 0xFF);
	fprintf(logsniff, "   |-Flow Label        : %u\n", flow & 0xFFFFF);
	fprintf(logsniff, "   |-Payload Length    : %u\n", ntohs(ip6->ip6_plen));
	fprintf(logsniff, "   |-Next Header       : %u (%s)\n", ip6->ip6_nxt, protocol_name(ip6->ip6_nxt));
	fprintf(logsniff, "   |-Hop Limit         : %u\n", ip6->ip6_hlim);
	fprintf(logsniff, "   |-Source IP         : %s\n", source_ip);
	fprintf(logsniff, "   |-Destination IP    : %s\n", destination_ip);
}

bool find_ipv6_transport(const unsigned char *buffer, int size, int *offset, uint8_t *next_header)
{
	if (size < (int)(sizeof(struct ethhdr) + sizeof(struct ip6_hdr))) return false;

	const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(buffer + sizeof(struct ethhdr));
	*next_header = ip6->ip6_nxt;
	*offset = sizeof(struct ethhdr) + sizeof(struct ip6_hdr);

	// Diferentemente do caso mais comum em IPv4, o IPv6 pode inserir cabeçalhos
	// de extensão entre o cabeçalho base e TCP/UDP/ICMPv6. Percorremos a cadeia
	// Next Header até o protocolo de transporte, atualizando o deslocamento.
	while (*next_header == IPPROTO_HOPOPTS || *next_header == IPPROTO_ROUTING || *next_header == IPPROTO_FRAGMENT) {
		if (*next_header == IPPROTO_FRAGMENT) {
			// O cabeçalho Fragment sempre ocupa oito bytes. Seu campo Next Header
			// informa qual protocolo ou cabeçalho de extensão vem em seguida.
			if (size < *offset + 8) return false;
			const struct ip6_frag *fragment = (const struct ip6_frag *)(buffer + *offset);
			fprintf(logsniff, "\nIPv6 Extension Header\n");
			fprintf(logsniff, "   |-Type              : Fragment\n");
			fprintf(logsniff, "   |-Next Header       : %u (%s)\n", fragment->ip6f_nxt, protocol_name(fragment->ip6f_nxt));
			*next_header = fragment->ip6f_nxt;
			*offset += 8;
		} else {
			// Hop-by-Hop e Routing codificam o tamanho em unidades de oito bytes,
			// pela fórmula (Hdr Ext Len + 1) * 8.
			if (size < *offset + 2) return false;
			uint8_t current_header = *next_header;
			uint8_t following_header = buffer[*offset];
			uint8_t header_extension_length = buffer[*offset + 1];
			int header_length = (header_extension_length + 1) * 8;
			if (size < *offset + header_length) return false;

			fprintf(logsniff, "\nIPv6 Extension Header\n");
			fprintf(logsniff, "   |-Type              : %s\n", protocol_name(current_header));
			fprintf(logsniff, "   |-Header Length     : %d Bytes\n", header_length);
			fprintf(logsniff, "   |-Next Header       : %u (%s)\n", following_header, protocol_name(following_header));

			*next_header = following_header;
			*offset += header_length;
		}
	}

	return true;
}

void parse_icmpv6_packet(const unsigned char *buffer, int size, int transport_offset)
{
	fprintf(logsniff, "\n***********************ICMPv6 PACKET***********************\n");
	if (size < transport_offset + 4) {
		fprintf(logsniff, "\nTruncated ICMPv6 packet\n");
		return;
	}

	const uint8_t *icmpv6 = buffer + transport_offset;
	uint16_t checksum;
	memcpy(&checksum, icmpv6 + 2, sizeof(checksum));
	print_ipv6_header(buffer, size);
	fprintf(logsniff, "\nICMPv6 Header\n");
	fprintf(logsniff, "   |-Type : %u (%s)\n", icmpv6[0], icmpv6_type_description(icmpv6[0]));
	fprintf(logsniff, "   |-Code : %u\n", icmpv6[1]);
	fprintf(logsniff, "   |-Checksum : %u\n", ntohs(checksum));
}

void parse_tcp_ipv6_packet(const unsigned char *buffer, int size, int transport_offset)
{
	if (size < transport_offset + (int)sizeof(struct tcphdr)) {
		fprintf(logsniff, "\nTruncated TCP/IPv6 packet\n");
		return;
	}

	const struct tcphdr *tcp = (const struct tcphdr *)(buffer + transport_offset);
	if (size < transport_offset + tcp->doff * 4) {
		fprintf(logsniff, "\nTruncated TCP/IPv6 header\n");
		return;
	}

	fprintf(logsniff, "\n\n***********************TCP over IPv6 Packet*****************\n");
	print_ipv6_header(buffer, size);
	print_tcp_header(tcp);
	fprintf(logsniff, "\n");
}

void parse_udp_ipv6_packet(const unsigned char *buffer, int size, int transport_offset)
{
	if (size < transport_offset + (int)sizeof(struct udphdr)) {
		fprintf(logsniff, "\nTruncated UDP/IPv6 packet\n");
		return;
	}

	const struct udphdr *udp = (const struct udphdr *)(buffer + transport_offset);
	fprintf(logsniff, "\n\n***********************UDP over IPv6 Packet*****************\n");
	print_ipv6_header(buffer, size);
	print_udp_header(udp);
}
