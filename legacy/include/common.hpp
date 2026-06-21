#pragma once

#include <stdio.h>

// Filtros aceitos pela interface de linha de comando.
enum class Filter {
	All,
	Udp,
	Tcp,
	Icmp,
	Ipv6,
	Icmpv6,
};

// Contadores mantidos durante toda a sessão de captura e exibidos ao encerrar.
struct PacketStats {
	int tcp = 0;
	int icmpv4 = 0;
	int icmpv6 = 0;
	int igmp = 0;
	int udp = 0;
	int ipv6 = 0;
	int others = 0;
	int total = 0;
};

extern FILE *logsniff;
extern PacketStats stats;
