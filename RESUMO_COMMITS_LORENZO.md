# Suporte a IPv6 — resumo dos commits do Lorenzo

Este documento resume os três commits mais recentes atribuídos a Lorenzo Menegotto em 16/06/2026, com foco principal na implementação de suporte a IPv6 no sniffer C++ legado. Ele foi preparado como apoio para apresentação e estudo das alterações.

> Observação sobre autoria: os commits `3d8cffd` e `ce9d130` foram implementados diretamente por `lorenzomene`. O commit `ccde797` é um *merge* realizado por Lorenzo, mas integra código produzido principalmente por Marcos Kloss e Bruno Borges Luza.

## Alteração principal: `ce9d130` — Implementação do parsing de IPv6

### Problema anterior

Antes deste commit, o programa assumia que os dados após o cabeçalho Ethernet eram sempre um cabeçalho IPv4 (`struct iphdr`). Isso impedia a análise correta de quadros IPv6: os campos eram lidos na posição e no formato errados, e TCP, UDP ou ICMPv6 não podiam ser identificados de forma confiável.

Além disso, IPv6 possui uma característica que exige tratamento específico: entre seu cabeçalho principal e o protocolo de transporte podem existir cabeçalhos de extensão. Portanto, não é suficiente pular um tamanho fixo de cabeçalho, como acontece no caso mais simples de IPv4.

### Solução implementada

O código passou a verificar o EtherType do quadro Ethernet antes de decidir como interpretá-lo:

```text
Quadro Ethernet
├── EtherType IPv4
│   └── cabeçalho IPv4 → TCP / UDP / ICMPv4
└── EtherType IPv6
    └── cabeçalho IPv6 → cabeçalhos de extensão → TCP / UDP / ICMPv6
```

O ponto de decisão está em `packetCounter`: se o EtherType for `ETH_P_IPV6`, o programa encaminha o quadro ao fluxo de análise IPv6; se for `ETH_P_IP`, mantém o fluxo IPv4 já existente.

### Leitura do cabeçalho IPv6

Foi criada a função `ipv6_header`, que interpreta `struct ip6_hdr` e registra no arquivo `sniff_logger.txt`:

- versão do IP;
- classe de tráfego (*Traffic Class*);
- rótulo de fluxo (*Flow Label*);
- tamanho do payload;
- campo *Next Header*;
- limite de saltos (*Hop Limit*);
- endereços IPv6 de origem e destino.

Os endereços são convertidos com `inet_ntop(AF_INET6, ...)`, pois a função usada no IPv4 (`inet_ntoa`) não é adequada para endereços IPv6.

### Cabeçalhos de extensão: a parte mais importante

Em IPv4, o campo `Protocol` normalmente permite descobrir diretamente se a carga é TCP, UDP ou ICMP. Em IPv6, o campo equivalente é `Next Header`, mas ele pode apontar primeiro para outro cabeçalho IPv6, e não para o protocolo de transporte.

A função `ipv6_transport_offset` percorre a cadeia de cabeçalhos e calcula o deslocamento exato até TCP, UDP ou ICMPv6. Ela suporta:

- **Hop-by-Hop Options**: opções que devem ser analisadas por todos os roteadores do caminho;
- **Routing**: informações de roteamento adicionais;
- **Fragment**: informações de fragmentação IPv6.

Durante esse percurso, o programa atualiza o valor de `Next Header` e avança o deslocamento do buffer. Só depois disso ele sabe onde começa o cabeçalho de transporte.

Esse cuidado é o que diferencia “detectar um pacote IPv6” de “fazer parsing IPv6 corretamente”.

### Protocolos transportados implementados

Após encontrar o protocolo final, o sniffer trata:

- **TCP sobre IPv6:** imprime portas, números de sequência e ACK, flags, janela e checksum;
- **UDP sobre IPv6:** imprime portas, tamanho e checksum;
- **ICMPv6:** imprime tipo, código e checksum.

Para ICMPv6, foram adicionadas descrições de mensagens relevantes, incluindo:

- Echo Request e Echo Reply;
- Destination Unreachable;
- Packet Too Big;
- Time Exceeded;
- Router Solicitation e Router Advertisement;
- Neighbor Solicitation e Neighbor Advertisement.

As quatro últimas mensagens são especialmente importantes porque pertencem ao NDP (*Neighbor Discovery Protocol*), mecanismo usado pelo IPv6 para descoberta de roteadores e vizinhos na rede local.

### Filtros e experiência de uso

O commit introduziu uma sintaxe única de filtro:

```bash
./sniffer <interface> --proto tcp
./sniffer <interface> --proto udp
./sniffer <interface> --proto icmp
./sniffer <interface> --proto ipv6
./sniffer <interface> --proto icmpv6
```

Os filtros antigos (`--tcp`, `--udp` e `--icmp`) continuam aceitos. O filtro `ipv6` mostra os protocolos reconhecidos dentro de tráfego IPv6, enquanto `icmpv6` restringe a saída às mensagens ICMPv6.

### Robustez adicionada

Também foram incluídas verificações de tamanho antes de acessar cada cabeçalho. Caso um quadro Ethernet, pacote IPv6, cabeçalho de extensão ou cabeçalho TCP/UDP/ICMPv6 esteja incompleto, o programa registra uma mensagem de pacote truncado em vez de acessar memória além dos dados recebidos.

O commit ainda melhora a limpeza de recursos: ao ocorrer erro ou ao encerrar a captura, fecha o socket e o arquivo de log, além de liberar o buffer alocado.

### Por que essa alteração era necessária

O IPv6 é uma parte real do tráfego de redes modernas, não apenas uma alternativa futura ao IPv4. Sem esse suporte, o sniffer deixaria de explicar comunicações IPv6 comuns e mensagens fundamentais de infraestrutura de rede, como anúncios de roteador e descoberta de vizinhos.

### Limites atuais

O código interpreta os cabeçalhos de extensão Hop-by-Hop, Routing e Fragment. Outros tipos possíveis, como Destination Options, AH e ESP, ainda não são tratados especificamente.

Também há impressão de TCP sobre IPv6, mas a verificação de sequência TCP existente permanece baseada em endereços IPv4; portanto, essa validação não foi estendida para conexões IPv6 neste commit.

### Roteiro de fala para a apresentação

> Antes, o sniffer interpretava apenas IPv4. Com esta alteração, ele primeiro identifica se o quadro Ethernet contém IPv4 ou IPv6. No caso de IPv6, ele lê o cabeçalho principal e percorre possíveis cabeçalhos de extensão para localizar corretamente TCP, UDP ou ICMPv6. Isso permite visualizar tanto tráfego de aplicações quanto mensagens de infraestrutura, como descoberta de vizinhos e anúncios de roteador.

---

## Contexto: `3d8cffd` — Makefile para comandos rápidos

### O que foi feito

Foi criado o arquivo `legacy/Makefile`, que automatiza compilação e execução da versão C++ legada. Para demonstrar a funcionalidade principal deste documento, ele inclui diretamente o alvo abaixo:

```bash
cd legacy
make run-ipv6 IFACE=enp0s3
```

O Makefile também contém `build`, `check`, `run-tcp`, `run-udp`, `run-icmp` e `clean`.

### Relação com IPv6

Ele não implementa o parsing IPv6, mas torna sua compilação e demonstração práticas e reproduzíveis.

---

## Conclusão para a apresentação

O ponto técnico mais relevante é o suporte a IPv6: o sniffer passou a reconhecer o tipo de pacote na camada Ethernet, ler o cabeçalho IPv6, atravessar cabeçalhos de extensão e então interpretar TCP, UDP ou ICMPv6.

Os demais commits dão contexto a essa evolução:

1. o merge incorpora uma versão gráfica moderna em C#;
2. a implementação IPv6 evolui tecnicamente o sniffer C++ preservado como legado;
3. o Makefile facilita compilar e demonstrar esse sniffer.

Em resumo, a alteração IPv6 amplia significativamente a capacidade de análise da versão C++, permitindo observar tráfego moderno e protocolos essenciais de funcionamento da rede IPv6.
