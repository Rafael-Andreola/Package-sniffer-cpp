using PacketDotNet;
using PacketSniffer.Resources;
using PacketSniffer.Builders.Abstractions;
using PacketSniffer.Enums;
using PacketSniffer.Models;

namespace PacketSniffer.Builders
{
    public class IcmpBuilder : IPacketBuilder<IcmpV4Packet>
    {
        public PacketRecord Build(IPPacket ip, IcmpV4Packet icmp)
        {
            var sections = new Dictionary<string, List<string>>
            {
                [SnifferLabels.SectionIpHeader] =
                [
                    $"{SnifferLabels.IpSource}: {ip.SourceAddress}",
                    $"{SnifferLabels.IpDestination}: {ip.DestinationAddress}",
                    $"{SnifferLabels.Ttl}: {ip.TimeToLive}",
                    $"{SnifferLabels.Protocol}: {Protocols.ICMP}"
                ],
                [SnifferLabels.SectionIcmpHeader] =
                [
                    $"{SnifferLabels.TypeCode}: {icmp.TypeCode}",
                    $"{SnifferLabels.Checksum}: 0x{icmp.Checksum:X4}"
                ]
            };

            return PacketRecord.Create(
                Protocols.ICMP,
                ip.SourceAddress.ToString(),
                ip.DestinationAddress.ToString(),
                $"{SnifferLabels.TypeCode}: {icmp.TypeCode}",
                sections);
        }
    }
}