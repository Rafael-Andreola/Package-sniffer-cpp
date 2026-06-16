using PacketDotNet;
using PacketSniffer.Resources;
using PacketSniffer.Builders.Abstractions;
using PacketSniffer.Enums;
using PacketSniffer.Models;

namespace PacketSniffer.Builders
{
    public class UdpBuilder : IPacketBuilder<UdpPacket>
    {
        public PacketRecord Build(IPPacket ip, UdpPacket udp)
        {
            string summary = $":{udp.SourcePort} → :{udp.DestinationPort}";

            var sections = new Dictionary<string, List<string>>
            {
                [SnifferLabels.SectionIpHeader] =
                [
                    $"{SnifferLabels.IpSource}: {ip.SourceAddress}",
                    $"{SnifferLabels.IpDestination}: {ip.DestinationAddress}",
                    $"{SnifferLabels.Ttl}: {ip.TimeToLive}",
                    $"{SnifferLabels.Protocol}: {Protocols.UDP}"
                ],
                [SnifferLabels.SectionUdpHeader] =
                [
                    $"{SnifferLabels.SourcePort}: {udp.SourcePort}",
                    $"{SnifferLabels.DestinationPort}: {udp.DestinationPort}",
                    $"{SnifferLabels.Length}: {udp.Length}",
                    $"{SnifferLabels.Checksum}: 0x{udp.Checksum:X4}"
                ]
            };

            return PacketRecord.Create(
                Protocols.UDP,
                ip.SourceAddress.ToString(),
                ip.DestinationAddress.ToString(),
                summary,
                sections);
        }
    }
}