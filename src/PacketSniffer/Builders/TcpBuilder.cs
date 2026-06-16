using PacketDotNet;
using PacketSniffer.Resources;
using PacketSniffer.Builders.Abstractions;
using PacketSniffer.Core;
using PacketSniffer.Enums;
using PacketSniffer.Models;

namespace PacketSniffer.Builders
{
    public class TcpBuilder : IPacketBuilder<TcpPacket>
    {
        private readonly SeqTracker _seqTracker;

        public TcpBuilder(SeqTracker seqTracker)
        {
            _seqTracker = seqTracker;
        }

        public PacketRecord Build(IPPacket ip, TcpPacket tcp)
        {
            string? seqError = _seqTracker.Check(ip, tcp);

            string summary = string.Format(
                SnifferLabels.PortSummary,
                tcp.SourcePort,
                tcp.DestinationPort);

            var sections = new Dictionary<string, List<string>>
            {
                [SnifferLabels.SectionIpHeader] =
                [
                    $"{SnifferLabels.IpSource}: {ip.SourceAddress}",
                    $"{SnifferLabels.IpDestination}: {ip.DestinationAddress}",
                    $"{SnifferLabels.Ttl}: {ip.TimeToLive}",
                    $"{SnifferLabels.Protocol}: {Protocols.TCP}"
                ],
                [SnifferLabels.SectionTcpHeader] =
                [
                    $"{SnifferLabels.SourcePort}: {tcp.SourcePort}",
                    $"{SnifferLabels.DestinationPort}: {tcp.DestinationPort}",
                    $"{SnifferLabels.SequenceNumber}: {tcp.SequenceNumber}",
                    $"{SnifferLabels.AckNumber}: {tcp.AcknowledgmentNumber}",
                    $"{SnifferLabels.WindowSize}: {tcp.WindowSize}"
                ],
                [SnifferLabels.SectionFlags] =
                [
                    $"{SnifferLabels.FlagSyn}: {tcp.Synchronize}",
                    $"{SnifferLabels.FlagAck}: {tcp.Acknowledgment}",
                    $"{SnifferLabels.FlagFin}: {tcp.Finished}",
                    $"{SnifferLabels.FlagRst}: {tcp.Reset}"
                ]
            };

            if (seqError != null)
                sections[SnifferLabels.SectionSequenceError] = [seqError];

            return PacketRecord.Create(
                Protocols.TCP,
                ip.SourceAddress.ToString(),
                ip.DestinationAddress.ToString(),
                summary,
                sections);
        }
    }
}