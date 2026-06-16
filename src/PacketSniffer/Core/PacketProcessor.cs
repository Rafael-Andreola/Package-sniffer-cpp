using SharpPcap;
using PacketDotNet;
using PacketSniffer.Builders.Abstractions;
using PacketSniffer.Models;

namespace PacketSniffer.Core
{
    public class PacketProcessor
    {
        public event Action<PacketRecord>? PacketParsed;

        private readonly IPacketBuilder<TcpPacket> _tcpBuilder;
        private readonly IPacketBuilder<UdpPacket> _udpBuilder;
        private readonly IPacketBuilder<IcmpV4Packet> _icmpBuilder;

        private SessionSummary SessionSummary { get; } = new();

        public PacketProcessor(
            IPacketBuilder<TcpPacket> tcpBuilder,
            IPacketBuilder<UdpPacket> udpBuilder,
            IPacketBuilder<IcmpV4Packet> icmpBuilder)
        {
            _tcpBuilder = tcpBuilder;
            _udpBuilder = udpBuilder;
            _icmpBuilder = icmpBuilder;
        }

        public void Reset() => SessionSummary.Reset();

        public void OnPacketArrival(object sender, PacketCapture e)
        {
            var raw = e.GetPacket();
            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);

            var ip = packet.Extract<IPPacket>();

            if (ip == null)
            {
                SessionSummary.IncrementOthers();
                return; 
            }

            var tcpPacket = packet.Extract<TcpPacket>();
            var udpPacket = packet.Extract<UdpPacket>();
            var icmpPacket = packet.Extract<IcmpV4Packet>();

            PacketRecord? record = null;

            if (tcpPacket != null)
            {
                SessionSummary.IncrementTcp();
                record = _tcpBuilder.Build(ip, tcpPacket);
            }
            else if (udpPacket != null)
            {
                SessionSummary.IncrementUdp();
                record = _udpBuilder.Build(ip, udpPacket);
            }
            else if (icmpPacket != null)
            {
                SessionSummary.IncrementIcmp();
                record = _icmpBuilder.Build(ip, icmpPacket);
            }
            else
            {
                SessionSummary.IncrementOthers();
            }

            if (record != null)
                PacketParsed?.Invoke(record);
        }
    }
}