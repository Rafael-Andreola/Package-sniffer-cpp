using PacketDotNet;
using PacketSniffer.Models;

namespace PacketSniffer.Builders.Abstractions
{
    public interface IPacketBuilder<TPacket> where TPacket : PacketDotNet.Packet
    {
        PacketRecord Build(IPPacket ip, TPacket packet);
    }
}
