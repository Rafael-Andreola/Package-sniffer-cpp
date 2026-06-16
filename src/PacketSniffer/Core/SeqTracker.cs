using PacketDotNet;

namespace PacketSniffer.Core
{
    public class SeqTracker
    {
        private readonly Dictionary<string, uint?> _tracker = new();

        public string? Check(IPPacket ip, TcpPacket tcp)
        {
            string reverseKey = $"{ip.DestinationAddress}:{tcp.DestinationPort}->{ip.SourceAddress}:{tcp.SourcePort}";
            string directKey = $"{ip.SourceAddress}:{tcp.SourcePort}->{ip.DestinationAddress}:{tcp.DestinationPort}";

            uint receivedSeq = tcp.SequenceNumber;
            uint ack = tcp.AcknowledgmentNumber;

            if (tcp.Synchronize && !tcp.Acknowledgment)
            {
                _tracker[directKey] = null;
                return null;
            }

            string? error = null;

            if (_tracker.TryGetValue(reverseKey, out var expectedSeq) && expectedSeq.HasValue)
            {
                if (receivedSeq + 1024 < expectedSeq.Value)
                    error = $"ERROR TCP: expected>={expectedSeq.Value}, received={receivedSeq}";
            }

            if (ack > 0)
                _tracker[directKey] = ack;

            return error;
        }

        public void Reset() => _tracker.Clear();
    }
}